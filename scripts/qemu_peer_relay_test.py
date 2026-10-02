"""Exercise stream boundaries and the exact loss selector used by the VM gate."""
import asyncio
import contextlib
import importlib.util
import io
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location("relay", Path(__file__).with_name("qemu-peer-relay.py"))
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


def confirmation():
    frame = bytearray(104)
    frame[:12] = relay.MAC_B + relay.MAC_A
    frame[12:20] = b"\x88\xb5ZGNP\x01\x04"
    frame[20:28] = (1).to_bytes(8, "little")
    frame[28:36] = (2).to_bytes(8, "little")
    frame[36:52] = bytes(range(16))
    frame[60:] = bytes(range(44))
    return bytes(frame)


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def test_fragmented_and_coalesced_frames(self):
        reader = asyncio.StreamReader()
        expected = confirmation()
        wire = struct.pack("!I", len(expected)) + expected

        async def feed():
            for byte in wire:
                reader.feed_data(bytes([byte]))
                await asyncio.sleep(0)
            reader.feed_data(wire + wire)
            reader.feed_eof()

        feeder = asyncio.create_task(feed())
        for _ in range(3):
            self.assertEqual(await relay.read_frame(reader), expected)
        self.assertIsNone(await relay.read_frame(reader))
        await feeder

    async def test_rejects_truncation_and_invalid_lengths(self):
        for wire in (b"\x00", struct.pack("!I", 104) + b"short", struct.pack("!I", 13), struct.pack("!I", relay.MAX_FRAME + 1)):
            reader = asyncio.StreamReader()
            reader.feed_data(wire)
            reader.feed_eof()
            with self.assertRaises(ValueError):
                await relay.read_frame(reader)

    async def test_drops_only_two_identical_final_confirmations(self):
        packet = confirmation()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rule = relay.ConfirmationLoss(2)
            for offset in (0, 6, 12, 14, 18, 19, 20, 28, 52):
                wrong = bytearray(packet)
                wrong[offset] ^= 1
                self.assertFalse(rule.drop(bytes(wrong)))
            self.assertFalse(rule.drop(packet[:-1]))
            self.assertEqual(rule.dropped, 0)
            self.assertTrue(rule.drop(packet))
            self.assertTrue(rule.drop(packet))
            self.assertFalse(rule.drop(packet))
            self.assertFalse(rule.drop(packet))
            self.assertEqual(rule.dropped, 2)
            self.assertTrue(rule.recovered)
            changed = bytearray(packet)
            changed[-1] ^= 1
            with self.assertRaises(ValueError):
                rule.drop(bytes(changed))
        self.assertEqual(output.getvalue().count("SYNC_RELAY:RETRIED_CONFIRMATION"), 1)

    async def test_forward_preserves_framing_and_unrelated_payloads(self):
        class Writer:
            def __init__(self):
                self.bytes = bytearray()
                self.drains = 0

            def write(self, data):
                self.bytes.extend(data)

            async def drain(self):
                self.drains += 1

        packet = confirmation()
        other = b"ordinary frame"
        reader = asyncio.StreamReader()
        for frame in (packet, other, packet, packet):
            reader.feed_data(struct.pack("!I", len(frame)) + frame)
        reader.feed_eof()
        writer = Writer()
        with contextlib.redirect_stdout(io.StringIO()):
            await relay.forward(reader, writer, relay.ConfirmationLoss(2))
        self.assertEqual(writer.bytes, struct.pack("!I", len(other)) + other + struct.pack("!I", len(packet)) + packet)
        self.assertEqual(writer.drains, 2)

    async def test_live_relay_delivers_both_directions_and_closes(self):
        loop = asyncio.get_running_loop()
        upstream = loop.create_future()
        ready = loop.create_future()
        server = await asyncio.start_server(lambda reader, writer: upstream.set_result((reader, writer)), "127.0.0.1", 0)
        running = asyncio.create_task(relay.run(server.sockets[0].getsockname()[1], 2, ready.set_result))
        writer_a = writer_b = None
        try:
            port = await asyncio.wait_for(ready, 2)
            reader_a, writer_a = await asyncio.wait_for(upstream, 2)
            reader_b, writer_b = await asyncio.open_connection("127.0.0.1", port)
            packet = confirmation()
            with contextlib.redirect_stdout(io.StringIO()):
                for _ in range(3):
                    writer_a.write(struct.pack("!I", len(packet)) + packet)
                await writer_a.drain()
                self.assertEqual(await asyncio.wait_for(relay.read_frame(reader_b), 2), packet)
            other = b"reverse traffic"
            writer_b.write(struct.pack("!I", len(other)) + other)
            await writer_b.drain()
            self.assertEqual(await asyncio.wait_for(relay.read_frame(reader_a), 2), other)
            writer_b.close()
            await writer_b.wait_closed()
            await asyncio.wait_for(running, 2)
            self.assertEqual(await asyncio.wait_for(reader_a.read(), 2), b"")
        finally:
            running.cancel()
            await asyncio.gather(running, return_exceptions=True)
            for writer in (writer_a, writer_b):
                if writer is not None:
                    writer.close()
                    await writer.wait_closed()
            server.close()
            await server.wait_closed()


if __name__ == "__main__":
    unittest.main()
