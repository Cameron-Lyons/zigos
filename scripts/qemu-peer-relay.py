#!/usr/bin/env python3
"""Bounded localhost relay that drops final Noise confirmations in QEMU tests.

QEMU net/socket.c sends a four-byte network-order length followed by one
Ethernet frame: https://github.com/qemu/qemu/blob/master/net/socket.c
Only the visible routing header and nonce are inspected. Ciphertext is never
changed, decrypted, or fabricated by this harness.
"""

import argparse
import asyncio
import struct

MAX_FRAME = 65536
MAC_A = bytes.fromhex("025a47000001")
MAC_B = bytes.fromhex("025a47000002")


def final_confirmation(frame):
    return (
        len(frame) == 104
        and frame[:6] == MAC_B
        and frame[6:12] == MAC_A
        and frame[12:20] == b"\x88\xb5ZGNP\x01\x04"
        and frame[20:28] == (1).to_bytes(8, "little")
        and frame[28:36] == (2).to_bytes(8, "little")
        and frame[52:60] == bytes(8)
    )


class ConfirmationLoss:
    def __init__(self, count):
        self.limit = count
        self.dropped = 0
        self.first = None
        self.recovered = False

    def drop(self, frame):
        if not final_confirmation(frame):
            return False
        if self.first is None:
            self.first = frame
        if frame != self.first:
            raise ValueError("confirmation changed before its channel completed")
        if self.dropped < self.limit:
            self.dropped += 1
            print(f"SYNC_RELAY:DROPPED_CONFIRMATION {self.dropped}", flush=True)
            return True
        if self.dropped and not self.recovered:
            self.recovered = True
            print("SYNC_RELAY:RETRIED_CONFIRMATION", flush=True)
        return False


async def read_frame(reader):
    try:
        header = await reader.readexactly(4)
    except asyncio.IncompleteReadError as error:
        if not error.partial:
            return None
        raise ValueError("truncated QEMU frame length") from error
    size = struct.unpack("!I", header)[0]
    if not 14 <= size <= MAX_FRAME:
        raise ValueError(f"invalid QEMU frame length: {size}")
    try:
        return await reader.readexactly(size)
    except asyncio.IncompleteReadError as error:
        raise ValueError("truncated QEMU Ethernet frame") from error


async def forward(reader, writer, loss=None):
    while (frame := await read_frame(reader)) is not None:
        if loss is not None and loss.drop(frame):
            continue
        writer.write(struct.pack("!I", len(frame)))
        writer.write(frame)
        await writer.drain()


async def connect_upstream(port):
    deadline = asyncio.get_running_loop().time() + 10
    while True:
        try:
            return await asyncio.open_connection("127.0.0.1", port, limit=MAX_FRAME)
        except ConnectionRefusedError:
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError("upstream QEMU did not listen")
            await asyncio.sleep(0.05)


async def run(port, losses, ready=None):
    upstream_reader, upstream_writer = await connect_upstream(port)
    connected = asyncio.get_running_loop().create_future()

    def accept(reader, writer):
        if connected.done():
            writer.close()
        else:
            connected.set_result((reader, writer))

    server = await asyncio.start_server(accept, "127.0.0.1", 0, limit=MAX_FRAME)
    tasks = []
    downstream_writer = None
    try:
        listen_port = server.sockets[0].getsockname()[1]
        if ready is None:
            print(f"SYNC_RELAY:READY {listen_port}", flush=True)
        else:
            ready(listen_port)
        downstream_reader, downstream_writer = await asyncio.wait_for(connected, 20)
        server.close()
        tasks = [
            asyncio.create_task(forward(upstream_reader, downstream_writer, ConfirmationLoss(losses))),
            asyncio.create_task(forward(downstream_reader, upstream_writer)),
        ]
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        server.close()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        upstream_writer.close()
        if downstream_writer is not None:
            downstream_writer.close()
        await upstream_writer.wait_closed()
        if downstream_writer is not None:
            await downstream_writer.wait_closed()
        await server.wait_closed()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-port", type=int, required=True)
    parser.add_argument("--drop-confirmations", type=int, choices=(0, 2), default=2)
    args = parser.parse_args()
    if not 1 <= args.upstream_port <= 65535:
        parser.error("upstream port must be between 1 and 65535")
    asyncio.run(run(args.upstream_port, args.drop_confirmations))
