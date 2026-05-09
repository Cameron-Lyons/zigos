const builtin = @import("builtin");
const measured_boot = @import("measured_boot.zig");

const console = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/utils/console.zig")
else
    struct {
        pub fn print(_: []const u8) void {}
        pub fn printChar(_: u8) void {}
    };

pub fn printMeasurementSummary(boot: *const measured_boot.BootRecord) void {
    console.print("ZIGOS:PLATFORM:MEASURED_BOOT:ROOT ");
    printHexDigest(&boot.root_digest);
    console.print("\n");
    console.print("ZIGOS:PLATFORM:MEASURED_BOOT:ROOT_PROVENANCE ");
    console.print(@tagName(boot.root_provenance));
    console.print("\n");
    if (boot.artifact_manifest_verified) {
        console.print("ZIGOS:PLATFORM:MEASURED_BOOT:ROOT_MANIFEST VERIFIED\n");
    }
    for (boot.records[0..boot.record_count]) |record| {
        console.print("ZIGOS:PLATFORM:MEASURED_BOOT:RECORD ");
        console.print(@tagName(record.kind));
        console.print(" ");
        console.print(record.labelSlice());
        console.print(" ");
        printHexDigest(&record.digest);
        console.print("\n");
    }
}

fn printHexDigest(digest: *const [32]u8) void {
    const hex = "0123456789abcdef";
    for (digest.*) |byte| {
        console.printChar(hex[byte >> 4]);
        console.printChar(hex[byte & 0x0f]);
    }
}
