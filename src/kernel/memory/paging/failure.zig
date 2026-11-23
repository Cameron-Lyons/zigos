const std = @import("std");
const x86 = @import("../../../arch/x86.zig");
const early_console = @import("../../utils/console.zig");

// Every fatal paging invariant halts this CPU with one bounded diagnostic.
pub const Reason = enum {
    kernel_text_outside_upper_half_image_window,
    kernel_text_outside_low_physical_aperture,
    kernel_immutable_data_outside_upper_half_image_window,
    kernel_immutable_image_outside_low_physical_aperture,
    invalid_page_aligned_kernel_image_extents,
    kernel_end_outside_physical_image_aperture,
    invalid_physical_kernel_image_end,
    page_table_frame_outside_direct_map_aperture,
    data_frame_outside_direct_map_aperture,
    page_table_pointer_outside_direct_map_aperture,
    missing_kernel_page_table_root,
    corrupt_process_context_identifier_accounting,
    allocated_frame_direct_alias_missing,
    out_of_physical_memory_while_mapping_page,
    attempted_to_map_an_unaligned_page,
    user_mapping_collided_with_inherited_kernel_memory,
    attempted_to_replace_an_owned_user_page,
    attempted_to_create_a_writable_executable_user_page,
    page_mapping_address_overflow,
    corrupt_pml4_allocation_accounting,
    corrupt_rejected_huge_page_allocation_accounting,
    corrupt_retired_user_range_accounting,
    corrupt_retired_user_hierarchy_accounting,
    invalid_framebuffer_ownership_extent,
    invalid_ram_direct_map_authority,
    final_paging_arena_outside_direct_map_aperture,
    sparse_kernel_hierarchy_admission_failed,
    corrupt_high_memory_probe_accounting,
    high_memory_probe_outside_direct_map_aperture,
    high_memory_direct_map_leaf_missing,
    high_memory_direct_map_permissions_are_invalid,
    high_memory_direct_map_probe_failed,
    missing_boot_info_handoff,
    missing_admitted_cache_policy,
    invalid_native_boot_memory_ownership,
    insufficient_early_heap_for_physical_frame_state,
    invalid_native_memory_map_allocator_admission,
    invalid_live_boot_handoff_extent,
    invalid_kernel_or_efi_heap_reservation,
    physical_memory_reservation_table_overflow,
    no_usable_physical_frames_remain_after_kernel_reservation,
    current_cpu_has_no_verified_paging_root,
    kernel_paging_root_not_initialized,
    current_cpu_failed_kernel_cr3_admission,
    address_space_root_exceeds_machine_address_width,
    invalid_address_space_cr3_value,
    address_space_switch_rejected_root,
    pcid_switch_requires_current_cpu_admission,
};

// Share cold diagnostics as bytes and bounded offsets, without one pointer
// relocation and standalone literal for every fatal path.
const diagnostics = blk: {
    const messages = [_][]const u8{
        "Kernel text lies outside the upper-half image window!\n",
        "Kernel text lies outside the low physical aperture!\n",
        "Kernel immutable data lies outside the upper-half image window!\n",
        "Kernel immutable image lies outside the low physical aperture!\n",
        "Invalid page-aligned kernel image extents!\n",
        "Kernel end lies outside the physical image aperture!\n",
        "Invalid physical kernel image end!\n",
        "Page-table frame lies outside the direct-map aperture!\n",
        "Data frame lies outside the direct-map aperture!\n",
        "Page-table pointer lies outside the direct-map aperture!\n",
        "Missing kernel page-table root!\n",
        "Corrupt process-context identifier accounting!\n",
        "Allocated frame has no WB direct alias!\n",
        "Out of physical memory while mapping page!\n",
        "Attempted to map an unaligned page!\n",
        "User mapping collided with inherited kernel memory!\n",
        "Attempted to replace an owned user page!\n",
        "Attempted to create a writable executable user page!\n",
        "Page mapping address overflow!\n",
        "Corrupt PML4 allocation accounting!\n",
        "Corrupt rejected huge-page allocation accounting!\n",
        "Corrupt retired user-range accounting!\n",
        "Corrupt retired user-hierarchy accounting!\n",
        "Invalid framebuffer ownership extent!\n",
        "Invalid RAM direct-map authority!\n",
        "Final paging arena lies outside the direct-map aperture!\n",
        "Sparse kernel hierarchy admission failed!\n",
        "Corrupt high-memory probe accounting!\n",
        "High-memory probe lies outside the direct-map aperture!\n",
        "High-memory direct-map leaf is missing!\n",
        "High-memory direct-map permissions are invalid!\n",
        "High-memory direct-map probe failed!\n",
        "Missing validated EFI boot handoff!\n",
        "Missing admitted cache policy!\n",
        "Invalid native boot memory ownership!\n",
        "Insufficient early heap for physical-frame state!\n",
        "Invalid native memory map allocator admission!\n",
        "Invalid live EFI handoff extent!\n",
        "Invalid kernel or EFI heap reservation!\n",
        "Physical-memory reservation table overflow!\n",
        "No usable physical frames remain after kernel reservation!\n",
        "Current CPU has no verified paging root!\n",
        "Kernel paging root is not initialized!\n",
        "Current CPU failed kernel CR3 admission!\n",
        "Address-space root exceeds the machine address width!\n",
        "Invalid address-space CR3 value!\n",
        "Address-space switch rejected its root!\n",
        "PCID switch requires current CPU admission!\n",
    };
    if (messages.len != @typeInfo(Reason).@"enum".field_names.len)
        @compileError("paging failure messages must cover every reason");
    var byte_count: usize = 0;
    for (messages) |message| byte_count += message.len;
    if (byte_count > std.math.maxInt(u16)) @compileError("paging diagnostics exceed their bounded offsets");
    var bytes: []const u8 = "";
    var offsets: [messages.len + 1]u16 = undefined;
    var cursor: usize = 0;
    for (messages, 0..) |message, index| {
        offsets[index] = @intCast(cursor);
        bytes = bytes ++ message;
        cursor += message.len;
    }
    offsets[messages.len] = @intCast(cursor);
    break :blk .{ .bytes = bytes, .offsets = offsets };
};

pub noinline fn halt(reason: Reason) noreturn {
    @branchHint(.cold);
    early_console.print(reasonMessage(reason));
    while (true) x86.hlt();
}

fn reasonMessage(reason: Reason) []const u8 {
    const index: usize = @backingInt(reason);
    return diagnostics.bytes[diagnostics.offsets[index]..diagnostics.offsets[index + 1]];
}

test "paging diagnostic runtime selectors retain addressable bytes for every fatal reason" {
    var selected: u8 = 0;
    const selector: *volatile u8 = &selected;
    const blob = diagnostics.bytes;
    for (0..@typeInfo(Reason).@"enum".field_names.len) |index| {
        selector.* = @intCast(index);
        const reason: Reason = @fromBackingInt(@intCast(selector.*));
        const message = reasonMessage(reason);
        try std.testing.expect(message.len != 0);
        try std.testing.expect(@intFromPtr(message.ptr) >= @intFromPtr(blob.ptr));
        try std.testing.expect(@intFromPtr(message.ptr) + message.len <= @intFromPtr(blob.ptr) + blob.len);
        try std.testing.expectEqual(@as(u8, '\n'), message[message.len - 1]);
    }
    selector.* = @backingInt(Reason.invalid_native_boot_memory_ownership);
    try std.testing.expectEqualStrings("Invalid native boot memory ownership!\n", reasonMessage(@fromBackingInt(@intCast(selector.*))));
}
