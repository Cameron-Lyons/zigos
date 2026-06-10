const std = @import("std");

pub const MAX_CHILDREN: usize = 8;
pub const MAX_LABEL_BYTES: usize = 64;
pub const MAX_RENDER_BYTES: usize = 4096;

pub const Role = enum(u8) {
    window,
    stack,
    toolbar,
    text,
    button,
    icon_button,
    text_field,
    toggle,
    list,
    list_item,
    permission_row,
};

pub const Intent = enum(u8) {
    neutral,
    primary,
    destructive,
    permission_allow,
    permission_deny,
};

pub const Node = struct {
    id: u32,
    role: Role,
    intent: Intent = .neutral,
    label: []const u8 = "",
    value: []const u8 = "",
    checked: bool = false,
    enabled: bool = true,
    child_count: usize = 0,
    children: [MAX_CHILDREN]*const Node = undefined,

    pub fn withChildren(self: Node, children: []const *const Node) Node {
        var copy = self;
        copy.child_count = @min(children.len, copy.children.len);
        for (children[0..copy.child_count], 0..) |child, index| {
            copy.children[index] = child;
        }
        return copy;
    }
};

pub fn window(id: u32, title: []const u8, children: []const *const Node) Node {
    return (Node{ .id = id, .role = .window, .label = title }).withChildren(children);
}

pub fn stack(id: u32, children: []const *const Node) Node {
    return (Node{ .id = id, .role = .stack }).withChildren(children);
}

pub fn toolbar(id: u32, children: []const *const Node) Node {
    return (Node{ .id = id, .role = .toolbar }).withChildren(children);
}

pub fn text(id: u32, label: []const u8) Node {
    return .{ .id = id, .role = .text, .label = label };
}

pub fn button(id: u32, label: []const u8, intent: Intent) Node {
    return .{ .id = id, .role = .button, .label = label, .intent = intent };
}

pub fn iconButton(id: u32, label: []const u8, value: []const u8, intent: Intent) Node {
    return .{ .id = id, .role = .icon_button, .label = label, .value = value, .intent = intent };
}

pub fn textField(id: u32, label: []const u8, value: []const u8) Node {
    return .{ .id = id, .role = .text_field, .label = label, .value = value };
}

pub fn toggle(id: u32, label: []const u8, checked: bool) Node {
    return .{ .id = id, .role = .toggle, .label = label, .checked = checked };
}

pub fn permissionRow(id: u32, label: []const u8, allowed: bool) Node {
    return .{
        .id = id,
        .role = .permission_row,
        .label = label,
        .checked = allowed,
        .intent = if (allowed) .permission_allow else .permission_deny,
    };
}

pub fn render(root: *const Node, out: []u8) error{UiRenderBufferTooSmall}![]const u8 {
    var cursor: usize = 0;
    try renderNode(root, 0, out, &cursor);
    return out[0..cursor];
}

fn renderNode(node: *const Node, depth: usize, out: []u8, cursor: *usize) error{UiRenderBufferTooSmall}!void {
    var indent: usize = 0;
    while (indent < depth) : (indent += 1) {
        try append(out, cursor, "  ");
    }
    try appendFmt(
        out,
        cursor,
        "id={d} role={s} intent={s} enabled={s} checked={s} label=\"{s}\" value=\"{s}\"\n",
        .{ node.id, @tagName(node.role), @tagName(node.intent), yesNo(node.enabled), yesNo(node.checked), node.label, node.value },
    );
    for (node.children[0..node.child_count]) |child| {
        try renderNode(child, depth + 1, out, cursor);
    }
}

fn append(out: []u8, cursor: *usize, text_bytes: []const u8) error{UiRenderBufferTooSmall}!void {
    if (cursor.* + text_bytes.len > out.len) return error.UiRenderBufferTooSmall;
    @memcpy(out[cursor.* .. cursor.* + text_bytes.len], text_bytes);
    cursor.* += text_bytes.len;
}

fn appendFmt(out: []u8, cursor: *usize, comptime fmt: []const u8, args: anytype) error{UiRenderBufferTooSmall}!void {
    const written = std.fmt.bufPrint(out[cursor.*..], fmt, args) catch return error.UiRenderBufferTooSmall;
    cursor.* += written.len;
}

fn yesNo(value: bool) []const u8 {
    return if (value) "yes" else "no";
}

test "UI primitives render a stable native tree for simulator snapshots" {
    const title = text(1, "Zigos Writer");
    const save = iconButton(2, "Save", "save", .primary);
    const autosave = toggle(3, "Autosave", true);
    const body = textField(4, "Document", "Hello");
    const tools = toolbar(5, &.{ &save, &autosave });
    const root_stack = stack(6, &.{ &tools, &title, &body });
    const root = window(7, "Writer", &.{&root_stack});

    var output: [MAX_RENDER_BYTES]u8 = undefined;
    const rendered = try render(&root, &output);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "role=icon_button") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "value=\"save\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "checked=yes") != null);
}
