const std = @import("std");

pub const MAX_CHILDREN: usize = 8;
pub const MAX_LABEL_BYTES: usize = 64;
pub const MAX_RENDER_BYTES: usize = 4096;
pub const MAX_A11Y_NODES: usize = 128;
pub const MAX_A11Y_ISSUES: usize = 32;
pub const COMPACT_REVIEW_UI_METADATA = true;
pub const NODE_SIZE_CEILING_BYTES: usize = 128;
pub const ACCESSIBILITY_REPORT_SIZE_CEILING_BYTES: usize = 776;
const AUDIT_STATE_SIZE_CEILING_BYTES: usize = 1_296;

comptime {
    if (MAX_CHILDREN > std.math.maxInt(u8) or
        MAX_A11Y_NODES > std.math.maxInt(u8) or
        MAX_A11Y_ISSUES > std.math.maxInt(u8))
    {
        @compileError("SDK review UI state exceeds compact count metadata capacity");
    }
}

pub const Role = enum(u8) {
    window,
    stack,
    toolbar,
    heading,
    text,
    button,
    icon_button,
    text_field,
    toggle,
    list,
    list_item,
    image,
    slider,
    status,
    dialog,
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
    focusable: bool = false,
    focus_order: u16 = 0,
    semantic_level: u8 = 0,
    live_region: bool = false,
    child_count: u8 = 0,
    hint: []const u8 = "",
    children: [MAX_CHILDREN]*const Node = undefined,

    pub fn withChildren(self: Node, children: []const *const Node) Node {
        var copy = self;
        copy.child_count = @intCast(@min(children.len, copy.children.len));
        for (children[0..@as(usize, copy.child_count)], 0..) |child, index| {
            copy.children[index] = child;
        }
        return copy;
    }
};

pub const AccessibilityIssueCode = enum(u8) {
    duplicate_id,
    missing_label,
    missing_hint,
    disabled_focusable,
    heading_level_missing,
    too_many_nodes,
};

pub const AccessibilityIssue = struct {
    node_id: u32,
    code: AccessibilityIssueCode,
    detail: []const u8,
};

pub const AccessibilityReport = struct {
    node_count: u8 = 0,
    issue_count: u8 = 0,
    issues: [MAX_A11Y_ISSUES]AccessibilityIssue = undefined,

    pub fn hasErrors(self: *const AccessibilityReport) bool {
        return self.issue_count != 0;
    }

    pub fn count(self: *const AccessibilityReport, code: AccessibilityIssueCode) usize {
        var total: usize = 0;
        for (self.issues[0..@as(usize, self.issue_count)]) |issue| {
            if (issue.code == code) total += 1;
        }
        return total;
    }

    fn add(self: *AccessibilityReport, node_id: u32, code: AccessibilityIssueCode, detail: []const u8) void {
        if (self.issue_count >= self.issues.len) return;
        self.issues[self.issue_count] = .{
            .node_id = node_id,
            .code = code,
            .detail = detail,
        };
        self.issue_count += 1;
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

pub fn heading(id: u32, label: []const u8, level: u8) Node {
    return .{ .id = id, .role = .heading, .label = label, .semantic_level = level };
}

pub fn button(id: u32, label: []const u8, intent: Intent) Node {
    return .{ .id = id, .role = .button, .label = label, .intent = intent, .focusable = true };
}

pub fn iconButton(id: u32, label: []const u8, value: []const u8, intent: Intent) Node {
    return .{ .id = id, .role = .icon_button, .label = label, .value = value, .intent = intent, .focusable = true };
}

pub fn textField(id: u32, label: []const u8, value: []const u8) Node {
    return .{ .id = id, .role = .text_field, .label = label, .value = value, .focusable = true };
}

pub fn toggle(id: u32, label: []const u8, checked: bool) Node {
    return .{ .id = id, .role = .toggle, .label = label, .checked = checked, .focusable = true };
}

pub fn permissionRow(id: u32, label: []const u8, allowed: bool) Node {
    return .{
        .id = id,
        .role = .permission_row,
        .label = label,
        .checked = allowed,
        .intent = if (allowed) .permission_allow else .permission_deny,
        .focusable = true,
    };
}

pub fn status(id: u32, label: []const u8, value: []const u8) Node {
    return .{ .id = id, .role = .status, .label = label, .value = value, .live_region = true };
}

pub fn image(id: u32, label: []const u8, value: []const u8) Node {
    return .{ .id = id, .role = .image, .label = label, .value = value };
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
        "id={d} role={s} intent={s} enabled={s} focusable={s} checked={s} level={d} label=\"{s}\" value=\"{s}\" hint=\"{s}\"\n",
        .{ node.id, @tagName(node.role), @tagName(node.intent), yesNo(node.enabled), yesNo(node.focusable), yesNo(node.checked), node.semantic_level, node.label, node.value, node.hint },
    );
    for (node.children[0..@as(usize, node.child_count)]) |child| {
        try renderNode(child, depth + 1, out, cursor);
    }
}

pub fn audit(root: *const Node) AccessibilityReport {
    var state = AuditState{};
    auditNode(root, &state);
    return state.report;
}

const AuditState = struct {
    report: AccessibilityReport = .{},
    seen_count: u8 = 0,
    seen_ids: [MAX_A11Y_NODES]u32 = [_]u32{0} ** MAX_A11Y_NODES,
};

comptime {
    if (@sizeOf(Node) > NODE_SIZE_CEILING_BYTES or
        @sizeOf(AccessibilityReport) > ACCESSIBILITY_REPORT_SIZE_CEILING_BYTES or
        @sizeOf(AuditState) > AUDIT_STATE_SIZE_CEILING_BYTES)
    {
        @compileError("SDK review UI state exceeds its compact size ceiling");
    }
}

fn auditNode(node: *const Node, state: *AuditState) void {
    if (state.seen_count >= state.seen_ids.len) {
        state.report.add(node.id, .too_many_nodes, "accessibility audit node capacity exceeded");
        return;
    }
    if (seenId(state, node.id)) {
        state.report.add(node.id, .duplicate_id, "node IDs must be stable and unique");
    } else {
        state.seen_ids[state.seen_count] = node.id;
        state.seen_count += 1;
    }
    state.report.node_count += 1;

    if (requiresLabel(node.role) and node.label.len == 0) {
        state.report.add(node.id, .missing_label, "interactive and semantic nodes require labels");
    }
    if (node.role == .icon_button and node.hint.len == 0) {
        state.report.add(node.id, .missing_hint, "icon buttons require a hint for assistive tech");
    }
    if (node.focusable and !node.enabled) {
        state.report.add(node.id, .disabled_focusable, "disabled nodes must not stay in focus order");
    }
    if (node.role == .heading and node.semantic_level == 0) {
        state.report.add(node.id, .heading_level_missing, "headings require a semantic level");
    }

    for (node.children[0..@as(usize, node.child_count)]) |child| {
        auditNode(child, state);
    }
}

fn seenId(state: *const AuditState, id: u32) bool {
    for (state.seen_ids[0..@as(usize, state.seen_count)]) |seen| {
        if (seen == id) return true;
    }
    return false;
}

fn requiresLabel(role: Role) bool {
    return switch (role) {
        .window,
        .heading,
        .button,
        .icon_button,
        .text_field,
        .toggle,
        .list_item,
        .image,
        .slider,
        .status,
        .dialog,
        .permission_row,
        => true,
        .stack,
        .toolbar,
        .text,
        .list,
        => false,
    };
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

test "UI review and accessibility records keep bounded metadata compact" {
    try std.testing.expectEqual(u8, @FieldType(Node, "child_count"));
    try std.testing.expectEqual(u8, @FieldType(AccessibilityReport, "node_count"));
    try std.testing.expectEqual(u8, @FieldType(AccessibilityReport, "issue_count"));
    try std.testing.expectEqual(u8, @FieldType(AuditState, "seen_count"));
    try std.testing.expect(@sizeOf(Node) <= NODE_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(AccessibilityReport) <= ACCESSIBILITY_REPORT_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(AuditState) <= AUDIT_STATE_SIZE_CEILING_BYTES);
}

test "UI primitives render a stable native tree for simulator snapshots" {
    const title = heading(1, "Zigos Writer", 1);
    var save = iconButton(2, "Save", "save", .primary);
    save.hint = "Save the current document";
    const autosave = toggle(3, "Autosave", true);
    const body = textField(4, "Document", "Hello");
    const saved = status(8, "Autosave status", "Saved");
    const tools = toolbar(5, &.{ &save, &autosave });
    const root_stack = stack(6, &.{ &tools, &title, &body, &saved });
    const root = window(7, "Writer", &.{&root_stack});

    var output: [MAX_RENDER_BYTES]u8 = undefined;
    const rendered = try render(&root, &output);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "role=icon_button") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "value=\"save\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "focusable=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "checked=yes") != null);

    const report = audit(&root);
    try std.testing.expect(!report.hasErrors());
}

test "UI accessibility audit catches unlabeled controls and duplicate IDs" {
    const bad_button = button(10, "", .primary);
    const duplicate = textField(10, "Name", "");
    const root = window(11, "Bad Surface", &.{ &bad_button, &duplicate });

    const report = audit(&root);
    try std.testing.expect(report.hasErrors());
    try std.testing.expectEqual(@as(usize, 1), report.count(.missing_label));
    try std.testing.expectEqual(@as(usize, 1), report.count(.duplicate_id));
}
