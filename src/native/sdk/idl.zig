const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");

pub const MAX_INTERFACES: usize = 8;
pub const MAX_OPERATIONS: usize = 32;
pub const MAX_RECORDS: usize = 24;
pub const MAX_FIELDS: usize = 96;
pub const MAX_DECLARATIONS: usize = 32;
pub const MAX_NAME_BYTES: usize = 64;
pub const MAX_RESOURCE_BYTES: usize = 96;
pub const MAX_GENERATED_BYTES: usize = 32768;
pub const COMPACT_IDL_METADATA = true;
pub const TYPE_REF_SIZE_CEILING_BYTES: usize = 66;
pub const FIELD_SIZE_CEILING_BYTES: usize = 132;
pub const RECORD_SIZE_CEILING_BYTES: usize = 67;
pub const PERMISSION_DECL_SIZE_CEILING_BYTES: usize = 100;
pub const OBJECT_DECL_SIZE_CEILING_BYTES: usize = 166;
pub const SYNC_DECL_SIZE_CEILING_BYTES: usize = 100;
pub const OPERATION_SIZE_CEILING_BYTES: usize = 204;
pub const INTERFACE_SIZE_CEILING_BYTES: usize = 72;
pub const DOCUMENT_SIZE_CEILING_BYTES: usize = 33_104;
pub const GENERATED_SOURCE_SIZE_CEILING_BYTES: usize = 32_770;

comptime {
    if (MAX_INTERFACES > std.math.maxInt(u8) or
        MAX_OPERATIONS > std.math.maxInt(u8) or
        MAX_RECORDS > std.math.maxInt(u8) or
        MAX_FIELDS > std.math.maxInt(u8) or
        MAX_DECLARATIONS > std.math.maxInt(u8) or
        MAX_NAME_BYTES > std.math.maxInt(u8) or
        MAX_RESOURCE_BYTES > std.math.maxInt(u8))
    {
        @compileError("IDL tables or text exceed compact byte metadata capacity");
    }
    if (MAX_GENERATED_BYTES > std.math.maxInt(u16)) {
        @compileError("generated IDL output exceeds compact length metadata capacity");
    }
}

pub const Error = error{
    EmptyInput,
    UnknownDirective,
    MissingInterfaceName,
    MissingVersion,
    MissingRecordName,
    MissingFieldName,
    MissingFieldType,
    MissingOperationName,
    MissingRequestSize,
    MissingResponseSize,
    MissingOperationArrow,
    MissingOperationRequestType,
    MissingOperationResponseType,
    MissingPermissionKind,
    MissingPermissionResource,
    MissingObjectName,
    MissingObjectType,
    MissingObjectPath,
    MissingSyncPrefix,
    MissingSyncSemantic,
    InvalidNumber,
    InvalidCardinality,
    UnknownPermissionKind,
    UnknownObjectKind,
    UnknownSyncSemantic,
    InterfaceTableFull,
    OperationTableFull,
    RecordTableFull,
    FieldTableFull,
    PermissionTableFull,
    ObjectTableFull,
    SyncTableFull,
    InterfaceNameTooLong,
    OperationNameTooLong,
    RecordNameTooLong,
    FieldNameTooLong,
    FieldTypeTooLong,
    PermissionResourceTooLong,
    ObjectPathTooLong,
    SyncPrefixTooLong,
    DuplicateInterface,
    DuplicateOperation,
    DuplicateRecord,
    DuplicateField,
    OperationBeforeInterface,
    FieldBeforeRecord,
    UnresolvedRecordType,
    UntypedOperation,
    GeneratedOutputTooLong,
};

pub const TypeKind = enum(u8) {
    void,
    bool,
    u8,
    u16,
    u32,
    u64,
    i64,
    string,
    bytes,
    object_id,
    version_id,
    principal_id,
    capability_id,
    record,
};

pub const Cardinality = enum(u8) {
    required,
    optional,
    list,
};

pub const TypeRef = struct {
    kind: TypeKind = .void,
    name_len: u8 = 0,
    name: [MAX_NAME_BYTES]u8 = [_]u8{0} ** MAX_NAME_BYTES,

    pub fn nameSlice(self: *const TypeRef) []const u8 {
        return self.name[0..@as(usize, self.name_len)];
    }
};

pub const Field = struct {
    name_len: u8 = 0,
    name: [MAX_NAME_BYTES]u8 = [_]u8{0} ** MAX_NAME_BYTES,
    type_ref: TypeRef = .{},
    cardinality: Cardinality = .required,

    pub fn nameSlice(self: *const Field) []const u8 {
        return self.name[0..@as(usize, self.name_len)];
    }
};

pub const Record = struct {
    name_len: u8 = 0,
    name: [MAX_NAME_BYTES]u8 = [_]u8{0} ** MAX_NAME_BYTES,
    field_start: u8 = 0,
    field_count: u8 = 0,

    pub fn nameSlice(self: *const Record) []const u8 {
        return self.name[0..@as(usize, self.name_len)];
    }
};

pub const ObjectKind = enum(u8) {
    blob,
    document,
    collection,
    secret,
    media_asset,
    model_artifact,
    event_stream,
};

pub const SyncSemantic = enum(u8) {
    mergeable_crdt,
    chunked_snapshot,
    secure_transfer,
    transactional_contract,
};

pub const PermissionDecl = struct {
    kind: manifest.PermissionKind = .object_access,
    resource_len: u8 = 0,
    resource: [MAX_RESOURCE_BYTES]u8 = [_]u8{0} ** MAX_RESOURCE_BYTES,
    required: bool = true,
    local_only: bool = true,

    pub fn resourceSlice(self: *const PermissionDecl) []const u8 {
        return self.resource[0..@as(usize, self.resource_len)];
    }
};

pub const ObjectDecl = struct {
    name_len: u8 = 0,
    name: [MAX_NAME_BYTES]u8 = [_]u8{0} ** MAX_NAME_BYTES,
    kind: ObjectKind = .document,
    path_len: u8 = 0,
    path: [MAX_RESOURCE_BYTES]u8 = [_]u8{0} ** MAX_RESOURCE_BYTES,
    signed: bool = true,
    versioned: bool = true,
    sync: bool = true,

    pub fn nameSlice(self: *const ObjectDecl) []const u8 {
        return self.name[0..@as(usize, self.name_len)];
    }

    pub fn pathSlice(self: *const ObjectDecl) []const u8 {
        return self.path[0..@as(usize, self.path_len)];
    }
};

pub const SyncDecl = struct {
    prefix_len: u8 = 0,
    prefix: [MAX_RESOURCE_BYTES]u8 = [_]u8{0} ** MAX_RESOURCE_BYTES,
    semantic: SyncSemantic = .mergeable_crdt,
    local_first: bool = true,
    e2ee: bool = true,

    pub fn prefixSlice(self: *const SyncDecl) []const u8 {
        return self.prefix[0..@as(usize, self.prefix_len)];
    }
};

pub const Operation = struct {
    name_len: u8 = 0,
    name: [MAX_NAME_BYTES]u8 = [_]u8{0} ** MAX_NAME_BYTES,
    request_size: u32 = 0,
    response_size: u32 = 0,
    request_type_len: u8 = 0,
    request_type: [MAX_NAME_BYTES]u8 = [_]u8{0} ** MAX_NAME_BYTES,
    response_type_len: u8 = 0,
    response_type: [MAX_NAME_BYTES]u8 = [_]u8{0} ** MAX_NAME_BYTES,

    pub fn nameSlice(self: *const Operation) []const u8 {
        return self.name[0..@as(usize, self.name_len)];
    }

    pub fn requestTypeSlice(self: *const Operation) []const u8 {
        return self.request_type[0..@as(usize, self.request_type_len)];
    }

    pub fn responseTypeSlice(self: *const Operation) []const u8 {
        return self.response_type[0..@as(usize, self.response_type_len)];
    }

    pub fn isTyped(self: *const Operation) bool {
        return self.request_type_len != 0 and self.response_type_len != 0;
    }
};

pub const Interface = struct {
    name_len: u8 = 0,
    name: [MAX_NAME_BYTES]u8 = [_]u8{0} ** MAX_NAME_BYTES,
    version_major: u16 = 1,
    version_minor: u16 = 0,
    operation_start: u8 = 0,
    operation_count: u8 = 0,

    pub fn nameSlice(self: *const Interface) []const u8 {
        return self.name[0..@as(usize, self.name_len)];
    }

    pub fn manifestDecl(self: *const Interface) manifest.InterfaceDecl {
        return .{
            .name = self.nameSlice(),
            .version_major = self.version_major,
            .version_minor = self.version_minor,
        };
    }
};

pub const Document = struct {
    interface_count: u8 = 0,
    operation_count: u8 = 0,
    record_count: u8 = 0,
    field_count: u8 = 0,
    permission_count: u8 = 0,
    object_count: u8 = 0,
    sync_count: u8 = 0,
    interfaces: [MAX_INTERFACES]Interface = [_]Interface{.{}} ** MAX_INTERFACES,
    operations: [MAX_OPERATIONS]Operation = [_]Operation{.{}} ** MAX_OPERATIONS,
    records: [MAX_RECORDS]Record = [_]Record{.{}} ** MAX_RECORDS,
    fields: [MAX_FIELDS]Field = [_]Field{.{}} ** MAX_FIELDS,
    permissions: [MAX_DECLARATIONS]PermissionDecl = [_]PermissionDecl{.{}} ** MAX_DECLARATIONS,
    objects: [MAX_DECLARATIONS]ObjectDecl = [_]ObjectDecl{.{}} ** MAX_DECLARATIONS,
    syncs: [MAX_DECLARATIONS]SyncDecl = [_]SyncDecl{.{}} ** MAX_DECLARATIONS,

    pub fn interfaceAt(self: *const Document, index: usize) *const Interface {
        return &self.interfaces[index];
    }

    pub fn operationsFor(self: *const Document, interface: *const Interface) []const Operation {
        const start: usize = @intCast(interface.operation_start);
        const count: usize = @intCast(interface.operation_count);
        return self.operations[start .. start + count];
    }

    pub fn fieldsFor(self: *const Document, record: *const Record) []const Field {
        const start: usize = @intCast(record.field_start);
        const count: usize = @intCast(record.field_count);
        return self.fields[start .. start + count];
    }

    pub fn findInterface(self: *const Document, name: []const u8) ?*const Interface {
        for (self.interfaces[0..self.interface_count]) |*interface| {
            if (std.mem.eql(u8, interface.nameSlice(), name)) return interface;
        }
        return null;
    }

    pub fn findRecord(self: *const Document, name: []const u8) ?*const Record {
        for (self.records[0..self.record_count]) |*record| {
            if (std.mem.eql(u8, record.nameSlice(), name)) return record;
        }
        return null;
    }

    pub fn typedOperationCount(self: *const Document) usize {
        var count: usize = 0;
        for (self.operations[0..self.operation_count]) |*operation| {
            if (operation.isTyped()) count += 1;
        }
        return count;
    }

    pub fn allOperationsTyped(self: *const Document) bool {
        return self.operation_count != 0 and self.typedOperationCount() == self.operation_count;
    }

    pub fn nativeDeclarationCount(self: *const Document) usize {
        return @as(usize, self.permission_count) + @as(usize, self.object_count) + @as(usize, self.sync_count);
    }
};

pub const GeneratedSource = struct {
    len: u16 = 0,
    buffer: [MAX_GENERATED_BYTES]u8 = [_]u8{0} ** MAX_GENERATED_BYTES,

    pub fn slice(self: *const GeneratedSource) []const u8 {
        return self.buffer[0..@as(usize, self.len)];
    }
};

comptime {
    if (@sizeOf(TypeRef) > TYPE_REF_SIZE_CEILING_BYTES or
        @sizeOf(Field) > FIELD_SIZE_CEILING_BYTES or
        @sizeOf(Record) > RECORD_SIZE_CEILING_BYTES or
        @sizeOf(PermissionDecl) > PERMISSION_DECL_SIZE_CEILING_BYTES or
        @sizeOf(ObjectDecl) > OBJECT_DECL_SIZE_CEILING_BYTES or
        @sizeOf(SyncDecl) > SYNC_DECL_SIZE_CEILING_BYTES or
        @sizeOf(Operation) > OPERATION_SIZE_CEILING_BYTES or
        @sizeOf(Interface) > INTERFACE_SIZE_CEILING_BYTES or
        @sizeOf(Document) > DOCUMENT_SIZE_CEILING_BYTES or
        @sizeOf(GeneratedSource) > GENERATED_SOURCE_SIZE_CEILING_BYTES)
    {
        @compileError("IDL state exceeds its compact layout ceiling");
    }
}

pub fn parseInto(source: []const u8, document: *Document) Error!void {
    document.* = .{};
    if (std.mem.trim(u8, source, " \t\r\n").len == 0) return error.EmptyInput;

    const doc = document;
    var current_interface_index: ?usize = null;
    var current_record_index: ?usize = null;
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        var tokens = std.mem.tokenizeAny(u8, line, " \t");
        const directive = tokens.next() orelse continue;
        if (std.mem.eql(u8, directive, "interface")) {
            const name = tokens.next() orelse return error.MissingInterfaceName;
            const version_text = tokens.next() orelse return error.MissingVersion;
            current_interface_index = try addInterface(doc, name, version_text);
            current_record_index = null;
        } else if (std.mem.eql(u8, directive, "record")) {
            const name = tokens.next() orelse return error.MissingRecordName;
            current_record_index = try addRecord(doc, name);
        } else if (std.mem.eql(u8, directive, "field")) {
            const record_index = current_record_index orelse return error.FieldBeforeRecord;
            const name = tokens.next() orelse return error.MissingFieldName;
            const type_name = tokens.next() orelse return error.MissingFieldType;
            const cardinality = if (tokens.next()) |token| try parseCardinality(token) else Cardinality.required;
            try addField(doc, record_index, name, try parseTypeRef(type_name), cardinality);
        } else if (std.mem.eql(u8, directive, "operation") or std.mem.eql(u8, directive, "op")) {
            const interface_index = current_interface_index orelse return error.OperationBeforeInterface;
            const name = tokens.next() orelse return error.MissingOperationName;
            const request_token = tokens.next() orelse return error.MissingOperationRequestType;
            if (parseMaybeU32(request_token)) |request_size| {
                const response_size = try parseU32(tokens.next() orelse return error.MissingResponseSize);
                try addOperation(doc, interface_index, name, request_size, response_size);
            } else {
                const arrow = tokens.next() orelse return error.MissingOperationArrow;
                if (!std.mem.eql(u8, arrow, "->")) return error.MissingOperationArrow;
                const response_type = tokens.next() orelse return error.MissingOperationResponseType;
                try addTypedOperation(doc, interface_index, name, request_token, response_type);
            }
        } else if (std.mem.eql(u8, directive, "permission")) {
            const kind = try parsePermissionKind(tokens.next() orelse return error.MissingPermissionKind);
            const resource = tokens.next() orelse return error.MissingPermissionResource;
            try addPermission(doc, kind, resource, tokens.rest());
        } else if (std.mem.eql(u8, directive, "object")) {
            const name = tokens.next() orelse return error.MissingObjectName;
            const kind = try parseObjectKind(tokens.next() orelse return error.MissingObjectType);
            const path = tokens.next() orelse return error.MissingObjectPath;
            try addObject(doc, name, kind, path, tokens.rest());
        } else if (std.mem.eql(u8, directive, "sync")) {
            const prefix = tokens.next() orelse return error.MissingSyncPrefix;
            const semantic = try parseSyncSemantic(tokens.next() orelse return error.MissingSyncSemantic);
            try addSync(doc, prefix, semantic, tokens.rest());
        } else {
            return error.UnknownDirective;
        }
    }

    if (doc.interface_count == 0) return error.EmptyInput;
    try validateTypeReferences(doc);
    populateTypedOperationSizes(doc);
}

pub fn generateZigBindings(document: *const Document, output: []u8) Error![]const u8 {
    var cursor: usize = 0;
    try appendFmt(
        output,
        &cursor,
        "// generated by zigos idl/codegen\npub const interface_count: usize = {d};\npub const record_count: usize = {d};\npub const native_declaration_count: usize = {d};\npub const OperationDescriptor = struct {{ name: []const u8, request_type: []const u8, response_type: []const u8, request_size: u32, response_size: u32 }};\npub const InterfaceDescriptor = struct {{ name: []const u8, version_major: u16, version_minor: u16, operation_count: usize }};\npub const FieldDescriptor = struct {{ name: []const u8, type_name: []const u8, cardinality: []const u8 }};\npub const RecordDescriptor = struct {{ name: []const u8, field_count: usize }};\n\n",
        .{ document.interface_count, document.record_count, document.nativeDeclarationCount() },
    );

    for (document.records[0..document.record_count]) |*record| {
        try append(output, &cursor, "pub const ");
        try appendIdentifier(output, &cursor, record.nameSlice());
        try append(output, &cursor, " = struct {\n");
        for (document.fieldsFor(record)) |*field| {
            try append(output, &cursor, "    ");
            try appendIdentifier(output, &cursor, field.nameSlice());
            try append(output, &cursor, ": ");
            try appendZigType(output, &cursor, field);
            try append(output, &cursor, ",\n");
        }
        try append(output, &cursor, "    pub const descriptor = RecordDescriptor{ .name = \"");
        try append(output, &cursor, record.nameSlice());
        try appendFmt(output, &cursor, "\", .field_count = {d} }};\n", .{record.field_count});
        try append(output, &cursor, "    pub const fields = [_]FieldDescriptor{\n");
        for (document.fieldsFor(record)) |*field| {
            try appendFmt(output, &cursor, "        .{{ .name = \"{s}\", .type_name = \"{s}\", .cardinality = \"{s}\" }},\n", .{
                field.nameSlice(),
                fieldTypeName(field),
                @tagName(field.cardinality),
            });
        }
        try append(output, &cursor, "    };\n};\n\n");
    }

    for (document.interfaces[0..document.interface_count]) |*interface| {
        try append(output, &cursor, "pub const ");
        try appendIdentifier(output, &cursor, interface.nameSlice());
        try append(output, &cursor, " = struct {\n");
        try appendFmt(output, &cursor, "    pub const name = \"{s}\";\n", .{interface.nameSlice()});
        try appendFmt(output, &cursor, "    pub const version_major: u16 = {d};\n", .{interface.version_major});
        try appendFmt(output, &cursor, "    pub const version_minor: u16 = {d};\n", .{interface.version_minor});
        try appendFmt(output, &cursor, "    pub const operation_count: usize = {d};\n", .{interface.operation_count});
        try append(output, &cursor, "    pub const descriptor = InterfaceDescriptor{ .name = name, .version_major = version_major, .version_minor = version_minor, .operation_count = operation_count };\n");
        try append(output, &cursor, "    pub const Operation = enum(u16) {\n");

        for (document.operationsFor(interface)) |*operation| {
            try append(output, &cursor, "        ");
            try appendIdentifier(output, &cursor, operation.nameSlice());
            try append(output, &cursor, ",\n");
        }

        try append(output, &cursor, "    };\n\n");
        try append(output, &cursor, "    pub const operations = [_]OperationDescriptor{\n");

        for (document.operationsFor(interface)) |*operation| {
            try appendFmt(output, &cursor, "        .{{ .name = \"{s}\", .request_type = \"{s}\", .response_type = \"{s}\", .request_size = {d}, .response_size = {d} }},\n", .{
                operation.nameSlice(),
                operation.requestTypeSlice(),
                operation.responseTypeSlice(),
                operation.request_size,
                operation.response_size,
            });
        }

        try append(output, &cursor, "    };\n\n");

        for (document.operationsFor(interface)) |*operation| {
            try append(output, &cursor, "    pub const ");
            try appendIdentifier(output, &cursor, operation.nameSlice());
            try append(output, &cursor, " = struct {\n");
            try append(output, &cursor, "        pub const operation: Operation = .");
            try appendIdentifier(output, &cursor, operation.nameSlice());
            try append(output, &cursor, ";\n");
            try appendFmt(output, &cursor, "        pub const name = \"{s}\";\n", .{operation.nameSlice()});
            try appendFmt(output, &cursor, "        pub const request_type = \"{s}\";\n", .{operation.requestTypeSlice()});
            try appendFmt(output, &cursor, "        pub const response_type = \"{s}\";\n", .{operation.responseTypeSlice()});
            try appendFmt(output, &cursor, "        pub const request_size: u32 = {d};\n", .{operation.request_size});
            try appendFmt(output, &cursor, "        pub const response_size: u32 = {d};\n", .{operation.response_size});
            try append(output, &cursor, "    };\n");
        }

        try append(output, &cursor, "};\n\n");
    }

    return output[0..cursor];
}

pub fn generateInto(document: *const Document, generated: *GeneratedSource) Error!void {
    generated.* = .{};
    const slice = try generateZigBindings(document, &generated.buffer);
    generated.len = @intCast(slice.len);
}

fn addInterface(doc: *Document, name: []const u8, version_text: []const u8) Error!usize {
    if (doc.interface_count >= doc.interfaces.len) return error.InterfaceTableFull;
    if (doc.findInterface(name) != null) return error.DuplicateInterface;

    const version = try parseVersion(version_text);
    const index: usize = @intCast(doc.interface_count);
    var interface = Interface{
        .version_major = version.major,
        .version_minor = version.minor,
        .operation_start = doc.operation_count,
        .operation_count = 0,
    };
    interface.name_len = @intCast(native_util.copyTextExact(&interface.name, name) catch return error.InterfaceNameTooLong);
    doc.interfaces[index] = interface;
    doc.interface_count += 1;
    return index;
}

fn addOperation(
    doc: *Document,
    interface_index: usize,
    name: []const u8,
    request_size: u32,
    response_size: u32,
) Error!void {
    if (doc.operation_count >= doc.operations.len) return error.OperationTableFull;

    const interface = &doc.interfaces[interface_index];
    for (doc.operationsFor(interface)) |*operation| {
        if (std.mem.eql(u8, operation.nameSlice(), name)) return error.DuplicateOperation;
    }

    const index: usize = @intCast(doc.operation_count);
    var operation = Operation{
        .request_size = request_size,
        .response_size = response_size,
    };
    operation.name_len = @intCast(native_util.copyTextExact(&operation.name, name) catch return error.OperationNameTooLong);
    doc.operations[index] = operation;
    doc.operation_count += 1;
    doc.interfaces[interface_index].operation_count += 1;
}

fn addTypedOperation(
    doc: *Document,
    interface_index: usize,
    name: []const u8,
    request_type: []const u8,
    response_type: []const u8,
) Error!void {
    if (doc.operation_count >= doc.operations.len) return error.OperationTableFull;

    const interface = &doc.interfaces[interface_index];
    for (doc.operationsFor(interface)) |*operation| {
        if (std.mem.eql(u8, operation.nameSlice(), name)) return error.DuplicateOperation;
    }

    const index: usize = @intCast(doc.operation_count);
    var operation = Operation{};
    operation.name_len = @intCast(native_util.copyTextExact(&operation.name, name) catch return error.OperationNameTooLong);
    operation.request_type_len = @intCast(native_util.copyTextExact(&operation.request_type, request_type) catch return error.FieldTypeTooLong);
    operation.response_type_len = @intCast(native_util.copyTextExact(&operation.response_type, response_type) catch return error.FieldTypeTooLong);
    doc.operations[index] = operation;
    doc.operation_count += 1;
    doc.interfaces[interface_index].operation_count += 1;
}

fn addRecord(doc: *Document, name: []const u8) Error!usize {
    if (doc.record_count >= doc.records.len) return error.RecordTableFull;
    if (doc.findRecord(name) != null) return error.DuplicateRecord;

    const index: usize = @intCast(doc.record_count);
    var record = Record{
        .field_start = doc.field_count,
        .field_count = 0,
    };
    record.name_len = @intCast(native_util.copyTextExact(&record.name, name) catch return error.RecordNameTooLong);
    doc.records[index] = record;
    doc.record_count += 1;
    return index;
}

fn addField(
    doc: *Document,
    record_index: usize,
    name: []const u8,
    type_ref: TypeRef,
    cardinality: Cardinality,
) Error!void {
    if (doc.field_count >= doc.fields.len) return error.FieldTableFull;

    const record = &doc.records[record_index];
    for (doc.fieldsFor(record)) |*field| {
        if (std.mem.eql(u8, field.nameSlice(), name)) return error.DuplicateField;
    }

    const index: usize = @intCast(doc.field_count);
    var field = Field{
        .type_ref = type_ref,
        .cardinality = cardinality,
    };
    field.name_len = @intCast(native_util.copyTextExact(&field.name, name) catch return error.FieldNameTooLong);
    doc.fields[index] = field;
    doc.field_count += 1;
    doc.records[record_index].field_count += 1;
}

fn addPermission(
    doc: *Document,
    kind: manifest.PermissionKind,
    resource: []const u8,
    flags: []const u8,
) Error!void {
    if (doc.permission_count >= doc.permissions.len) return error.PermissionTableFull;
    var decl = PermissionDecl{ .kind = kind };
    decl.resource_len = @intCast(native_util.copyTextExact(&decl.resource, resource) catch return error.PermissionResourceTooLong);
    applyPermissionFlags(&decl, flags);
    doc.permissions[doc.permission_count] = decl;
    doc.permission_count += 1;
}

fn addObject(
    doc: *Document,
    name: []const u8,
    kind: ObjectKind,
    path: []const u8,
    flags: []const u8,
) Error!void {
    if (doc.object_count >= doc.objects.len) return error.ObjectTableFull;
    var decl = ObjectDecl{ .kind = kind };
    decl.name_len = @intCast(native_util.copyTextExact(&decl.name, name) catch return error.RecordNameTooLong);
    decl.path_len = @intCast(native_util.copyTextExact(&decl.path, path) catch return error.ObjectPathTooLong);
    var tokens = std.mem.tokenizeAny(u8, flags, " \t");
    while (tokens.next()) |flag| {
        if (std.mem.eql(u8, flag, "unsigned")) decl.signed = false;
        if (std.mem.eql(u8, flag, "ephemeral")) decl.versioned = false;
        if (std.mem.eql(u8, flag, "local_only")) decl.sync = false;
    }
    doc.objects[doc.object_count] = decl;
    doc.object_count += 1;
}

fn addSync(
    doc: *Document,
    prefix: []const u8,
    semantic: SyncSemantic,
    flags: []const u8,
) Error!void {
    if (doc.sync_count >= doc.syncs.len) return error.SyncTableFull;
    var decl = SyncDecl{ .semantic = semantic };
    decl.prefix_len = @intCast(native_util.copyTextExact(&decl.prefix, prefix) catch return error.SyncPrefixTooLong);
    var tokens = std.mem.tokenizeAny(u8, flags, " \t");
    while (tokens.next()) |flag| {
        if (std.mem.eql(u8, flag, "remote_ok")) decl.local_first = false;
        if (std.mem.eql(u8, flag, "plaintext")) decl.e2ee = false;
    }
    doc.syncs[doc.sync_count] = decl;
    doc.sync_count += 1;
}

fn validateTypeReferences(doc: *const Document) Error!void {
    for (doc.fields[0..doc.field_count]) |*field| {
        if (field.type_ref.kind == .record and doc.findRecord(field.type_ref.nameSlice()) == null) {
            return error.UnresolvedRecordType;
        }
    }
    for (doc.operations[0..doc.operation_count]) |*operation| {
        if (!operation.isTyped()) continue;
        try validateOperationType(doc, operation.requestTypeSlice());
        try validateOperationType(doc, operation.responseTypeSlice());
    }
}

fn validateOperationType(doc: *const Document, type_name: []const u8) Error!void {
    if (std.mem.eql(u8, type_name, "void")) return;
    if (doc.findRecord(type_name) == null) return error.UnresolvedRecordType;
}

fn populateTypedOperationSizes(doc: *Document) void {
    for (doc.operations[0..doc.operation_count]) |*operation| {
        if (!operation.isTyped()) continue;
        operation.request_size = recordWireSize(doc, operation.requestTypeSlice());
        operation.response_size = recordWireSize(doc, operation.responseTypeSlice());
    }
}

fn recordWireSize(doc: *const Document, type_name: []const u8) u32 {
    if (std.mem.eql(u8, type_name, "void")) return 0;
    const record = doc.findRecord(type_name) orelse return 0;
    var total: u32 = 0;
    for (doc.fieldsFor(record)) |*field| {
        total += fieldWireSize(doc, field);
    }
    return total;
}

fn fieldWireSize(doc: *const Document, field: *const Field) u32 {
    const base: u32 = switch (field.type_ref.kind) {
        .void => 0,
        .bool, .u8 => 1,
        .u16 => 2,
        .u32 => 4,
        .u64, .i64, .object_id, .version_id, .principal_id, .capability_id => 8,
        .string, .bytes => 16,
        .record => recordWireSize(doc, field.type_ref.nameSlice()),
    };
    return switch (field.cardinality) {
        .required => base,
        .optional => base + 1,
        .list => 16,
    };
}

const Version = struct {
    major: u16,
    minor: u16,
};

fn parseTypeRef(type_name: []const u8) Error!TypeRef {
    var ref = TypeRef{ .kind = builtinTypeKind(type_name) orelse .record };
    ref.name_len = @intCast(native_util.copyTextExact(&ref.name, type_name) catch return error.FieldTypeTooLong);
    return ref;
}

fn builtinTypeKind(type_name: []const u8) ?TypeKind {
    if (std.mem.eql(u8, type_name, "void")) return .void;
    if (std.mem.eql(u8, type_name, "bool")) return .bool;
    if (std.mem.eql(u8, type_name, "u8")) return .u8;
    if (std.mem.eql(u8, type_name, "u16")) return .u16;
    if (std.mem.eql(u8, type_name, "u32")) return .u32;
    if (std.mem.eql(u8, type_name, "u64")) return .u64;
    if (std.mem.eql(u8, type_name, "i64")) return .i64;
    if (std.mem.eql(u8, type_name, "string")) return .string;
    if (std.mem.eql(u8, type_name, "bytes")) return .bytes;
    if (std.mem.eql(u8, type_name, "object_id")) return .object_id;
    if (std.mem.eql(u8, type_name, "version_id")) return .version_id;
    if (std.mem.eql(u8, type_name, "principal_id")) return .principal_id;
    if (std.mem.eql(u8, type_name, "capability_id")) return .capability_id;
    return null;
}

fn parseCardinality(text: []const u8) Error!Cardinality {
    if (std.mem.eql(u8, text, "required")) return .required;
    if (std.mem.eql(u8, text, "optional")) return .optional;
    if (std.mem.eql(u8, text, "list")) return .list;
    return error.InvalidCardinality;
}

fn parsePermissionKind(text: []const u8) Error!manifest.PermissionKind {
    inline for (@typeInfo(manifest.PermissionKind).@"enum".fields) |field| {
        if (std.mem.eql(u8, text, field.name)) return @enumFromInt(field.value);
    }
    return error.UnknownPermissionKind;
}

fn parseObjectKind(text: []const u8) Error!ObjectKind {
    inline for (@typeInfo(ObjectKind).@"enum".fields) |field| {
        if (std.mem.eql(u8, text, field.name)) return @enumFromInt(field.value);
    }
    return error.UnknownObjectKind;
}

fn parseSyncSemantic(text: []const u8) Error!SyncSemantic {
    inline for (@typeInfo(SyncSemantic).@"enum".fields) |field| {
        if (std.mem.eql(u8, text, field.name)) return @enumFromInt(field.value);
    }
    return error.UnknownSyncSemantic;
}

fn applyPermissionFlags(decl: *PermissionDecl, flags: []const u8) void {
    var tokens = std.mem.tokenizeAny(u8, flags, " \t");
    while (tokens.next()) |flag| {
        if (std.mem.eql(u8, flag, "optional")) decl.required = false;
        if (std.mem.eql(u8, flag, "required")) decl.required = true;
        if (std.mem.eql(u8, flag, "remote_ok")) decl.local_only = false;
        if (std.mem.eql(u8, flag, "local_only")) decl.local_only = true;
    }
}

fn parseVersion(text: []const u8) Error!Version {
    if (text.len == 0) return error.InvalidNumber;
    if (text[0] == 'v') {
        return .{
            .major = parseU16(text[1..]) catch return error.InvalidNumber,
            .minor = 0,
        };
    }
    if (std.mem.indexOfScalar(u8, text, '.')) |dot| {
        return .{
            .major = parseU16(text[0..dot]) catch return error.InvalidNumber,
            .minor = parseU16(text[dot + 1 ..]) catch return error.InvalidNumber,
        };
    }
    return .{
        .major = parseU16(text) catch return error.InvalidNumber,
        .minor = 0,
    };
}

fn parseU16(text: []const u8) Error!u16 {
    return std.fmt.parseInt(u16, text, 10) catch error.InvalidNumber;
}

fn parseU32(text: []const u8) Error!u32 {
    return std.fmt.parseInt(u32, text, 10) catch error.InvalidNumber;
}

fn parseMaybeU32(text: []const u8) ?u32 {
    return std.fmt.parseInt(u32, text, 10) catch null;
}

fn append(output: []u8, cursor: *usize, text: []const u8) Error!void {
    if (cursor.* + text.len > output.len) return error.GeneratedOutputTooLong;
    @memcpy(output[cursor.* .. cursor.* + text.len], text);
    cursor.* += text.len;
}

fn appendFmt(output: []u8, cursor: *usize, comptime fmt: []const u8, args: anytype) Error!void {
    const written = std.fmt.bufPrint(output[cursor.*..], fmt, args) catch return error.GeneratedOutputTooLong;
    cursor.* += written.len;
}

fn appendByte(output: []u8, cursor: *usize, byte: u8) Error!void {
    if (cursor.* >= output.len) return error.GeneratedOutputTooLong;
    output[cursor.*] = byte;
    cursor.* += 1;
}

fn appendIdentifier(output: []u8, cursor: *usize, name: []const u8) Error!void {
    if (name.len == 0) return appendByte(output, cursor, '_');
    if (isDigit(name[0])) try appendByte(output, cursor, '_');
    for (name) |byte| {
        try appendByte(output, cursor, if (isIdent(byte)) byte else '_');
    }
}

fn appendZigType(output: []u8, cursor: *usize, field: *const Field) Error!void {
    switch (field.cardinality) {
        .required => {},
        .optional => try append(output, cursor, "?"),
        .list => try append(output, cursor, "[]const "),
    }

    switch (field.type_ref.kind) {
        .void => try append(output, cursor, "void"),
        .bool => try append(output, cursor, "bool"),
        .u8 => try append(output, cursor, "u8"),
        .u16 => try append(output, cursor, "u16"),
        .u32 => try append(output, cursor, "u32"),
        .u64 => try append(output, cursor, "u64"),
        .i64 => try append(output, cursor, "i64"),
        .string, .bytes => try append(output, cursor, "[]const u8"),
        .object_id, .version_id, .principal_id, .capability_id => try append(output, cursor, "u64"),
        .record => try appendIdentifier(output, cursor, field.type_ref.nameSlice()),
    }
}

fn fieldTypeName(field: *const Field) []const u8 {
    return field.type_ref.nameSlice();
}

fn isIdent(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or
        (byte >= 'A' and byte <= 'Z') or
        (byte >= '0' and byte <= '9') or
        byte == '_';
}

fn isDigit(byte: u8) bool {
    return byte >= '0' and byte <= '9';
}

test "IDL parser produces manifest interfaces and codegen bindings" {
    const source =
        \\interface writer.edit 1.2
        \\record OpenRequest
        \\field object object_id
        \\field path string
        \\record SaveRequest
        \\field object object_id
        \\field version version_id
        \\field patch bytes optional
        \\record SaveResponse
        \\field version version_id
        \\operation open OpenRequest -> SaveResponse
        \\operation save SaveRequest -> SaveResponse
        \\permission object_access workspace://documents local_only
        \\object document document workspace://documents signed versioned sync
        \\sync documents/ mergeable_crdt local_first
    ;
    var doc: Document = undefined;
    try parseInto(source, &doc);
    try std.testing.expectEqual(@as(u8, 1), doc.interface_count);
    try std.testing.expectEqual(@as(u8, 2), doc.operation_count);
    try std.testing.expectEqual(@as(u8, 3), doc.record_count);
    try std.testing.expectEqual(@as(u8, 1), doc.permission_count);
    try std.testing.expectEqual(@as(u8, 1), doc.object_count);
    try std.testing.expectEqual(@as(u8, 1), doc.sync_count);
    try std.testing.expect(doc.allOperationsTyped());
    try std.testing.expectEqualStrings("writer.edit", doc.interfaceAt(0).nameSlice());
    try std.testing.expectEqual(@as(u16, 1), doc.interfaceAt(0).manifestDecl().version_major);
    try std.testing.expectEqualStrings("SaveRequest", doc.operations[1].requestTypeSlice());
    try std.testing.expect(doc.operations[1].request_size > 0);

    var generated: GeneratedSource = undefined;
    try generateInto(&doc, &generated);
    try std.testing.expect(std.mem.indexOf(u8, generated.slice(), "pub const OpenRequest") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated.slice(), "pub const writer_edit") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated.slice(), "pub const save") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated.slice(), "request_type = \"SaveRequest\"") != null);
}

test "IDL records keep bounded metadata compact" {
    try std.testing.expectEqual(u8, @FieldType(TypeRef, "name_len"));
    try std.testing.expectEqual(u8, @FieldType(Record, "field_start"));
    try std.testing.expectEqual(u8, @FieldType(Record, "field_count"));
    try std.testing.expectEqual(u8, @FieldType(Operation, "request_type_len"));
    try std.testing.expectEqual(u8, @FieldType(Interface, "operation_start"));
    try std.testing.expectEqual(u8, @FieldType(Document, "field_count"));
    try std.testing.expectEqual(u16, @FieldType(GeneratedSource, "len"));
    try std.testing.expect(@sizeOf(TypeRef) <= TYPE_REF_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(Field) <= FIELD_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(Record) <= RECORD_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(PermissionDecl) <= PERMISSION_DECL_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(ObjectDecl) <= OBJECT_DECL_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(SyncDecl) <= SYNC_DECL_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(Operation) <= OPERATION_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(Interface) <= INTERFACE_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(Document) <= DOCUMENT_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(GeneratedSource) <= GENERATED_SOURCE_SIZE_CEILING_BYTES);
}

test "IDL parser rejects ambiguous developer contracts" {
    var doc: Document = undefined;
    try std.testing.expectError(error.OperationBeforeInterface, parseInto("operation save 1 1", &doc));
    const duplicate_interface =
        \\interface writer.edit 1.0
        \\interface writer.edit 1.0
    ;
    try std.testing.expectError(error.DuplicateInterface, parseInto(duplicate_interface, &doc));
    const duplicate_operation =
        \\interface writer.edit 1.0
        \\operation save 1 1
        \\operation save 2 2
    ;
    try std.testing.expectError(error.DuplicateOperation, parseInto(duplicate_operation, &doc));
    const unresolved_record_type =
        \\interface writer.edit 1.0
        \\operation save MissingRequest -> MissingResponse
    ;
    try std.testing.expectError(error.UnresolvedRecordType, parseInto(unresolved_record_type, &doc));
}
