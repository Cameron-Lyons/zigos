const builtin = @import("builtin");
const store = @import("object_store/store.zig");

pub const ids = store.ids;

pub const MAX_OBJECTS = store.MAX_OBJECTS;
pub const MAX_VERSIONS = store.MAX_VERSIONS;
pub const MAX_BLOBS = store.MAX_BLOBS;
pub const PAGE_SIZE_BYTES = store.PAGE_SIZE_BYTES;
pub const MAX_CHUNK_BYTES = store.MAX_CHUNK_BYTES;
pub const MAX_BLOB_CHUNKS = store.MAX_BLOB_CHUNKS;
pub const MAX_CHUNKS = store.MAX_CHUNKS;
pub const MAX_BLOB_BYTES = store.MAX_BLOB_BYTES;
pub const MAX_PAYLOAD_BYTES = store.MAX_PAYLOAD_BYTES;
pub const MAX_VERSION_PARENTS = store.MAX_VERSION_PARENTS;

pub const StoreConfig = store.StoreConfig;
pub const ObjectType = store.ObjectType;
pub const BlobAddress = store.BlobAddress;
pub const ChunkAddress = store.ChunkAddress;
pub const VersionAddress = store.VersionAddress;
pub const SignedMetadata = store.SignedMetadata;
pub const PutRequest = store.PutRequest;
pub const PutResult = store.PutResult;
pub const ObjectRecord = store.ObjectRecord;
pub const ObjectProvenance = store.ObjectProvenance;
pub const ObjectSnapshotState = store.ObjectSnapshotState;
pub const ObjectSyncState = store.ObjectSyncState;
pub const ObjectSharingPolicy = store.ObjectSharingPolicy;
pub const ObjectRecoveryHistory = store.ObjectRecoveryHistory;
pub const VersionRecord = store.VersionRecord;
pub const ChunkRef = store.ChunkRef;
pub const BlobRecord = store.BlobRecord;
pub const ChunkRecord = store.ChunkRecord;
pub const Error = store.Error;
pub const PayloadChunk = store.PayloadChunk;
pub const PayloadTransferSummary = store.PayloadTransferSummary;
pub const SignMetadataError = store.SignMetadataError;
pub const BlobSlot = store.BlobSlot;
pub const ChunkSlot = store.ChunkSlot;
pub const Store = store.Store;
pub const StoreWith = store.StoreWith;

pub const signMetadata = store.signMetadata;
pub const computeBlobAddress = store.computeBlobAddress;
pub const computeChunkAddress = store.computeChunkAddress;
pub const computeBlobManifestAddress = store.computeBlobManifestAddress;
pub const computeBlobMerkleRoot = store.computeBlobMerkleRoot;

comptime {
    if (builtin.is_test) _ = @import("object_store/tests.zig");
}
