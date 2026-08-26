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
pub const MAX_INLINE_PAYLOAD_CHUNKS = store.MAX_INLINE_PAYLOAD_CHUNKS;
pub const MAX_INLINE_PAYLOAD_BYTES = store.MAX_INLINE_PAYLOAD_BYTES;
pub const MAX_VERSION_PARENTS = store.MAX_VERSION_PARENTS;
pub const MAX_OBJECT_QUERY_RESULTS = store.MAX_OBJECT_QUERY_RESULTS;
pub const MAX_OBJECT_HISTORY_RESULTS = store.MAX_OBJECT_HISTORY_RESULTS;
pub const MAX_METADATA_LABEL_BYTES = store.MAX_METADATA_LABEL_BYTES;
pub const MAX_CONTENT_TYPE_BYTES = store.MAX_CONTENT_TYPE_BYTES;
pub const COMPACT_OBJECT_RESULT_METADATA = store.COMPACT_OBJECT_RESULT_METADATA;
pub const SKIPS_EMPTY_ARENA_RESET_WORK = store.SKIPS_EMPTY_ARENA_RESET_WORK;
pub const DERIVES_LATEST_INSERTED_VERSION_FROM_ARENA_STATE = store.DERIVES_LATEST_INSERTED_VERSION_FROM_ARENA_STATE;
pub const DERIVES_OBJECT_MODEL_VERSION_IDS_FROM_CANONICAL_HEAD = store.DERIVES_OBJECT_MODEL_VERSION_IDS_FROM_CANONICAL_HEAD;
pub const DERIVES_OBJECT_MODEL_COUNTERS_FROM_VERSION_COUNT = store.DERIVES_OBJECT_MODEL_COUNTERS_FROM_VERSION_COUNT;
pub const OBJECT_QUERY_RESULT_SIZE_CEILING_BYTES = store.OBJECT_QUERY_RESULT_SIZE_CEILING_BYTES;
pub const OBJECT_HISTORY_ENTRY_SIZE_CEILING_BYTES = store.OBJECT_HISTORY_ENTRY_SIZE_CEILING_BYTES;
pub const OBJECT_RECORD_SIZE_CEILING_BYTES = store.OBJECT_RECORD_SIZE_CEILING_BYTES;

pub const StoreConfig = store.StoreConfig;
pub const ObjectType = store.ObjectType;
pub const BlobAddress = store.BlobAddress;
pub const ChunkAddress = store.ChunkAddress;
pub const VersionAddress = store.VersionAddress;
pub const SignedMetadata = store.SignedMetadata;
pub const PutRequest = store.PutRequest;
pub const PutLocallySignedRequest = store.PutLocallySignedRequest;
pub const PutResult = store.PutResult;
pub const ObjectQuery = store.ObjectQuery;
pub const ObjectQueryResult = store.ObjectQueryResult;
pub const ObjectHistoryEntry = store.ObjectHistoryEntry;
pub const ObjectAccessModel = store.ObjectAccessModel;
pub const ObjectSyncPolicy = store.ObjectSyncPolicy;
pub const ObjectHistoryPolicy = store.ObjectHistoryPolicy;
pub const FileBridgePolicy = store.FileBridgePolicy;
pub const ObjectOperatingModel = store.ObjectOperatingModel;
pub const ObjectRecord = store.ObjectRecord;
pub const ObjectProvenance = store.ObjectProvenance;
pub const ObjectSharingPolicy = store.ObjectSharingPolicy;
pub const ObjectRecoveryHistory = store.ObjectRecoveryHistory;
pub const VersionRecord = store.VersionRecord;
pub const BlobChunkSlotIndex = store.BlobChunkSlotIndex;
pub const VersionBlobSlotIndex = store.VersionBlobSlotIndex;
pub const ChunkRef = store.ChunkRef;
pub const BlobRecord = store.BlobRecord;
pub const ChunkRecord = store.ChunkRecord;
pub const Error = store.Error;
pub const PayloadChunk = store.PayloadChunk;
pub const PayloadTransferSummary = store.PayloadTransferSummary;
pub const SignMetadataError = store.SignMetadataError;
pub const PutLocallySignedError = store.PutLocallySignedError;
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
