pub const Error = error{
    VolumeOperationBusy,
    VolumeGenerationExhausted,
    DeviceReadFailed,
    StorageMutationDuringLoad,
    ChecksumMismatch,
    CorruptImage,
    DurabilityBarrierFailed,
    ImageTooSmall,
    InvalidSignatureEncoding,
    MissingCheckpoint,
    NoSpaceLeft,
    UnsupportedVersion,
};
