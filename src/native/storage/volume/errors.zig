pub const Error = error{
    ChecksumMismatch,
    CorruptImage,
    DurabilityBarrierFailed,
    ImageTooSmall,
    InvalidSignatureEncoding,
    MissingCheckpoint,
    NoSpaceLeft,
    UnsupportedVersion,
};
