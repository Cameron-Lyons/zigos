pub const Error = error{
    ChecksumMismatch,
    CorruptImage,
    ImageTooSmall,
    InvalidSignatureEncoding,
    MissingCheckpoint,
    NoSpaceLeft,
    UnsupportedVersion,
};
