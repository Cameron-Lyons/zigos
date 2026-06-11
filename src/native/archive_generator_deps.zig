const elf_image_inspector = @import("task/elf_image_inspector.zig");
const signing = @import("core/signing.zig");

pub const Inspection = elf_image_inspector.Inspection;
pub const inspect = elf_image_inspector.inspect;

pub const SIGNATURE_FORMAT_ED25519 = signing.SIGNATURE_FORMAT_ED25519;
pub const SIGNATURE_FORMAT_ED25519_ML_DSA65 = signing.SIGNATURE_FORMAT_ED25519_ML_DSA65;
pub const SIGNATURE_FORMAT_ML_DSA65 = signing.SIGNATURE_FORMAT_ML_DSA65;
pub const ED25519_PUBLIC_KEY_BYTES = signing.ED25519_PUBLIC_KEY_BYTES;
pub const ED25519_SIGNATURE_BYTES = signing.ED25519_SIGNATURE_BYTES;
pub const SignerIdentity = signing.SignerIdentity;
pub const signWithDefaultRegistry = signing.signWithDefaultRegistry;
