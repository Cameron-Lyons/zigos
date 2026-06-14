pub const bytes_per_kib = 1024;
pub const bytes_per_mib = bytes_per_kib * bytes_per_kib;
pub const bytes_per_gib = bytes_per_kib * bytes_per_mib;

pub fn kibibytes(comptime amount: comptime_int) comptime_int {
    return amount * bytes_per_kib;
}

pub fn mebibytes(comptime amount: comptime_int) comptime_int {
    return amount * bytes_per_mib;
}

pub fn gibibytes(comptime amount: comptime_int) comptime_int {
    return amount * bytes_per_gib;
}
