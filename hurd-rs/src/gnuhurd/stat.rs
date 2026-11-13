type mode_t = libc::mode_t;

pub const S_IFBLK:  mode_t = 24576;
pub const S_IFLNK:  mode_t = 40960;
pub const S_IFIFO:  mode_t = 4096;
pub const S_IFSOCK: mode_t = 49152;

pub const S_IRWXU: mode_t = 448;
pub const S_IRWXG: mode_t = 56;
pub const S_IRWXO: mode_t = 7;

pub const ALLPERMS: mode_t = 4095;
pub const S_IFMT: mode_t = 61440;
pub const S_IFCHR: mode_t = 8192;
pub const S_IRUSR: mode_t = 256;
pub const S_IWUSR: mode_t = 128;
pub const S_IRGRP: mode_t = 32;
pub const S_IWGRP: mode_t = 16;
pub const S_IROTH: mode_t = 4;
pub const S_IWOTH: mode_t = 2;
pub const S_IFREG: mode_t = 32768;  // 0o100000
pub const S_IFDIR: mode_t = 16384;  // 0o040000
pub const S_IXUSR: mode_t = 64;     // 0o0100
pub const S_IXGRP: mode_t = 8;      // 0o0010
pub const S_IXOTH: mode_t = 1;      // 0o0001