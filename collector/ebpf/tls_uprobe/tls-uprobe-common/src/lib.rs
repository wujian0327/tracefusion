#![no_std]

pub const TLS_PAYLOAD_CAP: usize = 4096;
pub const TLS_OP_READ: u8 = 0;
pub const TLS_OP_WRITE: u8 = 1;
pub const TLS_OP_READ_EX: u8 = 2;
pub const TLS_OP_WRITE_EX: u8 = 3;
pub const TLS_OP_GO_READ: u8 = 4;
pub const TLS_OP_GO_WRITE: u8 = 5;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub op: u8,
    pub _pad: [u8; 7],
    pub ssl: u64,
    pub requested_len: u64,
    pub payload_len: u32,
    pub captured_len: u32,
    pub comm: [u8; 16],
    pub payload: [u8; TLS_PAYLOAD_CAP],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReadArgs {
    pub ssl: u64,
    pub buf: u64,
    pub requested_len: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReadExArgs {
    pub ssl: u64,
    pub buf: u64,
    pub requested_len: u64,
    pub out_len_ptr: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TlsEvent {}
