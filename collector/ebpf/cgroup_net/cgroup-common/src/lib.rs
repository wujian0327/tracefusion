#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub timestamp: u64,   // eBPF ktime_get_ns() 捕获时间
    pub dir: u8,          // 0 = Egress, 1 = Ingress
    pub _pad: [u8; 7],    // padding 到 8字节对齐
    pub sock_cookie: u64, // socket的唯一标识
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_len: u32,
    pub payload: [u8; 2048], // 抓取前2048字节
    pub tcp_seq: u32,        // TCP Sequence Number
    pub _pad2: u32,          // 确保总大小为8的倍数
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
