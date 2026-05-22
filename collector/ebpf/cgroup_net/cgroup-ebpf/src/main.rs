#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    macros::{cgroup_skb, map},
    maps::{Array, RingBuf},
    programs::SkBuffContext,
};
use cgroup_common::PacketLog;
use network_types::{
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

// 扩大为 16MB 的缓冲
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

// 用于记录丢包次数 (只有一个元素，索引为 0)
#[map]
static DROP_COUNT: Array<u32> = Array::with_max_entries(1, 0);

// Optional destination/source port allowlist. When PORT_FILTER_COUNT is zero,
// all TCP payloads are captured. Otherwise, only packets whose src or dst port
// appears in PORT_FILTERS are emitted to user space.
#[map]
static PORT_FILTERS: Array<u16> = Array::with_max_entries(64, 0);

#[map]
static PORT_FILTER_COUNT: Array<u32> = Array::with_max_entries(1, 0);

#[cgroup_skb]
pub fn cgroup_egress(ctx: SkBuffContext) -> i32 {
    let _ = try_cgroup(ctx, 0); // 0 = Egress
    1
}

#[cgroup_skb]
pub fn cgroup_ingress(ctx: SkBuffContext) -> i32 {
    let _ = try_cgroup(ctx, 1); // 1 = Ingress
    1
}

#[inline(always)]
fn try_cgroup(ctx: SkBuffContext, dir: u8) -> Result<i32, i32> {
    let ipv4hdr_len = core::mem::size_of::<Ipv4Hdr>();

    let ipv4_hdr = ctx.load::<Ipv4Hdr>(0).map_err(|_| 1)?;

    if ipv4_hdr.proto != IpProto::Tcp {
        return Ok(1);
    }

    let tcp_hdr = ctx.load::<TcpHdr>(ipv4hdr_len).map_err(|_| 1)?;
    let tcphdr_len = (tcp_hdr.doff() as usize) * 4;
    let src_port = u16::from_be_bytes(tcp_hdr.source);
    let dst_port = u16::from_be_bytes(tcp_hdr.dest);

    if let Some(count_ref) = PORT_FILTER_COUNT.get(0) {
        let count = *count_ref;
        if count > 0 {
            let mut matched = false;
            let max_count = if count > 64 { 64 } else { count };
            for idx in 0..64 {
                if idx >= max_count {
                    break;
                }
                if let Some(port_ref) = PORT_FILTERS.get(idx) {
                    let port = *port_ref;
                    if port == src_port || port == dst_port {
                        matched = true;
                        break;
                    }
                }
            }
            if !matched {
                return Ok(1);
            }
        }
    }

    let payload_offset = ipv4hdr_len + tcphdr_len;
    let total_len = ctx.len() as usize;

    if total_len <= payload_offset {
        return Ok(1);
    }

    let payload_len = total_len - payload_offset;

    // 尝试在 RingBuf 申请空间
    if let Some(mut event) = EVENTS.reserve::<PacketLog>(0) {
        let log_ptr = event.as_mut_ptr() as *mut PacketLog;
        unsafe {
            (*log_ptr).timestamp = aya_ebpf::helpers::bpf_ktime_get_ns();
            (*log_ptr).sock_cookie =
                aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr() as *mut _);
            (*log_ptr).dir = dir;
            (*log_ptr).src_addr = u32::from_be_bytes(ipv4_hdr.src_addr);
            (*log_ptr).dst_addr = u32::from_be_bytes(ipv4_hdr.dst_addr);
            (*log_ptr).src_port = src_port;
            (*log_ptr).dst_port = dst_port;
            (*log_ptr).payload_len = payload_len as u32;
            (*log_ptr).tcp_seq = u32::from_be_bytes(tcp_hdr.seq);
        }

        let mut limit = payload_len;
        if limit > 0 {
            if limit > 2048 {
                limit = 2048;
            }

            // Fallback to iterating for BPF Verifier safety since bpf_skb_load_bytes variable length can fail checks.
            for i in 0..2048 {
                if i >= limit {
                    break;
                }
                if let Ok(b) = ctx.load::<u8>(payload_offset + i) {
                    unsafe {
                        (*log_ptr).payload[i] = b;
                    }
                } else {
                    break;
                }
            }
        }

        event.submit(0);
    } else {
        // 如果 RingBuf 已满或申请失败，记录一次 Drop
        if let Some(counter) = DROP_COUNT.get_ptr_mut(0) {
            unsafe {
                let val = core::ptr::read_volatile(counter);
                core::ptr::write_volatile(counter, val + 1);
            }
        }
    }

    Ok(1)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
