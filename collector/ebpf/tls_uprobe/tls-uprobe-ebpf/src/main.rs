#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user,
        bpf_probe_read_user_buf,
    },
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use tls_uprobe_common::{
    ReadArgs, ReadExArgs, TLS_OP_GO_READ, TLS_OP_GO_WRITE, TLS_OP_READ, TLS_OP_READ_EX,
    TLS_OP_WRITE, TLS_OP_WRITE_EX, TLS_PAYLOAD_CAP, TlsEvent,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

#[map]
static READ_ARGS: HashMap<u64, ReadArgs> = HashMap::with_max_entries(16384, 0);

#[map]
static READ_EX_ARGS: HashMap<u64, ReadExArgs> = HashMap::with_max_entries(16384, 0);

#[uprobe]
pub fn ssl_write(ctx: ProbeContext) -> u32 {
    match try_ssl_write(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uprobe]
pub fn ssl_write_ex(ctx: ProbeContext) -> u32 {
    match try_ssl_write_ex(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uprobe]
pub fn ssl_read_enter(ctx: ProbeContext) -> u32 {
    match try_ssl_read_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uretprobe]
pub fn ssl_read_exit(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uprobe]
pub fn ssl_read_ex_enter(ctx: ProbeContext) -> u32 {
    match try_ssl_read_ex_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uretprobe]
pub fn ssl_read_ex_exit(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_ex_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uprobe]
pub fn go_tls_write(ctx: ProbeContext) -> u32 {
    match try_go_tls_write(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uprobe]
pub fn go_tls_read_enter(ctx: ProbeContext) -> u32 {
    match try_go_tls_read_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uretprobe]
pub fn go_tls_read_exit(ctx: RetProbeContext) -> u32 {
    match try_go_tls_read_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
fn try_ssl_write(ctx: ProbeContext) -> Result<u32, u32> {
    let ssl = ctx.arg::<u64>(0).ok_or(1u32)?;
    let buf = ctx.arg::<*const u8>(1).ok_or(1u32)?;
    let len = ctx.arg::<u64>(2).ok_or(1u32)?;
    emit_tls_event(TLS_OP_WRITE, ssl, buf, len, len)?;
    Ok(0)
}

#[inline(always)]
fn try_ssl_write_ex(ctx: ProbeContext) -> Result<u32, u32> {
    let ssl = ctx.arg::<u64>(0).ok_or(1u32)?;
    let buf = ctx.arg::<*const u8>(1).ok_or(1u32)?;
    let len = ctx.arg::<u64>(2).ok_or(1u32)?;
    emit_tls_event(TLS_OP_WRITE_EX, ssl, buf, len, len)?;
    Ok(0)
}

#[inline(always)]
fn try_ssl_read_enter(ctx: ProbeContext) -> Result<u32, u32> {
    let ssl = ctx.arg::<u64>(0).ok_or(1u32)?;
    let buf = ctx.arg::<u64>(1).ok_or(1u32)?;
    let requested_len = ctx.arg::<u64>(2).ok_or(1u32)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let args = ReadArgs {
        ssl,
        buf,
        requested_len,
    };
    let _ = READ_ARGS.insert(pid_tgid, args, 0);
    Ok(0)
}

#[inline(always)]
fn try_ssl_read_exit(ctx: RetProbeContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ret = ctx.ret::<i64>();
    if ret <= 0 {
        let _ = READ_ARGS.remove(pid_tgid);
        return Ok(0);
    }
    if let Some(args) = unsafe { READ_ARGS.get(pid_tgid) } {
        emit_tls_event(
            TLS_OP_READ,
            args.ssl,
            args.buf as *const u8,
            args.requested_len,
            ret as u64,
        )?;
    }
    let _ = READ_ARGS.remove(pid_tgid);
    Ok(0)
}

#[inline(always)]
fn try_ssl_read_ex_enter(ctx: ProbeContext) -> Result<u32, u32> {
    let ssl = ctx.arg::<u64>(0).ok_or(1u32)?;
    let buf = ctx.arg::<u64>(1).ok_or(1u32)?;
    let requested_len = ctx.arg::<u64>(2).ok_or(1u32)?;
    let out_len_ptr = ctx.arg::<u64>(3).ok_or(1u32)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let args = ReadExArgs {
        ssl,
        buf,
        requested_len,
        out_len_ptr,
    };
    let _ = READ_EX_ARGS.insert(pid_tgid, args, 0);
    Ok(0)
}

#[inline(always)]
fn try_ssl_read_ex_exit(ctx: RetProbeContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ret = ctx.ret::<i64>();
    if ret != 1 {
        let _ = READ_EX_ARGS.remove(pid_tgid);
        return Ok(0);
    }
    if let Some(args) = unsafe { READ_EX_ARGS.get(pid_tgid) } {
        let out_len = unsafe { bpf_probe_read_user(args.out_len_ptr as *const u64) }.unwrap_or(0);
        if out_len > 0 {
            emit_tls_event(
                TLS_OP_READ_EX,
                args.ssl,
                args.buf as *const u8,
                args.requested_len,
                out_len,
            )?;
        }
    }
    let _ = READ_EX_ARGS.remove(pid_tgid);
    Ok(0)
}

#[inline(always)]
fn try_go_tls_write(ctx: ProbeContext) -> Result<u32, u32> {
    // Go 1.17+ on amd64 uses ABIInternal. For:
    // crypto/tls.(*Conn).Write(b []byte), receiver is AX, slice ptr is BX, len is CX.
    let conn = go_reg_ax(&ctx);
    let buf = go_reg_bx(&ctx) as *const u8;
    let len = go_reg_cx(&ctx);
    emit_tls_event(TLS_OP_GO_WRITE, conn, buf, len, len)?;
    Ok(0)
}

#[inline(always)]
fn try_go_tls_read_enter(ctx: ProbeContext) -> Result<u32, u32> {
    // crypto/tls.(*Conn).Read(b []byte): receiver AX, slice ptr BX, len CX.
    let conn = go_reg_ax(&ctx);
    let buf = go_reg_bx(&ctx);
    let requested_len = go_reg_cx(&ctx);
    let pid_tgid = bpf_get_current_pid_tgid();
    let args = ReadArgs {
        ssl: conn,
        buf,
        requested_len,
    };
    let _ = READ_ARGS.insert(pid_tgid, args, 0);
    Ok(0)
}

#[inline(always)]
fn try_go_tls_read_exit(ctx: RetProbeContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ret = go_ret_ax(&ctx);
    if ret <= 0 {
        let _ = READ_ARGS.remove(pid_tgid);
        return Ok(0);
    }
    if let Some(args) = unsafe { READ_ARGS.get(pid_tgid) } {
        emit_tls_event(
            TLS_OP_GO_READ,
            args.ssl,
            args.buf as *const u8,
            args.requested_len,
            ret as u64,
        )?;
    }
    let _ = READ_ARGS.remove(pid_tgid);
    Ok(0)
}

#[cfg(bpf_target_arch = "x86_64")]
#[inline(always)]
fn go_reg_ax(ctx: &ProbeContext) -> u64 {
    unsafe { (*ctx.regs).rax as u64 }
}

#[cfg(bpf_target_arch = "x86_64")]
#[inline(always)]
fn go_reg_bx(ctx: &ProbeContext) -> u64 {
    unsafe { (*ctx.regs).rbx as u64 }
}

#[cfg(bpf_target_arch = "x86_64")]
#[inline(always)]
fn go_reg_cx(ctx: &ProbeContext) -> u64 {
    unsafe { (*ctx.regs).rcx as u64 }
}

#[cfg(bpf_target_arch = "x86_64")]
#[inline(always)]
fn go_ret_ax(ctx: &RetProbeContext) -> i64 {
    unsafe { (*ctx.regs).rax as i64 }
}

#[inline(always)]
fn emit_tls_event(
    op: u8,
    ssl: u64,
    buf: *const u8,
    requested_len: u64,
    payload_len: u64,
) -> Result<(), u32> {
    if buf.is_null() || payload_len == 0 {
        return Ok(());
    }

    let mut cap = payload_len as usize;
    if cap > TLS_PAYLOAD_CAP {
        cap = TLS_PAYLOAD_CAP;
    }

    if let Some(mut event) = EVENTS.reserve::<TlsEvent>(0) {
        let event_ptr = event.as_mut_ptr() as *mut TlsEvent;
        let pid_tgid = bpf_get_current_pid_tgid();
        unsafe {
            (*event_ptr).timestamp = bpf_ktime_get_ns();
            (*event_ptr).pid = (pid_tgid >> 32) as u32;
            (*event_ptr).tid = pid_tgid as u32;
            (*event_ptr).op = op;
            (*event_ptr).ssl = ssl;
            (*event_ptr).requested_len = requested_len;
            (*event_ptr).payload_len = payload_len as u32;
            (*event_ptr).captured_len = cap as u32;
            (*event_ptr).comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
        }

        let dst = unsafe { &mut (*event_ptr).payload };
        if let Some(slice) = dst.get_mut(..cap) {
            let _ = unsafe { bpf_probe_read_user_buf(buf, slice) };
        }

        event.submit(0);
    }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
