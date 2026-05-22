use anyhow::{Context as _, bail};
use aya::{
    maps::RingBuf,
    programs::{UProbe, uprobe::UProbeScope},
};
use clap::Parser;
use log::{debug, warn};
use std::io::Write as _;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use tls_uprobe_common::{
    TLS_OP_GO_READ, TLS_OP_GO_WRITE, TLS_OP_READ, TLS_OP_READ_EX, TLS_OP_WRITE, TLS_OP_WRITE_EX,
    TlsEvent,
};
use tokio::signal::{
    self,
    unix::{SignalKind, signal as unix_signal},
};

#[derive(Debug, Parser)]
struct Opt {
    /// Target process id. Repeat or comma-separate to attach to multiple processes.
    #[clap(long, default_value = "")]
    pid: Vec<String>,

    /// Path to libssl.so. If omitted with --pid, the loader resolves libssl from /proc/<pid>/maps.
    #[clap(long)]
    libssl: Option<PathBuf>,

    /// Go TLS target process id. Repeat or comma-separate to attach to multiple Go processes.
    #[clap(long, default_value = "")]
    go_pid: Vec<String>,

    /// Path to a Go binary with crypto/tls symbols. If omitted with --go-pid, resolved from /proc/<pid>/exe.
    #[clap(long)]
    go_binary: Option<PathBuf>,

    /// Experimental: also attach Go TLS Read with a uretprobe. This can crash Go programs during stack growth.
    #[clap(long)]
    go_capture_reads: bool,

    /// Output CSV path.
    #[clap(short, long, default_value = "tls_uprobe_output.csv")]
    output: PathBuf,

    /// Do not print captured events to stdout.
    #[clap(long)]
    quiet: bool,
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn csv_escape(value: &str) -> String {
    value.replace('"', "\"\"")
}

fn parse_pid_list(values: Vec<String>) -> Vec<u32> {
    values
        .into_iter()
        .flat_map(|value| {
            value
                .split(',')
                .filter_map(|part| part.trim().parse::<u32>().ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn comm_to_string(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).to_string()
}

fn op_name(op: u8) -> &'static str {
    match op {
        TLS_OP_READ => "SSL_read",
        TLS_OP_WRITE => "SSL_write",
        TLS_OP_READ_EX => "SSL_read_ex",
        TLS_OP_WRITE_EX => "SSL_write_ex",
        TLS_OP_GO_READ => "go_tls_read",
        TLS_OP_GO_WRITE => "go_tls_write",
        _ => "unknown",
    }
}

fn op_direction(op: u8) -> &'static str {
    match op {
        TLS_OP_READ | TLS_OP_READ_EX | TLS_OP_GO_READ => "READ",
        TLS_OP_WRITE | TLS_OP_WRITE_EX | TLS_OP_GO_WRITE => "WRITE",
        _ => "UNKNOWN",
    }
}

fn resolve_libssl_for_pid(pid: u32) -> anyhow::Result<PathBuf> {
    let maps_path = format!("/proc/{pid}/maps");
    let maps = std::fs::read_to_string(&maps_path)
        .with_context(|| format!("failed to read {maps_path}"))?;

    for line in maps.lines() {
        if !line.contains("libssl.so") {
            continue;
        }
        let Some(path) = line.split_whitespace().last() else {
            continue;
        };
        let path = path.trim_end_matches(" (deleted)");
        if !path.starts_with('/') {
            continue;
        }

        let proc_root_path = PathBuf::from(format!("/proc/{pid}/root{path}"));
        if proc_root_path.exists() {
            return Ok(proc_root_path);
        }

        let host_path = PathBuf::from(path);
        if host_path.exists() {
            return Ok(host_path);
        }
    }

    bail!("could not find libssl.so in /proc/{pid}/maps")
}

fn resolve_exe_for_pid(pid: u32) -> anyhow::Result<PathBuf> {
    let exe_link = PathBuf::from(format!("/proc/{pid}/exe"));
    let exe = std::fs::read_link(&exe_link)
        .with_context(|| format!("failed to resolve {}", exe_link.display()))?;

    if exe.is_absolute() {
        if let Ok(stripped) = exe.strip_prefix("/") {
            let proc_root_path = PathBuf::from(format!("/proc/{pid}/root")).join(stripped);
            if proc_root_path.exists() {
                return Ok(proc_root_path);
            }
        }
    }

    if exe.exists() {
        return Ok(exe);
    }

    Ok(exe_link)
}

fn load_program(ebpf: &mut aya::Ebpf, name: &str) -> anyhow::Result<()> {
    let program: &mut UProbe = ebpf
        .program_mut(name)
        .with_context(|| format!("missing eBPF program {name}"))?
        .try_into()?;
    program
        .load()
        .with_context(|| format!("failed to load eBPF program {name}"))?;
    Ok(())
}

fn attach_symbol(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    symbol: &str,
    target: &Path,
    pid: Option<u32>,
) -> anyhow::Result<()> {
    let program: &mut UProbe = ebpf
        .program_mut(program_name)
        .with_context(|| format!("missing eBPF program {program_name}"))?
        .try_into()?;
    let scope = match pid.and_then(NonZeroU32::new) {
        Some(pid) => UProbeScope::OneProcess(pid),
        None => UProbeScope::AllProcesses,
    };
    program.attach(symbol, target, scope).with_context(|| {
        format!(
            "failed to attach {program_name} to {symbol} in {} pid={pid:?}",
            target.display()
        )
    })?;
    Ok(())
}

fn attach_all(ebpf: &mut aya::Ebpf, target: &Path, pid: Option<u32>) -> anyhow::Result<usize> {
    let attach_points = [
        ("ssl_write", "SSL_write"),
        ("ssl_write_ex", "SSL_write_ex"),
        ("ssl_read_enter", "SSL_read"),
        ("ssl_read_exit", "SSL_read"),
        ("ssl_read_ex_enter", "SSL_read_ex"),
        ("ssl_read_ex_exit", "SSL_read_ex"),
    ];
    let mut attached = 0usize;
    for (program, symbol) in attach_points {
        match attach_symbol(ebpf, program, symbol, target, pid) {
            Ok(()) => {
                attached += 1;
                println!(
                    "Attached {program} -> {symbol} target={} pid={pid:?}",
                    target.display()
                );
            }
            Err(err) => {
                warn!("{err:#}");
            }
        }
    }
    Ok(attached)
}

fn attach_go_tls(
    ebpf: &mut aya::Ebpf,
    target: &Path,
    pid: Option<u32>,
    capture_reads: bool,
) -> anyhow::Result<usize> {
    let write_attach_points = [("go_tls_write", "crypto/tls.(*Conn).Write")];
    let read_attach_points = [
        ("go_tls_read_enter", "crypto/tls.(*Conn).Read"),
        ("go_tls_read_exit", "crypto/tls.(*Conn).Read"),
    ];
    let mut attached = 0usize;
    for (program, symbol) in write_attach_points {
        match attach_symbol(ebpf, program, symbol, target, pid) {
            Ok(()) => {
                attached += 1;
                println!(
                    "Attached {program} -> {symbol} target={} pid={pid:?}",
                    target.display()
                );
            }
            Err(err) => {
                warn!("{err:#}");
            }
        }
    }
    if capture_reads {
        for (program, symbol) in read_attach_points {
            match attach_symbol(ebpf, program, symbol, target, pid) {
                Ok(()) => {
                    attached += 1;
                    println!(
                        "Attached {program} -> {symbol} target={} pid={pid:?}",
                        target.display()
                    );
                }
                Err(err) => {
                    warn!("{err:#}");
                }
            }
        }
    }
    Ok(attached)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let pids = parse_pid_list(opt.pid);
    let go_pids = parse_pid_list(opt.go_pid);
    if pids.is_empty()
        && opt.libssl.is_none()
        && go_pids.is_empty()
        && opt.go_binary.is_none()
    {
        bail!(
            "provide --pid/--libssl for OpenSSL, or --go-pid/--go-binary for Go crypto/tls"
        );
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/tls_uprobe"
    )))?;

    for program in [
        "ssl_write",
        "ssl_write_ex",
        "ssl_read_enter",
        "ssl_read_exit",
        "ssl_read_ex_enter",
        "ssl_read_ex_exit",
        "go_tls_write",
        "go_tls_read_enter",
        "go_tls_read_exit",
    ] {
        load_program(&mut ebpf, program)?;
    }

    let mut attached = 0usize;
    if pids.is_empty() && opt.libssl.is_some() {
        let target = opt.libssl.as_deref().expect("checked above");
        attached += attach_all(&mut ebpf, target, None)?;
    } else if !pids.is_empty() {
        for pid in &pids {
            let target = match opt.libssl.as_ref() {
                Some(path) => path.clone(),
                None => resolve_libssl_for_pid(*pid)?,
            };
            attached += attach_all(&mut ebpf, &target, Some(*pid))?;
        }
    }
    if go_pids.is_empty() && opt.go_binary.is_some() {
        let target = opt.go_binary.as_deref().expect("checked above");
        attached += attach_go_tls(&mut ebpf, target, None, opt.go_capture_reads)?;
    } else if !go_pids.is_empty() {
        for pid in &go_pids {
            let target = match opt.go_binary.as_ref() {
                Some(path) => path.clone(),
                None => resolve_exe_for_pid(*pid)?,
            };
            attached += attach_go_tls(&mut ebpf, &target, Some(*pid), opt.go_capture_reads)?;
        }
    }
    if attached == 0 {
        bail!("no uprobes were attached");
    }

    let uptime = std::fs::read_to_string("/proc/uptime").unwrap_or_else(|_| "0.0".to_string());
    let uptime_sec: f64 = uptime
        .split_whitespace()
        .next()
        .unwrap_or("0.0")
        .parse()
        .unwrap_or(0.0);
    let boot_time =
        chrono::Local::now() - chrono::Duration::milliseconds((uptime_sec * 1000.0) as i64);

    let mut csv_writer = std::io::BufWriter::new(
        std::fs::File::create(&opt.output)
            .with_context(|| format!("failed to create {}", opt.output.display()))?,
    );
    writeln!(
        csv_writer,
        "type,timestamp,direction,pid,tid,comm,function,ssl,requested_len,payload_len,captured_len,payload"
    )?;

    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").context("missing EVENTS map")?)?;
    let mut async_fd =
        tokio::io::unix::AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;
    let mut sigterm = unix_signal(SignalKind::terminate())?;

    println!("Waiting for Ctrl-C...");
    loop {
        tokio::select! {
            readable = async_fd.readable_mut() => {
                let mut guard = readable?;
                let ring_buf = guard.get_inner_mut();
                while let Some(item) = ring_buf.next() {
                    let event = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const TlsEvent) };
                    let event_time = boot_time + chrono::Duration::nanoseconds(event.timestamp as i64);
                    let now = event_time.format("%Y-%m-%d %H:%M:%S%.6f");
                    let captured_len = event.captured_len.min(event.payload.len() as u32) as usize;
                    let payload = &event.payload[..captured_len];
                    let payload_hex = hex_encode(payload);
                    let comm = comm_to_string(&event.comm);
                    let function = op_name(event.op);
                    let direction = op_direction(event.op);

                    writeln!(
                        csv_writer,
                        "TLS_PLAINTEXT,{},{},{},{},\"{}\",{},0x{:x},{},{},{},\"{}\"",
                        now,
                        direction,
                        event.pid,
                        event.tid,
                        csv_escape(&comm),
                        function,
                        event.ssl,
                        event.requested_len,
                        event.payload_len,
                        event.captured_len,
                        payload_hex
                    ).ok();

                    if !opt.quiet {
                        println!(
                            "[TLS] [{}] {} pid={} tid={} comm={} ssl=0x{:x} captured={} payload_len={}",
                            now,
                            function,
                            event.pid,
                            event.tid,
                            comm,
                            event.ssl,
                            event.captured_len,
                            event.payload_len
                        );
                    }
                }
                guard.clear_ready();
            }
            _ = signal::ctrl_c() => {
                break;
            }
            _ = sigterm.recv() => {
                break;
            }
        }
    }

    csv_writer.flush().ok();
    println!("Exiting. Wrote {}", opt.output.display());
    Ok(())
}
