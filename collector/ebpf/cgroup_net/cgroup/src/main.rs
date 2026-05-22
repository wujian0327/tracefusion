use anyhow::Context as _;
use aya::{
    maps::RingBuf,
    programs::{CgroupSkb, CgroupSkbAttachType, links::CgroupAttachMode},
};
use cgroup_common::PacketLog;
use clap::{Parser, ValueEnum};
#[rustfmt::skip]
use log::{debug};
use std::io::Write as _;
use std::net::Ipv4Addr;
use tokio::signal;

const RAW_MAGIC: &[u8; 8] = b"TFEBPF1\0";
const RAW_VERSION: u16 = 1;
const RAW_RECORD_HEADER_LEN: u16 = 42;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ProtocolFilter {
    All,
    Http1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Raw,
    Csv,
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

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup")]
    cgroup_path: std::path::PathBuf,

    #[clap(short, long, default_value = "output.csv")]
    output: std::path::PathBuf,

    /// Collector output format. raw writes a compact binary event stream and
    /// avoids per-packet hex/text CSV encoding on the capture path.
    #[clap(long, value_enum, default_value_t = OutputFormat::Raw)]
    output_format: OutputFormat,

    /// Optional target IP to filter. If provided, e.g. "172.17.0.1",
    /// only traffic between this IP and any other IP, or within this IP, will be logged.
    /// Can be provided multiple times for multiple IPs, e.g. -i 1.1.1.1 -i 2.2.2.2.
    /// Only traffic where BOTH src_ip and dst_ip are in this list will be logged.
    #[clap(short, long, default_value = "")]
    ip: Vec<String>,

    /// Optional target ports to exclude.
    /// If traffic's src_port or dst_port matches these, it will NOT be logged.
    /// Supports comma-separated ports, e.g., -p 8000,9000 or -p 8000 -p 9000
    #[clap(long, default_value = "14250,16686")]
    ignored_port: Vec<String>,

    /// Optional target ports to capture.
    /// When provided, only traffic whose src_port or dst_port matches these
    /// ports is copied from eBPF to user space. Supports comma-separated ports,
    /// e.g., --port 9080,27017 or --port 9080 --port 27017.
    #[clap(long, default_value = "")]
    port: Vec<String>,

    /// Capture mode hint retained for script compatibility. The collector
    /// always writes raw TCP payload events; protocol parsing happens offline.
    #[clap(long, value_enum, default_value_t = ProtocolFilter::All)]
    protocol: ProtocolFilter,

    /// Do not print per-packet metadata to stdout. The capture output is unaffected.
    #[clap(long)]
    quiet: bool,
}

fn write_raw_header<W: std::io::Write>(
    writer: &mut W,
    boot_time_unix_ns: i64,
) -> std::io::Result<()> {
    writer.write_all(RAW_MAGIC)?;
    writer.write_all(&RAW_VERSION.to_le_bytes())?;
    writer.write_all(&RAW_RECORD_HEADER_LEN.to_le_bytes())?;
    writer.write_all(&boot_time_unix_ns.to_le_bytes())?;
    writer.write_all(&0u64.to_le_bytes())?;
    Ok(())
}

fn write_raw_record<W: std::io::Write>(
    writer: &mut W,
    log: &PacketLog,
    captured_payload: &[u8],
) -> std::io::Result<()> {
    let captured_len = captured_payload.len().min(u16::MAX as usize) as u16;
    writer.write_all(&log.timestamp.to_le_bytes())?;
    writer.write_all(&[log.dir])?;
    writer.write_all(&[0u8])?;
    writer.write_all(&log.src_addr.to_le_bytes())?;
    writer.write_all(&log.dst_addr.to_le_bytes())?;
    writer.write_all(&log.src_port.to_le_bytes())?;
    writer.write_all(&log.dst_port.to_le_bytes())?;
    writer.write_all(&log.payload_len.to_le_bytes())?;
    writer.write_all(&captured_len.to_le_bytes())?;
    writer.write_all(&0u16.to_le_bytes())?;
    writer.write_all(&log.tcp_seq.to_le_bytes())?;
    writer.write_all(&log.sock_cookie.to_le_bytes())?;
    writer.write_all(&captured_payload[..captured_len as usize])?;
    Ok(())
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

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/cgroup"
    )))?;

    let Opt {
        cgroup_path,
        output,
        output_format,
        ip: raw_ip_filters,
        ignored_port: raw_port_filters,
        port: raw_port_filters_allow,
        protocol: _protocol,
        quiet,
    } = opt;

    // 解析包含逗号分隔的 IP，例如：-i "1.1.1.1,2.2.2.2" 或者 -i 1.1.1.1 -i 2.2.2.2
    let ip_filters: Vec<String> = raw_ip_filters
        .into_iter()
        .flat_map(|s| {
            s.split(',')
                .map(|ip| ip.trim().to_string())
                .collect::<Vec<_>>()
        })
        .filter(|s| !s.is_empty())
        .collect();

    // 解析需要排除的端口
    let ignored_ports: Vec<u16> = raw_port_filters
        .into_iter()
        .flat_map(|s| {
            s.split(',')
                .filter_map(|p| p.trim().parse::<u16>().ok())
                .collect::<Vec<_>>()
        })
        .collect();

    let port_filters: Vec<u16> = raw_port_filters_allow
        .into_iter()
        .flat_map(|s| {
            s.split(',')
                .filter_map(|p| p.trim().parse::<u16>().ok())
                .collect::<Vec<_>>()
        })
        .take(64)
        .collect();

    if !port_filters.is_empty() {
        let mut port_map =
            aya::maps::Array::<_, u16>::try_from(ebpf.map_mut("PORT_FILTERS").unwrap())?;
        for (idx, port) in port_filters.iter().enumerate() {
            port_map.set(idx as u32, *port, 0)?;
        }
        let mut count_map =
            aya::maps::Array::<_, u32>::try_from(ebpf.map_mut("PORT_FILTER_COUNT").unwrap())?;
        count_map.set(0, port_filters.len() as u32, 0)?;
    }

    let mut output_writer = std::io::BufWriter::new(
        std::fs::File::create(&output)
            .with_context(|| format!("Failed to create {}", output.display()))?,
    );
    if output_format == OutputFormat::Csv {
        writeln!(
            output_writer,
            "type,timestamp,direction,src_ip,src_port,dst_ip,dst_port,tcp_seq,payload_len,sock_cookie,payload"
        )?;
    }

    let prog1_name = "cgroup_egress";
    let prog2_name = "cgroup_ingress";

    {
        let prog: &mut CgroupSkb = ebpf.program_mut(prog1_name).unwrap().try_into()?;
        prog.load()?;
    }
    {
        let prog: &mut CgroupSkb = ebpf.program_mut(prog2_name).unwrap().try_into()?;
        prog.load()?;
    }

    if cgroup_path.display().to_string() == "/sys/fs/cgroup" {
        let system_slice = std::path::Path::new("/sys/fs/cgroup/system.slice");
        if system_slice.exists() {
            for entry in std::fs::read_dir(system_slice)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir()
                    && path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .starts_with("docker-")
                {
                    println!("Attaching to Docker cgroup: {}", path.display());
                    let cgroup_file = std::fs::File::open(&path)
                        .with_context(|| format!("Failed to open {}", path.display()))?;
                    let fd = cgroup_file.try_clone()?;
                    let prog_egress: &mut CgroupSkb =
                        ebpf.program_mut("cgroup_egress").unwrap().try_into()?;
                    prog_egress.attach(
                        cgroup_file,
                        CgroupSkbAttachType::Egress,
                        CgroupAttachMode::default(),
                    )?;
                    let prog_ingress: &mut CgroupSkb =
                        ebpf.program_mut("cgroup_ingress").unwrap().try_into()?;
                    prog_ingress.attach(
                        fd,
                        CgroupSkbAttachType::Ingress,
                        CgroupAttachMode::default(),
                    )?;
                }
            }
        }
    } else {
        let cgroup = std::fs::File::open(&cgroup_path)
            .with_context(|| format!("{}", cgroup_path.display()))?;
        let fd = cgroup.try_clone()?;
        let prog_egress: &mut CgroupSkb = ebpf.program_mut("cgroup_egress").unwrap().try_into()?;
        prog_egress.attach(
            cgroup,
            CgroupSkbAttachType::Egress,
            CgroupAttachMode::default(),
        )?;
        let prog_ingress: &mut CgroupSkb =
            ebpf.program_mut("cgroup_ingress").unwrap().try_into()?;
        prog_ingress.attach(
            fd,
            CgroupSkbAttachType::Ingress,
            CgroupAttachMode::default(),
        )?;
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
    if output_format == OutputFormat::Raw {
        let boot_time_unix_ns = boot_time.timestamp_nanos_opt().unwrap_or(0);
        write_raw_header(&mut output_writer, boot_time_unix_ns)?;
    }

    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let mut async_fd =
        tokio::io::unix::AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

    println!("Waiting for Ctrl-C...");
    loop {
        tokio::select! {
            readable = async_fd.readable_mut() => {
                let mut guard = readable?;
            let ring_buf = guard.get_inner_mut();
            while let Some(item) = ring_buf.next() {
                let log = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const PacketLog) };

                if !ip_filters.is_empty() {
                    let src_ip_str = Ipv4Addr::from(log.src_addr).to_string();
                    let dst_ip_str = Ipv4Addr::from(log.dst_addr).to_string();
                    if !ip_filters.contains(&src_ip_str) || !ip_filters.contains(&dst_ip_str) {
                        continue;
                    }
                }

                if !ignored_ports.is_empty() {
                    if ignored_ports.contains(&log.src_port)
                        || ignored_ports.contains(&log.dst_port)
                    {
                        continue;
                    }
                }

                let payload_len = log.payload_len as usize;
                let max_len = if payload_len > log.payload.len() {
                    log.payload.len()
                } else {
                    payload_len
                };

                if max_len > 0 {
                    let payload = &log.payload[..max_len];
                    if output_format == OutputFormat::Raw {
                        write_raw_record(&mut output_writer, &log, payload)?;
                    } else {
                        let src_ip = Ipv4Addr::from(log.src_addr);
                        let dst_ip = Ipv4Addr::from(log.dst_addr);
                        let event_time =
                            boot_time + chrono::Duration::nanoseconds(log.timestamp as i64);
                        let now = event_time.format("%Y-%m-%d %H:%M:%S%.6f"); // 精确到微秒
                        let dir_str = if log.dir == 0 { "OUT" } else { "IN" };
                        let payload_hex = hex_encode(payload);
                        writeln!(
                            output_writer,
                            "TCP,{},{},{},{},{},{},{},{},{},\"{}\"",
                            now,
                            dir_str,
                            src_ip,
                            log.src_port,
                            dst_ip,
                            log.dst_port,
                            log.tcp_seq,
                            payload_len,
                            log.sock_cookie,
                            payload_hex
                        )?;
                    }

                    if !quiet {
                        let src_ip = Ipv4Addr::from(log.src_addr);
                        let dst_ip = Ipv4Addr::from(log.dst_addr);
                        let event_time =
                            boot_time + chrono::Duration::nanoseconds(log.timestamp as i64);
                        let now = event_time.format("%Y-%m-%d %H:%M:%S%.6f"); // 精确到微秒
                        let dir_str = if log.dir == 0 { "OUT" } else { "IN" };
                        println!(
                            "\n[TCP] [{}] [{}] {}:{} -> {}:{} seq={} captured={} payload_len={}",
                            now,
                            dir_str,
                            src_ip,
                            log.src_port,
                            dst_ip,
                            log.dst_port,
                            log.tcp_seq,
                            max_len,
                            payload_len
                        );
                    }
                }
            }
            guard.clear_ready();
            }
            _ = signal::ctrl_c() => {
                break;
            }
        }
    }

    println!("Exiting...");
    output_writer.flush()?;

    // 读取所有的丢包计数
    if let Ok(drop_map) = aya::maps::Array::<_, u32>::try_from(ebpf.take_map("DROP_COUNT").unwrap())
    {
        if let Ok(drop_count) = drop_map.get(&0, 0) {
            println!("========================================================");
            if drop_count > 0 {
                println!("⚠️  WARNING: eBPF Buffer Overflow Detected!");
                println!("⚠️  Total Dropped Packets: {}", drop_count);
                println!("⚠️  Some requests/responses will be missing in output.csv");
            } else {
                println!("✅  SUCCESS: No packets were dropped by the eBPF Buffer.");
            }
            println!("========================================================");
        }
    }

    Ok(())
}
