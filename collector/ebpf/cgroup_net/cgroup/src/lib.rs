use hpack::Decoder;
use lazy_static::lazy_static;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ConnKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub dir: u8,
}

pub struct TcpStream {
    pub expected_seq: Option<u32>,
    pub buffer: Vec<u8>,
    pub out_of_order: std::collections::BTreeMap<u32, (Vec<u8>, u32)>,
    pub pending_hpack: std::collections::BTreeMap<u32, Vec<u8>>,
    pub is_broken: bool,
}

pub struct Http1Stream {
    pub expected_seq: Option<u32>,
    pub message_start_seq: Option<u32>,
    pub buffer: Vec<u8>,
    pub out_of_order: std::collections::BTreeMap<u32, (Vec<u8>, u32)>,
}

impl Http1Stream {
    pub fn new() -> Self {
        Self {
            expected_seq: None,
            message_start_seq: None,
            buffer: Vec::new(),
            out_of_order: std::collections::BTreeMap::new(),
        }
    }
}

impl TcpStream {
    pub fn new() -> Self {
        Self {
            expected_seq: None,
            buffer: Vec::new(),
            out_of_order: std::collections::BTreeMap::new(),
            pending_hpack: std::collections::BTreeMap::new(),
            is_broken: false,
        }
    }
}

lazy_static! {
    static ref HPACK_DYN_TABLES: Mutex<LruCache<ConnKey, Decoder<'static>>> =
        Mutex::new(LruCache::new(NonZeroUsize::new(4096).unwrap()));
    static ref TCP_STREAMS: Mutex<LruCache<ConnKey, TcpStream>> =
        Mutex::new(LruCache::new(NonZeroUsize::new(4096).unwrap()));
    static ref HTTP1_STREAMS: Mutex<LruCache<ConnKey, Http1Stream>> =
        Mutex::new(LruCache::new(NonZeroUsize::new(4096).unwrap()));
}

fn same_socket_pair(a: &ConnKey, b: &ConnKey) -> bool {
    (a.src_ip == b.src_ip
        && a.dst_ip == b.dst_ip
        && a.src_port == b.src_port
        && a.dst_port == b.dst_port)
        || (a.src_ip == b.dst_ip
            && a.dst_ip == b.src_ip
            && a.src_port == b.dst_port
            && a.dst_port == b.src_port)
}

fn reset_hpack_decoder(conn_key: &ConnKey) {
    let mut cache = HPACK_DYN_TABLES.lock().unwrap();
    if !cache.contains(conn_key) {
        cache.put(conn_key.clone(), Decoder::new());
    } else if let Some(decoder) = cache.get_mut(conn_key) {
        *decoder = Decoder::new();
    }
}

pub fn is_http(payload: &[u8]) -> bool {
    let s = String::from_utf8_lossy(payload);
    s.starts_with("GET ")
        || s.starts_with("POST ")
        || s.starts_with("PUT ")
        || s.starts_with("DELETE ")
        || s.starts_with("HTTP/")
}

pub fn format_http_payload(payload: &[u8]) -> String {
    let s = String::from_utf8_lossy(payload);
    let mut lines = s.lines();

    let mut json_str = String::from("{");
    let mut has_fields = false;

    // 解析第一行 (Request Line: "GET / HTTP/1.1" 或 Status Line: "HTTP/1.1 200 OK")
    if let Some(first_line) = lines.next() {
        let first_line = first_line.trim();
        if !first_line.is_empty() {
            if first_line.starts_with("HTTP/") {
                // Response Line: HTTP/1.1 200 OK
                let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
                if parts.len() >= 2 {
                    let status = parts[1].replace('"', "\\\"");
                    json_str.push_str(&format!("\"status\": \"{}\"", status));
                    has_fields = true;
                }
            } else {
                // Request Line: POST /path?a=1 HTTP/1.1
                let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
                if parts.len() >= 2 {
                    let method = parts[0].replace('"', "\\\"");
                    let full_url = parts[1];
                    let (url, paras) = if let Some((u, p)) = full_url.split_once('?') {
                        (u, p)
                    } else {
                        (full_url, "")
                    };
                    let esc_url = url.replace('"', "\\\"");
                    let esc_paras = paras.replace('"', "\\\"");

                    json_str.push_str(&format!(
                        "\"method\": \"{}\", \"url\": \"{}\", \"paras\": \"{}\"",
                        method, esc_url, esc_paras
                    ));
                    has_fields = true;
                }
            }
        }
    }

    // 解析 Headers (一直到第一个空行)
    let mut headers = vec![];
    for line in lines.by_ref() {
        let line = line.trim();
        if line.is_empty() {
            break; // 空行之后就是 Body
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        } else {
            // 有些奇怪的格式，直接当做 key，没有 value
            headers.push((line.to_string(), String::new()));
        }
    }

    if !headers.is_empty() {
        if has_fields {
            json_str.push_str(", ");
        }
        json_str.push_str("\"headers\": {");
        for (i, (k, v)) in headers.iter().enumerate() {
            if i > 0 {
                json_str.push_str(", ");
            }
            let esc_k = k.replace('\\', "\\\\").replace('"', "\\\"");
            let esc_v = v.replace('\\', "\\\\").replace('"', "\\\"");
            json_str.push_str(&format!("\"{}\": \"{}\"", esc_k, esc_v));
        }
        json_str.push('}');
        has_fields = true;
    }

    let header_text = headers
        .iter()
        .map(|(k, v)| format!("{}: {}", k, v))
        .collect::<Vec<_>>()
        .join("\n");
    if http_is_html_content(&header_text) {
        json_str.push('}');
        return json_str;
    }

    // 解析 Body (剩余的所有行合并)
    let body: String = lines.collect::<Vec<_>>().join("\n").trim().to_string();
    if !body.is_empty() {
        if has_fields {
            json_str.push_str(", ");
        }
        let esc_body = body
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t");
        json_str.push_str(&format!("\"body\": \"{}\"", esc_body));
    }

    json_str.push('}');
    json_str
}

fn find_http_header_end(buffer: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((pos, pos + 4));
    }
    if let Some(pos) = buffer.windows(2).position(|w| w == b"\n\n") {
        return Some((pos, pos + 2));
    }
    None
}

fn http_content_length(header_text: &str) -> Option<usize> {
    for line in header_text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            if let Ok(parsed) = value.trim().parse::<usize>() {
                return Some(parsed);
            }
        }
    }
    None
}

fn http_is_chunked(header_text: &str) -> bool {
    for line in header_text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            return true;
        }
    }
    false
}

fn http_is_html_content(header_text: &str) -> bool {
    for line in header_text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-type") {
            let content_type = value.trim().to_ascii_lowercase();
            return content_type.contains("text/html")
                || content_type.contains("application/xhtml");
        }
    }
    false
}

fn find_chunked_message_end(buffer: &[u8], body_start: usize) -> Option<usize> {
    let body = &buffer[body_start..];
    for marker in [b"\r\n0\r\n\r\n".as_slice(), b"\n0\n\n".as_slice()] {
        if let Some(pos) = body.windows(marker.len()).position(|w| w == marker) {
            return Some(body_start + pos + marker.len());
        }
    }
    None
}

fn take_complete_http1_message(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buffer.is_empty() {
        return None;
    }
    if !is_http(buffer) {
        buffer.clear();
        return None;
    }

    let (header_end, body_start) = find_http_header_end(buffer)?;
    let header_text = String::from_utf8_lossy(&buffer[..header_end]);
    let total_len = if http_is_html_content(&header_text) {
        body_start
    } else if let Some(content_length) = http_content_length(&header_text) {
        body_start + content_length
    } else if http_is_chunked(&header_text) {
        find_chunked_message_end(buffer, body_start)?
    } else {
        body_start
    };

    if buffer.len() < total_len {
        return None;
    }

    let message: Vec<u8> = buffer.drain(..total_len).collect();
    Some(message)
}

fn append_http1_payload(stream: &mut Http1Stream, tcp_seq: u32, payload: &[u8], payload_len: u32) {
    let captured_len = payload.len() as u32;
    let seq_advance = payload_len.max(captured_len);

    match stream.expected_seq {
        None => {
            if !is_http(payload) {
                return;
            }
            stream.buffer.clear();
            stream.out_of_order.clear();
            stream.buffer.extend_from_slice(payload);
            stream.expected_seq = Some(tcp_seq.wrapping_add(seq_advance));
            stream.message_start_seq = Some(tcp_seq);
        }
        Some(expected) => {
            if stream.buffer.is_empty() && is_http(payload) {
                stream.out_of_order.clear();
                stream.buffer.extend_from_slice(payload);
                stream.expected_seq = Some(tcp_seq.wrapping_add(seq_advance));
                stream.message_start_seq = Some(tcp_seq);
                return;
            }
            if tcp_seq == expected {
                if stream.buffer.is_empty() && is_http(payload) {
                    stream.message_start_seq = Some(tcp_seq);
                }
                stream.buffer.extend_from_slice(payload);
                stream.expected_seq = Some(expected.wrapping_add(seq_advance));
            } else if tcp_seq > expected {
                stream
                    .out_of_order
                    .insert(tcp_seq, (payload.to_vec(), seq_advance));
            } else if is_http(payload) {
                stream.buffer.clear();
                stream.out_of_order.clear();
                stream.buffer.extend_from_slice(payload);
                stream.expected_seq = Some(tcp_seq.wrapping_add(seq_advance));
                stream.message_start_seq = Some(tcp_seq);
            } else {
                let already_seen = expected.wrapping_sub(tcp_seq) as usize;
                if already_seen < payload.len() {
                    stream.buffer.extend_from_slice(&payload[already_seen..]);
                    stream.expected_seq = Some(expected.wrapping_add(seq_advance));
                }
            }
        }
    }

    loop {
        let Some(expected) = stream.expected_seq else {
            break;
        };
        let Some((chunk, chunk_len)) = stream.out_of_order.remove(&expected) else {
            break;
        };
        stream.buffer.extend_from_slice(&chunk);
        stream.expected_seq = Some(expected.wrapping_add(chunk_len));
    }
}

pub fn process_http1_stream(
    conn_key: &ConnKey,
    tcp_seq: u32,
    payload: &[u8],
    payload_len: u32,
) -> Vec<(u32, String)> {
    let mut streams = HTTP1_STREAMS.lock().unwrap();
    if !streams.contains(conn_key) {
        if !is_http(payload) {
            return Vec::new();
        }
        streams.put(conn_key.clone(), Http1Stream::new());
    }

    let Some(stream) = streams.get_mut(conn_key) else {
        return Vec::new();
    };
    append_http1_payload(stream, tcp_seq, payload, payload_len);

    let mut messages = Vec::new();
    while let Some(message) = take_complete_http1_message(&mut stream.buffer) {
        let start_seq = stream.message_start_seq.unwrap_or(tcp_seq);
        let next_start_seq = start_seq.wrapping_add(message.len() as u32);
        messages.push((start_seq, format_http_payload(&message)));
        stream.message_start_seq = if stream.buffer.is_empty() {
            None
        } else {
            Some(next_start_seq)
        };
    }
    messages
}

pub fn is_sql(payload: &[u8]) -> bool {
    // 粗略判断以明文 SELECT、UPDATE、INSERT、DELETE 开头
    // 实际 MySQL 等协议前面可能会有几个字节的 packet length 等 header，所以我们用 contains 宽泛匹配
    let s = String::from_utf8_lossy(payload).to_ascii_uppercase();
    s.contains("SELECT ")
        || s.contains("UPDATE ")
        || s.contains("INSERT ")
        || s.contains("DELETE FROM ")
}

pub fn strip_rn(payload: &[u8]) -> String {
    let s = String::from_utf8_lossy(payload);
    // 只取第一行打印，防止刷屏
    s.lines().next().unwrap_or("").trim().to_string()
}

/// Read a protobuf varint from `data[pos]`. Returns (value, new_pos).
fn read_varint(data: &[u8], mut pos: usize) -> (u64, usize) {
    let mut value = 0u64;
    let mut shift = 0u32;
    while pos < data.len() {
        let b = data[pos];
        pos += 1;
        value |= ((b & 0x7F) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            break;
        }
    }
    (value, pos)
}

/// Parse protobuf fields, append JSON-like representation to `out`.
fn parse_protobuf(data: &[u8], mut pos: usize, end: usize, out: &mut String, depth: usize) {
    out.push('{');
    let mut first = true;
    while pos < end {
        let (tag_wire, p) = read_varint(data, pos);
        if p == pos {
            break;
        }
        pos = p;
        let field_num = tag_wire >> 3;
        let wire_type = tag_wire & 0x7;
        if field_num == 0 {
            break;
        }

        if !first {
            out.push_str(", ");
        }
        first = false;
        out.push_str(&format!("\"{}\": ", field_num));

        match wire_type {
            0 => {
                // varint
                let (val, p) = read_varint(data, pos);
                pos = p;
                out.push_str(&val.to_string());
            }
            1 => {
                // 64-bit
                if pos + 8 <= data.len() {
                    let val = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap_or([0; 8]));
                    out.push_str(&val.to_string());
                    pos += 8;
                } else {
                    pos = end;
                }
            }
            2 => {
                // length-delimited
                let (len, p) = read_varint(data, pos);
                pos = p;
                let slice_end = (pos + len as usize).min(end).min(data.len());
                let slice = &data[pos..slice_end];
                // Try to display as UTF-8 string, otherwise recurse as embedded message
                if slice
                    .iter()
                    .all(|&b| b >= 32 || b == b'\n' || b == b'\r' || b == b'\t')
                    && !slice.is_empty()
                {
                    let s = String::from_utf8_lossy(slice);
                    let escaped = s
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"")
                        .replace('\n', "\\n")
                        .replace('\r', "\\r")
                        .replace('\t', "\\t");
                    out.push('"');
                    out.push_str(&escaped);
                    out.push('"');
                } else if depth > 0 && slice.len() >= 2 {
                    parse_protobuf(data, pos, slice_end, out, depth - 1);
                } else {
                    out.push_str(&format!("\"<{} bytes>\"", slice.len()));
                }
                pos = slice_end;
            }
            5 => {
                // 32-bit
                if pos + 4 <= data.len() {
                    let val = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap_or([0; 4]));
                    out.push_str(&val.to_string());
                    pos += 4;
                } else {
                    pos = end;
                }
            }
            _ => {
                // Unknown wire type, stop parsing
                break;
            }
        }
    }
    out.push('}');
}

pub fn format_grpc_payload(payload: &[u8], conn_key: &ConnKey) -> String {
    let mut pos = 0;
    let mut streams: Vec<(u32, String, Vec<String>)> = Vec::new();

    while pos + 9 <= payload.len() {
        let frame_len = ((payload[pos] as usize) << 16)
            | ((payload[pos + 1] as usize) << 8)
            | (payload[pos + 2] as usize);
        let frame_type = payload[pos + 3];
        let flags = payload[pos + 4];
        let stream_id = u32::from_be_bytes([
            payload[pos + 5],
            payload[pos + 6],
            payload[pos + 7],
            payload[pos + 8],
        ]) & 0x7FFFFFFF;

        let data_start = pos + 9;
        let data_end = (data_start + frame_len).min(payload.len());

        let stream_idx = if let Some(idx) = streams.iter().position(|(id, _, _)| *id == stream_id) {
            idx
        } else {
            streams.push((stream_id, String::new(), Vec::new()));
            streams.len() - 1
        };

        match frame_type {
            0 => {
                // DATA frame
                let mut current_p = data_start;
                while current_p + 5 <= data_end {
                    let grpc_message_len = ((payload[current_p + 1] as usize) << 24)
                        | ((payload[current_p + 2] as usize) << 16)
                        | ((payload[current_p + 3] as usize) << 8)
                        | (payload[current_p + 4] as usize);
                    let pb_start = current_p + 5;
                    let pb_end = (pb_start + grpc_message_len).min(data_end);
                    if pb_start < data_end {
                        let mut data_str = String::new();
                        parse_protobuf(payload, pb_start, pb_end, &mut data_str, 2);
                        streams[stream_idx].2.push(data_str);
                    }
                    current_p = pb_end;
                    if grpc_message_len == 0 {
                        break;
                    }
                }
            }
            1 => {
                // HEADERS frame
                let hpack_start = if flags & 0x08 != 0 && data_start < data_end {
                    data_start + 1
                } else {
                    data_start
                };
                let hpack_start = if flags & 0x20 != 0 && hpack_start + 5 <= data_end {
                    hpack_start + 5
                } else {
                    hpack_start
                };
                let mut hdrs = Vec::new();
                let mut cache = HPACK_DYN_TABLES.lock().unwrap();
                if !cache.contains(conn_key) {
                    cache.put(conn_key.clone(), Decoder::new());
                }
                let dyn_table = cache.get_mut(conn_key).unwrap();
                let hpack_data = &payload[hpack_start..data_end];
                match dyn_table.decode(hpack_data) {
                    Ok(headers) => {
                        for (k, v) in headers {
                            hdrs.push((
                                String::from_utf8_lossy(&k).to_string(),
                                String::from_utf8_lossy(&v).to_string(),
                            ));
                        }
                    }
                    Err(_) => {
                        // 解码失败！可能是由于抓包截断或前置丢包导致 HPACK 字典状态错乱。
                        // 必须立刻重置该连接的 Decoder，防止后续所有正常的请求也全军覆没！
                        *dyn_table = Decoder::new();
                    }
                }

                // Convert key:val pairs to JSON map
                let mut hdr_json = streams[stream_idx].1.clone();
                if hdr_json.is_empty() {
                    hdr_json.push('{');
                } else {
                    // remove closing brace to append
                    hdr_json.pop();
                    if !hdrs.is_empty() && hdr_json.len() > 1 {
                        hdr_json.push_str(", ");
                    }
                }

                for (idx, (k, v)) in hdrs.iter().enumerate() {
                    if idx > 0 {
                        hdr_json.push_str(", ");
                    }
                    hdr_json.push_str(&format!(
                        "\"{}\": \"{}\"",
                        k.replace('"', "\\\""),
                        v.replace('"', "\\\"")
                    ));
                }
                if hdr_json.starts_with('{') {
                    hdr_json.push('}');
                }
                streams[stream_idx].1 = hdr_json;
            }
            _ => {}
        }
        pos = data_end;
        if pos >= payload.len() {
            break;
        }
    }

    if streams.is_empty() {
        return format!(
            "\"{}\"",
            String::from_utf8_lossy(payload).replace('"', "\\\"")
        );
    }

    let mut final_json = String::from("[");
    for (i, (sid, hdrs, data)) in streams.iter().enumerate() {
        if i > 0 {
            final_json.push_str(", ");
        }
        final_json.push_str(&format!("{{\"stream\": \"{}\"", sid));
        if !hdrs.is_empty() {
            final_json.push_str(&format!(", \"headers\": {}", hdrs));
        }
        if !data.is_empty() {
            final_json.push_str(", \"data\": [");
            for (j, d) in data.iter().enumerate() {
                if j > 0 {
                    final_json.push_str(", ");
                }
                final_json.push_str(d);
            }
            final_json.push(']');
        }
        final_json.push('}');
    }
    final_json.push(']');
    final_json
}

pub fn is_mongodb(payload: &[u8]) -> bool {
    // MongoDB Wire Protocol (最低需要 16 字节头部)
    if payload.len() < 16 {
        return false;
    }

    // 1. 获取消息长度 MsgHeader.messageLength (小端 int32)
    let msg_len = i32::from_le_bytes(payload[0..4].try_into().unwrap());

    // 合理的包大小（比如大于等于 16，且小于某个巨大的阈值例如 128MB）
    if msg_len < 16 || msg_len > 134217728 {
        return false;
    }

    // 2. 获取操作码 MsgHeader.opCode (小端 int32)
    let op_code = i32::from_le_bytes(payload[12..16].try_into().unwrap());

    // 常用的 MongoDB OpCodes
    // OP_REPLY=1, OP_INSERT=2002, OP_QUERY=2004, OP_GET_MORE=2005, OP_DELETE=2006
    // OP_MSG=2013 (现代驱动常用)
    let is_mongo = match op_code {
        1 | 2001 | 2002 | 2003 | 2004 | 2005 | 2006 | 2010 | 2011 | 2012 | 2013 => true,
        _ => false,
    };

    if !is_mongo {
        return false;
    }

    // 清洗非业务流量 (例如 isMaster, hello, 拓扑检测等心跳探活包)
    // 这些包里通常包含 "hello" 或 "isMaster" 字符串
    let s = extract_printable_chars(payload);
    let s_lower = s.to_lowercase();
    if s_lower.contains("hello")
        || s_lower.contains("ismaster")
        || s_lower.contains("topologyversion")
        || s_lower.contains("iswritableprimary")
    {
        return false; // 过滤掉这些后台维系通信
    }

    true
}

pub fn is_rpc_grpc(payload: &[u8]) -> Option<&'static str> {
    // 1. 纯文本判断 gRPC / HTTP2 的连接前言 Magic String
    // gRPC 客户端发起连接时必带
    if payload.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
        return Some("");
        // return Some("MagicString");
    }

    // 2. HTTP/2 的数据帧有时包含 application/grpc 关键字 (明文情况)
    let s = String::from_utf8_lossy(payload);
    if s.contains("application/grpc")
        || s.contains("grpc-status")
        || s.contains("grpc-message")
        || s.contains("ServiceMethod")
    // gRPC 反射或元数据常见特征
    {
        return Some("");
        // return Some("TextKeyword");
    }

    // 3. HTTP2 Frame Header 强特征匹配 (9 Byte Header)
    // 这是为了识别被 HPACK 压缩过的二进制 gRPC 帧
    if payload.len() >= 9 {
        let frame_length =
            (payload[0] as u32) << 16 | (payload[1] as u32) << 8 | (payload[2] as u32);
        let frame_type = payload[3];
        let _flags = payload[4];
        let stream_id =
            u32::from_be_bytes([payload[5], payload[6], payload[7], payload[8]]) & 0x7FFFFFFF;

        // 如果是有效帧，长度通常不会夸张到离谱，且stream_id合理
        if frame_length < 16384
            && (stream_id > 0
                || frame_type == 4
                || frame_type == 8
                || frame_type == 6
                || frame_type == 0)
        {
            // 头帧(HEADERS=1) 或 数据帧(DATA=0) 或 设置帧(SETTINGS=4) 等
            if frame_type == 4 && frame_length % 6 == 0 {
                // SETTINGS 帧的长度必须是 6 的倍数
                return Some("H2_Settings");
            }
            if frame_type == 8 && frame_length == 4 {
                return Some("H2_Window_Update");
            }
            if frame_type == 6 && frame_length == 8 {
                return Some("H2_Ping");
            }
            if frame_type == 9 {
                return Some("H2_Continuation");
            }
            if frame_type == 1 || frame_type == 0 {
                // 如果发现包含典型的 HPACK 的 magic byte 或者属于已知的 gRPC protobuf 编码二进制序列 (0x00 开头)
                // gRPC Data frame first payload byte is 'compressed' flag (0x00 for no compression) followed by 4 byte length
                if frame_type == 0 && payload.len() >= 14 {
                    // gRPC Header (1 byte compressed flag, 4 bytes length) inside HTTP/2 Data Frame
                    let compressed_flag = payload[9];
                    if compressed_flag == 0x00 || compressed_flag == 0x01 {
                        let grpc_len = u32::from_be_bytes([
                            payload[10],
                            payload[11],
                            payload[12],
                            payload[13],
                        ]);
                        if grpc_len <= frame_length {
                            return Some("H2_Data_Protobuf");
                        }
                    }
                }

                // 由于微服务内部的高频复用，大量帧既没有 SETTINGS 也没有显式的 Magic String，
                // 非常可能直接发送 HEADERS (type=1) 且带 END_HEADERS (flags & 0x04).
                // 特别是在 DeathStarBench 中，流量非常集中，可以放宽启发。
                if frame_type == 1 && (_flags & 0x04) != 0 {
                    // 结合 tcpdump 抓包发现的完美特征：HPACK 静态表压缩
                    // 0x83 = :method POST (gRPC 固定使用 POST)
                    // 0x86 = :scheme http, 0x87 = :scheme https
                    if payload.len() >= 11
                        && payload[9] == 0x83
                        && (payload[10] == 0x86 || payload[10] == 0x87)
                    {
                        return Some("HPACK_Headers"); // 极高置信度为 gRPC 流量
                    }
                    return Some("H2_Headers_Fallback"); // 兼容宽泛匹配
                }
            }
        }
    }

    None
}

pub fn extract_printable_chars(payload: &[u8]) -> String {
    // 快速提取 BSON 二进制中的前几十个可读字符用于诊断（如 coll 名称、命令名等）
    let mut result = String::new();
    let mut count = 0;
    // 跳过前面的16字节 header
    for &b in payload.iter().skip(16) {
        if b >= 32 && b <= 126 {
            result.push(b as char);
            count += 1;
        } else if b == 0 && count > 0 && !result.ends_with(' ') {
            // 对 BSON 字符串以 '\0' 结尾的补充一个空格增强可读性
            result.push(' ');
        }
        if count > 60 {
            result.push_str("...");
            break;
        }
    }
    result.trim().to_string()
}

// ── MongoDB wire-protocol parser ─────────────────────────────────────────────

pub fn read_i32_le(data: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

pub fn read_i64_le(data: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

pub fn read_f64_le(data: &[u8], offset: usize) -> f64 {
    f64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Top-level entry: dispatch by opCode, return a human-readable string.
pub fn format_mongodb_payload(payload: &[u8]) -> String {
    if payload.len() < 16 {
        return format!(
            "\"{}\"",
            extract_printable_chars(payload).replace('"', "\\\"")
        );
    }
    let op_code = read_i32_le(payload, 12);
    match op_code {
        // OP_MSG (modern driver default)
        2013 => {
            if payload.len() < 21 {
                return format!(
                    "\"{}\"",
                    extract_printable_chars(payload).replace('"', "\\\"")
                );
            }
            let mut s = String::new();
            let mut pos = 20;
            s.push('[');
            let mut first_section = true;
            while pos < payload.len() {
                let kind = payload[pos];
                pos += 1;

                if kind == 0 {
                    if !first_section {
                        s.push_str(", ");
                    }
                    first_section = false;
                    let doc_end = bson_doc_to_string(payload, pos, &mut s, 6);
                    if doc_end <= pos {
                        break;
                    }
                    pos = doc_end;
                } else if kind == 1 {
                    if pos + 4 > payload.len() {
                        break;
                    }
                    let section_size = read_i32_le(payload, pos) as usize;
                    let section_end = (pos + section_size).min(payload.len());
                    pos += 4;

                    let id_start = pos;
                    while pos < section_end && payload[pos] != 0 {
                        pos += 1;
                    }
                    let id = String::from_utf8_lossy(&payload[id_start..pos]).to_string();
                    pos += 1; // skip null byte

                    if !first_section {
                        s.push_str(", ");
                    }
                    first_section = false;
                    s.push_str(&format!("{{\"seq\":\"{}\", \"docs\": [", id));

                    let mut first_doc = true;
                    while pos + 4 <= section_end {
                        if !first_doc {
                            s.push_str(", ");
                        }
                        first_doc = false;
                        let doc_end = bson_doc_to_string(payload, pos, &mut s, 6);
                        if doc_end <= pos {
                            break;
                        }
                        pos = doc_end;
                    }
                    s.push_str("]}");
                    pos = section_end;
                } else {
                    break;
                }
            }
            s.push(']');
            s
        }
        // OP_REPLY
        1 => {
            if payload.len() < 36 {
                return format!(
                    "\"{}\"",
                    extract_printable_chars(payload).replace('"', "\\\"")
                );
            }
            let num = read_i32_le(payload, 32);
            let mut s = format!("{{\"numReturned\": {}, \"docs\": [", num);
            if payload.len() > 36 {
                bson_doc_to_string(payload, 36, &mut s, 4);
            }
            s.push_str("]}");
            s
        }
        // OP_QUERY (legacy)
        2004 => {
            if payload.len() < 21 {
                return format!(
                    "\"{}\"",
                    extract_printable_chars(payload).replace('"', "\\\"")
                );
            }
            let mut pos = 20;
            let coll_start = pos;
            while pos < payload.len() && payload[pos] != 0 {
                pos += 1;
            }
            let coll = String::from_utf8_lossy(&payload[coll_start..pos]).to_string();
            pos += 1;
            if pos + 8 > payload.len() {
                return format!("{{\"collection\": \"{}\"}}", coll.replace('"', "\\\""));
            }
            pos += 8;
            let mut s = format!(
                "{{\"collection\": \"{}\", \"query\": ",
                coll.replace('"', "\\\"")
            );
            bson_doc_to_string(payload, pos, &mut s, 4);
            s.push('}');
            s
        }
        _ => format!(
            "\"{}\"",
            extract_printable_chars(payload).replace('"', "\\\"")
        ),
    }
}

/// Parse a BSON document at `offset`, append JSON-like text to `out`.
/// Returns the offset just past the document end.
pub fn bson_doc_to_string(data: &[u8], offset: usize, out: &mut String, max_depth: usize) -> usize {
    if offset + 4 > data.len() {
        out.push_str("{..}");
        return data.len();
    }
    let doc_len = read_i32_le(data, offset) as usize;
    let end = (offset + doc_len).min(data.len());

    out.push('{');
    let mut pos = offset + 4;
    let mut first = true;

    while pos < end {
        let type_byte = data[pos];
        if type_byte == 0 {
            pos += 1;
            break;
        }
        pos += 1;

        // key (cstring)
        let key_start = pos;
        while pos < end && data[pos] != 0 {
            pos += 1;
        }
        let key = String::from_utf8_lossy(&data[key_start..pos]).to_string();
        if pos < end {
            pos += 1;
        }

        if !first {
            out.push_str(", ");
        }
        first = false;
        out.push_str(&format!("\"{}\": ", key));

        pos = bson_value_to_string(data, pos, type_byte, out, max_depth);
    }

    out.push('}');
    end
}

pub fn bson_value_to_string(
    data: &[u8],
    pos: usize,
    type_byte: u8,
    out: &mut String,
    max_depth: usize,
) -> usize {
    match type_byte {
        0x01 => {
            // Double (8 bytes)
            if pos + 8 <= data.len() {
                out.push_str(&format!("{}", read_f64_le(data, pos)));
                pos + 8
            } else {
                out.push('?');
                data.len()
            }
        }
        0x02 => {
            // UTF-8 string: int32 len + chars + \0
            if pos + 4 > data.len() {
                out.push('?');
                return data.len();
            }
            let str_len = read_i32_le(data, pos) as usize;
            let str_start = pos + 4;
            let str_end = str_start + str_len.saturating_sub(1);
            out.push('"');
            if str_end <= data.len() {
                let s = String::from_utf8_lossy(&data[str_start..str_end]);
                let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
                out.push_str(&escaped);
                out.push('"');
                str_start + str_len
            } else {
                let s = String::from_utf8_lossy(&data[str_start.min(data.len())..data.len()]);
                let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
                out.push_str(&escaped);
                out.push_str("..\"");
                data.len()
            }
        }
        0x03 | 0x04 => {
            // Embedded document / Array
            if max_depth == 0 {
                out.push_str("{..}");
                if pos + 4 <= data.len() {
                    (pos + read_i32_le(data, pos) as usize).min(data.len())
                } else {
                    data.len()
                }
            } else {
                bson_doc_to_string(data, pos, out, max_depth - 1)
            }
        }
        0x05 => {
            // Binary: int32 len + subtype(1) + bytes
            if pos + 5 <= data.len() {
                let bin_len = read_i32_le(data, pos) as usize;
                out.push_str("\"<bin>\"");
                (pos + 5 + bin_len).min(data.len())
            } else {
                out.push_str("\"<bin>\"");
                data.len()
            }
        }
        0x07 => {
            // ObjectId (12 bytes)
            if pos + 12 <= data.len() {
                let hex: String = data[pos..pos + 12]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                out.push_str(&format!("\"OID({})\"", hex));
                pos + 12
            } else {
                out.push_str("\"<OID>\"");
                data.len()
            }
        }
        0x08 => {
            // Boolean (1 byte)
            if pos < data.len() {
                out.push_str(if data[pos] != 0 { "true" } else { "false" });
                pos + 1
            } else {
                out.push('?');
                data.len()
            }
        }
        0x09 => {
            // UTC DateTime (int64 ms)
            if pos + 8 <= data.len() {
                out.push_str(&format!("Date({})", read_i64_le(data, pos)));
                pos + 8
            } else {
                out.push('?');
                data.len()
            }
        }
        0x0A => {
            out.push_str("null");
            pos
        } // Null
        0x0B => {
            // Regex: pattern(cstring) + options(cstring)
            let mut p = pos;
            while p < data.len() && data[p] != 0 {
                p += 1;
            }
            out.push_str(&format!("/{}/", String::from_utf8_lossy(&data[pos..p])));
            if p < data.len() {
                p += 1;
            }
            while p < data.len() && data[p] != 0 {
                p += 1;
            }
            if p < data.len() {
                p += 1;
            }
            p
        }
        0x10 => {
            // Int32
            if pos + 4 <= data.len() {
                out.push_str(&format!("{}", read_i32_le(data, pos)));
                pos + 4
            } else {
                out.push('?');
                data.len()
            }
        }
        0x11 => {
            // Timestamp (uint64, internal)
            if pos + 8 <= data.len() {
                pos + 8
            } else {
                data.len()
            }
        }
        0x12 => {
            // Int64
            if pos + 8 <= data.len() {
                out.push_str(&format!("{}", read_i64_le(data, pos)));
                pos + 8
            } else {
                out.push('?');
                data.len()
            }
        }
        0x13 => {
            // Decimal128
            out.push_str("\"<Dec128>\"");
            (pos + 16).min(data.len())
        }
        _ => {
            out.push_str(&format!("\"<0x{:02x}>\"", type_byte));
            data.len() // unknown type size, stop
        }
    }
}

pub fn process_grpc_stream(
    conn_key: &ConnKey,
    tcp_seq: u32,
    payload: &[u8],
    payload_len: u32,
    is_grpc_hint: bool,
) -> Option<String> {
    let mut conns = TCP_STREAMS.lock().unwrap();

    let looks_like_h2 = if payload.len() >= 9 {
        let frame_len =
            ((payload[0] as usize) << 16) | ((payload[1] as usize) << 8) | (payload[2] as usize);
        let frame_type = payload[3];
        let stream_id =
            u32::from_be_bytes([payload[5], payload[6], payload[7], payload[8]]) & 0x7FFFFFFF;
        frame_len <= 16_777_215
            && stream_id <= 1_000_000
            && matches!(frame_type, 0 | 1 | 4 | 6 | 8 | 9)
    } else {
        false
    };

    let is_new = !conns.contains(conn_key);
    let has_related_conn = conns.iter().any(|(k, _)| same_socket_pair(k, conn_key));
    if is_new {
        // Build state for explicit gRPC hints, and also for likely HTTP/2 traffic
        // so responses that start from CONTINUATION/DATA frames are not dropped.
        if !is_grpc_hint && !looks_like_h2 && !has_related_conn {
            return None;
        }
        conns.put(
            conn_key.clone(),
            TcpStream {
                expected_seq: Some(tcp_seq),
                buffer: Vec::new(),
                out_of_order: std::collections::BTreeMap::new(),
                pending_hpack: std::collections::BTreeMap::new(),
                is_broken: false,
            },
        );
    }

    let conn = conns.get_mut(conn_key).unwrap();
    let is_truncated = payload.len() < payload_len as usize;
    let seeded_from_related_conn = !is_grpc_hint && !looks_like_h2 && has_related_conn;

    if conn.is_broken {
        return None;
    }

    let expected = conn.expected_seq.unwrap_or(tcp_seq);

    let mut truncated_in_batch = false;

    if tcp_seq == expected {
        if is_truncated {
            // Start from a clean parser state, but still try to decode what we did capture.
            conn.buffer.clear();
            conn.pending_hpack.clear();
            reset_hpack_decoder(conn_key);
            truncated_in_batch = true;
        }
        conn.buffer.extend_from_slice(payload);
        conn.expected_seq = Some(expected.wrapping_add(payload_len));

        // Process out of order
        loop {
            // Once we detect truncation in this batch, stop stitching following segments.
            // They are after an unseen byte gap and would corrupt frame alignment.
            if truncated_in_batch {
                break;
            }
            let next_seq = conn.expected_seq.unwrap();
            if let Some((next_data, n_len)) = conn.out_of_order.remove(&next_seq) {
                if next_data.len() < n_len as usize {
                    conn.buffer.clear();
                    conn.pending_hpack.clear();
                    reset_hpack_decoder(conn_key);
                    truncated_in_batch = true;
                }
                conn.buffer.extend_from_slice(&next_data);
                conn.expected_seq = Some(next_seq.wrapping_add(n_len));
            } else {
                break;
            }
        }
    } else if tcp_seq > expected {
        conn.out_of_order
            .insert(tcp_seq, (payload.to_vec(), payload_len));
        if conn.out_of_order.len() > 50 {
            conns.pop(conn_key);
            return None;
        }
        return None;
    } else {
        return None;
    }

    if conn.buffer.len() > 1024 * 512 {
        conns.pop(conn_key);
        return None;
    }

    let mut pos = 0;
    let mut parsed_any_frame = false;
    if conn.buffer.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
        pos += 24;
    }

    let mut streams: Vec<(u32, String, Vec<String>)> = Vec::new();
    let mut consumed_pos = pos;

    while pos + 9 <= conn.buffer.len() {
        let frame_len = ((conn.buffer[pos] as usize) << 16)
            | ((conn.buffer[pos + 1] as usize) << 8)
            | (conn.buffer[pos + 2] as usize);

        let frame_type = conn.buffer[pos + 3];
        let flags = conn.buffer[pos + 4];
        let stream_id = u32::from_be_bytes([
            conn.buffer[pos + 5],
            conn.buffer[pos + 6],
            conn.buffer[pos + 7],
            conn.buffer[pos + 8],
        ]) & 0x7FFFFFFF;

        if frame_len > 16_777_215 || stream_id > 1_000_000 {
            // Parser is out-of-sync; skip one byte and retry to re-sync.
            pos += 1;
            if !seeded_from_related_conn {
                consumed_pos = pos;
            }
            continue;
        }

        let data_start = pos + 9;
        let data_end = data_start + frame_len;

        if data_end > conn.buffer.len() {
            // Frame incomplete, wait for more data
            break;
        }

        consumed_pos = data_end;
        parsed_any_frame = true;

        let stream_idx = if let Some(idx) = streams.iter().position(|(id, _, _)| *id == stream_id) {
            idx
        } else {
            streams.push((stream_id, String::new(), Vec::new()));
            streams.len() - 1
        };

        match frame_type {
            0 => {
                let mut current_p = data_start;
                while current_p + 5 <= data_end {
                    let grpc_message_len = ((conn.buffer[current_p + 1] as usize) << 24)
                        | ((conn.buffer[current_p + 2] as usize) << 16)
                        | ((conn.buffer[current_p + 3] as usize) << 8)
                        | (conn.buffer[current_p + 4] as usize);
                    let pb_start = current_p + 5;
                    let pb_end = (pb_start + grpc_message_len).min(data_end);
                    if pb_start < data_end {
                        let mut data_str = String::new();
                        parse_protobuf(&conn.buffer, pb_start, pb_end, &mut data_str, 2);
                        streams[stream_idx].2.push(data_str);
                    }
                    current_p = pb_end;
                    if grpc_message_len == 0 {
                        break;
                    }
                }
            }
            1 => {
                let mut hpack_start = data_start;
                if flags & 0x08 != 0 && hpack_start < data_end {
                    hpack_start += 1;
                }
                if flags & 0x20 != 0 && hpack_start + 5 <= data_end {
                    hpack_start += 5;
                }

                let mut hpack_block = conn.buffer[hpack_start..data_end].to_vec();
                if let Some(existing) = conn.pending_hpack.remove(&stream_id) {
                    let mut merged = existing;
                    merged.extend_from_slice(&hpack_block);
                    hpack_block = merged;
                }

                // END_HEADERS not set, wait for CONTINUATION frames.
                if flags & 0x04 == 0 {
                    conn.pending_hpack.insert(stream_id, hpack_block);
                    pos = data_end;
                    continue;
                }

                let mut hdrs = Vec::new();
                let mut cache = HPACK_DYN_TABLES.lock().unwrap();
                if !cache.contains(conn_key) {
                    cache.put(conn_key.clone(), Decoder::new());
                }
                let dyn_table = cache.get_mut(conn_key).unwrap();
                match dyn_table.decode(&hpack_block) {
                    Ok(headers) => {
                        for (k, v) in headers {
                            hdrs.push((
                                String::from_utf8_lossy(&k).to_string(),
                                String::from_utf8_lossy(&v).to_string(),
                            ));
                        }
                    }
                    Err(_) => {
                        *dyn_table = Decoder::new();
                    }
                }

                let mut hdr_json = streams[stream_idx].1.clone();
                if hdr_json.is_empty() {
                    hdr_json.push('{');
                } else {
                    hdr_json.pop();
                    hdr_json.push(',');
                }
                for (i, (k, v)) in hdrs.iter().enumerate() {
                    if i > 0 {
                        hdr_json.push_str(", ");
                    }
                    let safe_k = k.replace('\\', "\\\\").replace('"', "\\\"");
                    let safe_v = v.replace('\\', "\\\\").replace('"', "\\\"");
                    hdr_json.push_str(&format!("\"{}\": \"{}\"", safe_k, safe_v));
                }
                if hdr_json.ends_with(',') {
                    hdr_json.pop();
                }
                hdr_json.push('}');
                streams[stream_idx].1 = hdr_json;
            }
            9 => {
                // CONTINUATION frame: append to pending header block for this stream.
                let chunk = &conn.buffer[data_start..data_end];
                let entry = conn.pending_hpack.entry(stream_id).or_default();
                entry.extend_from_slice(chunk);

                if flags & 0x04 != 0 {
                    if let Some(block) = conn.pending_hpack.remove(&stream_id) {
                        let mut hdrs = Vec::new();
                        let mut cache = HPACK_DYN_TABLES.lock().unwrap();
                        if !cache.contains(conn_key) {
                            cache.put(conn_key.clone(), Decoder::new());
                        }
                        let dyn_table = cache.get_mut(conn_key).unwrap();
                        match dyn_table.decode(&block) {
                            Ok(headers) => {
                                for (k, v) in headers {
                                    hdrs.push((
                                        String::from_utf8_lossy(&k).to_string(),
                                        String::from_utf8_lossy(&v).to_string(),
                                    ));
                                }
                            }
                            Err(_) => {
                                *dyn_table = Decoder::new();
                            }
                        }

                        if !hdrs.is_empty() {
                            let mut hdr_json = streams[stream_idx].1.clone();
                            if hdr_json.is_empty() {
                                hdr_json.push('{');
                            } else {
                                hdr_json.pop();
                                hdr_json.push(',');
                            }
                            for (i, (k, v)) in hdrs.iter().enumerate() {
                                if i > 0 {
                                    hdr_json.push_str(", ");
                                }
                                let safe_k = k.replace('\\', "\\\\").replace('"', "\\\"");
                                let safe_v = v.replace('\\', "\\\\").replace('"', "\\\"");
                                hdr_json.push_str(&format!("\"{}\": \"{}\"", safe_k, safe_v));
                            }
                            if hdr_json.ends_with(',') {
                                hdr_json.pop();
                            }
                            hdr_json.push('}');
                            streams[stream_idx].1 = hdr_json;
                        }
                    }
                }
            }
            _ => {}
        }
        pos = data_end;
    }

    // For connections that were only inferred from the peer direction,
    // keep unparsed bytes so later packets can help recover frame alignment.
    if parsed_any_frame || !seeded_from_related_conn {
        conn.buffer.drain(..consumed_pos);
    }

    // Do not carry parser state across chunks with missing bytes.
    if truncated_in_batch {
        conn.buffer.clear();
        conn.pending_hpack.clear();
        reset_hpack_decoder(conn_key);
    }

    if streams.is_empty() {
        return None;
    }

    let mut json_arr = String::from("[");
    for (i, (stream_id, headers, data_vec)) in streams.iter().enumerate() {
        if i > 0 {
            json_arr.push_str(", ");
        }
        json_arr.push_str(&format!("{{\"stream\": \"{}\"", stream_id));
        if !headers.is_empty() && headers != "{}" {
            json_arr.push_str(&format!(", \"headers\": {}", headers));
        }
        if !data_vec.is_empty() {
            let mut data_arr = String::from("[");
            for (j, d) in data_vec.iter().enumerate() {
                if j > 0 {
                    data_arr.push_str(", ");
                }
                data_arr.push_str(&d);
            }
            data_arr.push(']');
            json_arr.push_str(&format!(", \"data\": {}", data_arr));
        }
        json_arr.push('}');
    }
    json_arr.push(']');

    Some(json_arr)
}
