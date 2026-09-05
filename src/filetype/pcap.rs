// LogCrab - GPL-3.0-or-later
// Copyright (C) 2026 Daniel Freiermuth

use chrono::{DateTime, Local, TimeZone};
use egui::Ui;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError, PcapNGReader};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use crate::filetype::{BinaryFileType, InputFileType, LineType};

// ============================================================================
// PcapLogLine
// ============================================================================

/// PCAP (Packet Capture) format log line representing a network packet
#[derive(Debug, Clone)]
pub struct PcapLogLine {
    /// Parsed packet information
    pub packet_info: PacketInfo,
    /// Original packet number in source file
    pub line_number: usize,
}

impl PcapLogLine {
    #[must_use]
    pub const fn new(packet_info: PacketInfo, line_number: usize) -> Self {
        Self {
            packet_info,
            line_number,
        }
    }
}

// ============================================================================
// PcapFileState
// ============================================================================

/// Well-known SOME/IP Service Discovery port
const SOMEIP_SD_PORT: u16 = 30490;

/// File state for PCAP files, including time offset and SOME/IP SD decoding state.
///
/// # Panics
///
/// Methods accessing SOME/IP state panic if a prior holder poisoned its mutex.
#[derive(Debug)]
pub struct PcapFileState {
    /// Shared time-offset and calibration state
    inner: crate::filetype::SimpleFileState,
    /// Set of multicast address:port combinations that should decode SOME/IP SD
    someip_sd_decodings: std::sync::Mutex<HashSet<String>>,
    /// Known SOME/IP endpoints discovered from SD messages (format: "TCP:ip:port" or "UDP:ip:port")
    someip_known_endpoints: std::sync::Mutex<HashSet<String>>,
}

#[allow(
    clippy::missing_panics_doc,
    reason = "the shared mutex-poisoning precondition is documented on PcapFileState"
)]
impl PcapFileState {
    /// Read the current time offset in milliseconds.
    #[inline]
    pub fn time_offset_ms(&self) -> i64 {
        self.inner.time_offset_ms()
    }

    /// Set the time offset in milliseconds.
    #[inline]
    pub fn set_time_offset_ms(&self, v: i64) {
        self.inner.set_time_offset_ms(v);
    }

    /// Check if SOME/IP SD decoding is active for a multicast key
    pub fn is_someip_sd_active(&self, key: &str) -> bool {
        self.someip_sd_decodings
            .lock()
            .expect("someip_sd_decodings lock poisoned")
            .contains(key)
    }

    /// Toggle SOME/IP SD decoding for a multicast key
    pub fn toggle_someip_sd(&self, key: String) -> bool {
        let mut decodings = self
            .someip_sd_decodings
            .lock()
            .expect("someip_sd_decodings lock poisoned");
        if decodings.contains(&key) {
            decodings.remove(&key);
            false
        } else {
            decodings.insert(key);
            true
        }
    }

    /// Add discovered SOME/IP endpoints from SD messages
    pub fn add_someip_endpoints(&self, endpoints: &[SomeIpEndpoint]) {
        let mut known = self
            .someip_known_endpoints
            .lock()
            .expect("someip_known_endpoints lock poisoned");
        for ep in endpoints {
            known.insert(ep.key());
        }
    }

    /// Check if a given address:port is a known SOME/IP endpoint
    pub fn is_known_someip_endpoint(&self, proto: &str, addr: &str, port: u16) -> bool {
        self.someip_known_endpoints
            .lock()
            .expect("someip_known_endpoints lock poisoned")
            .contains(&format!("{proto}:{addr}:{port}"))
    }
}

impl Default for PcapFileState {
    fn default() -> Self {
        Self {
            inner: crate::filetype::SimpleFileState::default(),
            someip_sd_decodings: std::sync::Mutex::new(HashSet::new()),
            someip_known_endpoints: std::sync::Mutex::new(HashSet::new()),
        }
    }
}

impl Clone for PcapFileState {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            someip_sd_decodings: std::sync::Mutex::new(
                self.someip_sd_decodings
                    .lock()
                    .expect("someip_sd_decodings lock poisoned")
                    .clone(),
            ),
            someip_known_endpoints: std::sync::Mutex::new(
                self.someip_known_endpoints
                    .lock()
                    .expect("someip_known_endpoints lock poisoned")
                    .clone(),
            ),
        }
    }
}

impl serde::Serialize for PcapFileState {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = s.serialize_struct("PcapFileState", 3)?;
        state.serialize_field("time_offset_ms", &self.time_offset_ms())?;
        let decodings: Vec<String> = self
            .someip_sd_decodings
            .lock()
            .expect("someip_sd_decodings lock poisoned")
            .iter()
            .cloned()
            .collect();
        state.serialize_field("someip_sd_decodings", &decodings)?;
        let endpoints: Vec<String> = self
            .someip_known_endpoints
            .lock()
            .expect("someip_known_endpoints lock poisoned")
            .iter()
            .cloned()
            .collect();
        state.serialize_field("someip_known_endpoints", &endpoints)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for PcapFileState {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Helper {
            #[serde(default)]
            time_offset_ms: i64,
            #[serde(default)]
            someip_sd_decodings: Vec<String>,
            #[serde(default)]
            someip_known_endpoints: Vec<String>,
        }
        let h = Helper::deserialize(d)?;
        Ok(Self {
            inner: crate::filetype::SimpleFileState {
                time_offset_ms: std::sync::atomic::AtomicI64::new(h.time_offset_ms),
                calibration: std::sync::Mutex::new(None),
            },
            someip_sd_decodings: std::sync::Mutex::new(h.someip_sd_decodings.into_iter().collect()),
            someip_known_endpoints: std::sync::Mutex::new(
                h.someip_known_endpoints.into_iter().collect(),
            ),
        })
    }
}

impl crate::filetype::LogFileState for PcapFileState {
    fn egui_render_file_state(&self, ui: &egui::Ui, source_path: &std::path::Path) -> bool {
        self.inner.egui_render_file_state(ui, source_path)
    }
}

// ============================================================================
// PcapConfig — persistent per-type settings
// ============================================================================

/// Persistent settings for PCAP files, stored in the global config.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PcapConfig {
    /// When `true`, include the Ethernet MAC addresses in each log line.
    #[serde(default)]
    pub show_mac_addresses: bool,
}

impl crate::filetype::EguiConfig for PcapConfig {
    fn egui_render(&mut self, ui: &mut egui::Ui) -> bool {
        ui.separator();
        ui.label("PCAP:");
        let resp = ui.checkbox(&mut self.show_mac_addresses, "Show MAC addresses");
        resp.changed()
    }
}

// ============================================================================
// LineType implementation
// ============================================================================

impl LineType for PcapLogLine {
    type Config = PcapConfig;
    type FileState = PcapFileState;

    fn file_state_from_v2(time_offset_ms: i64) -> PcapFileState {
        let s = PcapFileState::default();
        s.set_time_offset_ms(time_offset_ms);
        s
    }

    fn timestamp(&self, _config: &PcapConfig, file_state: &PcapFileState) -> DateTime<Local> {
        self.packet_info.timestamp + chrono::Duration::milliseconds(file_state.time_offset_ms())
    }

    fn message(&self) -> String {
        self.packet_info.format_message()
    }

    fn display_message(&self, config: &PcapConfig, file_state: &PcapFileState) -> String {
        let offset_ms = file_state.time_offset_ms();
        let base_msg = if offset_ms != 0 {
            format!(
                "[{}] {}",
                crate::parser::format_time_diff(chrono::Duration::milliseconds(offset_ms)),
                self.message()
            )
        } else {
            self.packet_info.format_message()
        };

        // Prepend MAC addresses if the setting is enabled.
        let base_msg = if config.show_mac_addresses {
            let pi = &self.packet_info;
            match (&pi.src_mac, &pi.dst_mac) {
                (Some(smac), Some(dmac)) => format!("{smac} \u{2192} {dmac} | {base_msg}"),
                _ => base_msg,
            }
        } else {
            base_msg
        };

        let pi = &self.packet_info;

        // 1. Auto-decode SOME/IP-SD on well-known SD port (30490)
        if pi.protocol == "UDP"
            && (pi.src_port == Some(SOMEIP_SD_PORT) || pi.dst_port == Some(SOMEIP_SD_PORT))
        {
            if let Some(ref payload) = pi.transport_payload {
                if let Some(sd_info) = decode_someip_sd(payload) {
                    // Lazily register discovered endpoints
                    file_state.add_someip_endpoints(&sd_info.endpoints);
                    let entries_str = if sd_info.entries.is_empty() {
                        String::new()
                    } else {
                        format!(" {}", sd_info.entries.join(", "))
                    };
                    return format!(
                        "{} [SOME/IP-SD {}{}]",
                        base_msg, sd_info.message_type, entries_str
                    );
                }
            }
        }

        // 2. Legacy per-multicast toggle (backward compat)
        if let Some(key) = pi.multicast_key() {
            if file_state.is_someip_sd_active(&key) {
                if let Some(ref payload) = pi.transport_payload {
                    if let Some(sd_info) = decode_someip_sd(payload) {
                        file_state.add_someip_endpoints(&sd_info.endpoints);
                        let entries_str = if sd_info.entries.is_empty() {
                            String::new()
                        } else {
                            format!(" {}", sd_info.entries.join(", "))
                        };
                        return format!(
                            "{} [SOME/IP-SD {}{}]",
                            base_msg, sd_info.message_type, entries_str
                        );
                    }
                }
            }
        }

        // 3. Auto-decode SOME/IP on known endpoints discovered from SD
        if let Some(ref payload) = pi.transport_payload {
            let proto = &pi.protocol;
            let is_known_src = pi
                .src_port
                .is_some_and(|p| file_state.is_known_someip_endpoint(proto, &pi.src_addr, p));
            let is_known_dst = pi
                .dst_port
                .is_some_and(|p| file_state.is_known_someip_endpoint(proto, &pi.dst_addr, p));
            if is_known_src || is_known_dst {
                if let Some(someip_str) = decode_someip(payload) {
                    return format!("{base_msg} [SOME/IP {someip_str}]");
                }
            }
        }

        base_msg
    }

    fn raw(&self) -> String {
        self.packet_info.format_raw()
    }

    fn line_number(&self) -> usize {
        self.line_number
    }

    fn egui_render_context_menu(
        &self,
        ui: &mut Ui,
        _config: &PcapConfig,
        file_state: &PcapFileState,
    ) {
        if ui.button("⏱ Calibrate Time Here").clicked() {
            let raw_time = self.packet_info.timestamp;
            let display_time =
                raw_time + chrono::Duration::milliseconds(file_state.time_offset_ms());
            *file_state
                .inner
                .calibration
                .lock()
                .expect("calibration lock poisoned") = Some((
                raw_time,
                crate::filetype::CalibrationWindow::new(
                    display_time,
                    false,
                    Some(display_time),
                    raw_time,
                ),
            ));
            ui.close();
        }

        // SOME/IP SD decoding toggle for multicast packets
        if let Some(key) = self.packet_info.multicast_key() {
            ui.separator();
            let is_active = file_state.is_someip_sd_active(&key);
            let label = if is_active {
                format!("🔓 Disable SOME/IP SD decoding for {key}")
            } else {
                format!("🔒 Enable SOME/IP SD decoding for {key}")
            };
            if ui.button(label).clicked() {
                file_state.toggle_someip_sd(key);
                ui.close();
            }
        }
    }
}

// ============================================================================
// PcapFileType (InputFileType + BinaryFileType)
// ============================================================================

/// Stateful reader for packet captures in both classic pcap and pcapng formats.
///
/// All packets are parsed eagerly at `open()` time via the streaming `pcap_parser`
/// crate, then drained in chunks via `read()`.
pub struct PcapFileType {
    lines: Vec<PcapLogLine>,
    cursor: usize,
    file_size: u64,
}

impl InputFileType for PcapFileType {
    type LineType = PcapLogLine;

    const FILE_EXTENSIONS: &'static [&'static str] = &["pcap", "pcapng", "cap"];

    /// Open a pcap/pcapng file for pull-based reading.
    fn open(
        path: &Path,
        _config: PcapConfig,
        file_state: std::sync::Arc<PcapFileState>,
    ) -> anyhow::Result<Self> {
        let file_size = std::fs::metadata(path).map_or(0, |m| m.len());
        let lines = parse_pcap_to_lines(path)?;

        // Pre-scan for SOME/IP-SD endpoints on the well-known SD port
        pre_discover_someip_endpoints(&lines, &file_state);

        Ok(Self {
            lines,
            cursor: 0,
            file_size,
        })
    }

    fn read(&mut self, lines_to_read: usize) -> anyhow::Result<Vec<Self::LineType>> {
        let end = (self.cursor + lines_to_read).min(self.lines.len());
        let batch = self.lines[self.cursor..end].to_vec();
        self.cursor = end;
        Ok(batch)
    }

    fn bytes_consumed(&self) -> u64 {
        let total = self.lines.len();
        if total == 0 {
            return self.file_size;
        }
        (self.cursor as f64 / total as f64 * self.file_size as f64) as u64
    }
}

impl BinaryFileType for PcapFileType {
    /// All magic byte patterns for classic pcap (LE/BE, normal/nanosec) and pcapng.
    const MAGIC_BYTES: &'static [&'static [u8]] = &[
        &[0xd4, 0xc3, 0xb2, 0xa1], // classic pcap, little-endian
        &[0xa1, 0xb2, 0xc3, 0xd4], // classic pcap, big-endian
        &[0x4d, 0x3c, 0xb2, 0xa1], // nanosec pcap, little-endian
        &[0xa1, 0xb2, 0x3c, 0x4d], // nanosec pcap, big-endian
        &[0x0a, 0x0d, 0x0d, 0x0a], // pcapng Section Header Block
    ];
}

// ============================================================================
// Pcap parsing utilities (moved from parser/pcap.rs)
// ============================================================================

/// Represents a parsed network packet for display
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub timestamp: DateTime<Local>,
    pub src_addr: String,
    pub src_port: Option<u16>,
    pub dst_addr: String,
    pub dst_port: Option<u16>,
    /// Ethernet source MAC address (e.g. `"aa:bb:cc:dd:ee:ff"`), if available.
    pub src_mac: Option<String>,
    /// Ethernet destination MAC address, if available.
    pub dst_mac: Option<String>,
    pub protocol: String,
    pub vlan_id: Option<u16>,
    pub length: u32,
    pub info: String,
    pub tcp_details: Option<TcpDetails>,
    pub is_abnormal: bool,
    pub transport_payload: Option<Vec<u8>>,
}

/// TCP-specific packet details
#[derive(Debug, Clone)]
pub struct TcpDetails {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload_len: u32,
}

impl PacketInfo {
    /// Check if the destination address is multicast
    #[must_use]
    pub fn is_multicast(&self) -> bool {
        is_multicast_address(&self.dst_addr)
    }

    /// Get the multicast key for tracking SOME/IP SD decodings
    #[must_use]
    pub fn multicast_key(&self) -> Option<String> {
        if self.is_multicast() && self.protocol == "UDP" {
            self.dst_port
                .map(|port| format!("{}:{}", self.dst_addr, port))
        } else {
            None
        }
    }

    /// Format as a display message
    #[must_use]
    pub fn format_message(&self) -> String {
        let src = self.src_port.map_or_else(
            || self.src_addr.clone(),
            |port| format!("{}:{}", self.src_addr, port),
        );
        let dst = self.dst_port.map_or_else(
            || self.dst_addr.clone(),
            |port| format!("{}:{}", self.dst_addr, port),
        );
        let vlan = self
            .vlan_id
            .map_or(String::new(), |id| format!(" [VLAN {id}]"));
        let abnormal = if self.is_abnormal { " \u{26a0}" } else { "" };
        self.tcp_details.as_ref().map_or_else(
            || {
                if self.info.is_empty() {
                    format!(
                        "{} {} \u{2192} {}{} Len={}{}",
                        self.protocol, src, dst, vlan, self.length, abnormal
                    )
                } else {
                    format!(
                        "{} {} \u{2192} {}{} {} Len={}{}",
                        self.protocol, src, dst, vlan, self.info, self.length, abnormal
                    )
                }
            },
            |tcp| {
                let flags_str = format_tcp_flags(tcp.flags);
                let seq_str = format!("Seq={}", tcp.seq);
                let ack_str = if tcp.flags & 0x10 != 0 {
                    format!(" Ack={}", tcp.ack)
                } else {
                    String::new()
                };
                let win_str = format!(" Win={}", tcp.window);
                let len_str = if tcp.payload_len > 0 {
                    format!(" Len={}", tcp.payload_len)
                } else {
                    String::new()
                };
                format!(
                    "{} {} \u{2192} {}{} {} {}{}{}{}{}",
                    self.protocol,
                    src,
                    dst,
                    vlan,
                    flags_str,
                    seq_str,
                    ack_str,
                    win_str,
                    len_str,
                    abnormal
                )
            },
        )
    }

    /// Format as raw line (more detailed)
    #[must_use]
    pub fn format_raw(&self) -> String {
        let src = self.src_port.map_or_else(
            || self.src_addr.clone(),
            |port| format!("{}:{}", self.src_addr, port),
        );
        let dst = self.dst_port.map_or_else(
            || self.dst_addr.clone(),
            |port| format!("{}:{}", self.dst_addr, port),
        );
        let vlan = self
            .vlan_id
            .map_or(String::new(), |id| format!(" VLAN={id}"));
        let abnormal = if self.is_abnormal { " [ABNORMAL]" } else { "" };
        self.tcp_details.as_ref().map_or_else(
            || {
                format!(
                    "[{}] {} {} \u{2192} {}{} {} Length={}{}",
                    self.timestamp.format("%H:%M:%S%.6f"),
                    self.protocol,
                    src,
                    dst,
                    vlan,
                    self.info,
                    self.length,
                    abnormal
                )
            },
            |tcp| {
                let flags_str = format_tcp_flags(tcp.flags);
                let seq_str = format!("Seq={}", tcp.seq);
                let ack_str = if tcp.flags & 0x10 != 0 {
                    format!(" Ack={}", tcp.ack)
                } else {
                    String::new()
                };
                let win_str = format!(" Win={}", tcp.window);
                let len_str = if tcp.payload_len > 0 {
                    format!(" Len={}", tcp.payload_len)
                } else {
                    String::new()
                };
                format!(
                    "[{}] {} {} \u{2192} {}{} {} {}{}{}{}{}",
                    self.timestamp.format("%H:%M:%S%.6f"),
                    self.protocol,
                    src,
                    dst,
                    vlan,
                    flags_str,
                    seq_str,
                    ack_str,
                    win_str,
                    len_str,
                    abnormal
                )
            },
        )
    }
}

fn format_tcp_flags(flags: u8) -> String {
    let mut flag_strs = Vec::new();
    if flags & 0x02 != 0 {
        flag_strs.push("SYN");
    }
    if flags & 0x10 != 0 {
        flag_strs.push("ACK");
    }
    if flags & 0x01 != 0 {
        flag_strs.push("FIN");
    }
    if flags & 0x04 != 0 {
        flag_strs.push("RST");
    }
    if flags & 0x08 != 0 {
        flag_strs.push("PSH");
    }
    if flags & 0x20 != 0 {
        flag_strs.push("URG");
    }
    if flag_strs.is_empty() {
        "[]".to_string()
    } else {
        format!("[{}]", flag_strs.join(","))
    }
}

// ============================================================================
// TCP Flow Tracking
// ============================================================================

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct FlowKey {
    src_addr: String,
    src_port: u16,
    dst_addr: String,
    dst_port: u16,
}

impl FlowKey {
    const fn new(src_addr: String, src_port: u16, dst_addr: String, dst_port: u16) -> Self {
        Self {
            src_addr,
            src_port,
            dst_addr,
            dst_port,
        }
    }
    fn reverse(&self) -> Self {
        Self {
            src_addr: self.dst_addr.clone(),
            src_port: self.dst_port,
            dst_addr: self.src_addr.clone(),
            dst_port: self.src_port,
        }
    }
}

#[derive(Debug, Clone)]
struct TcpFlowState {
    next_seq: u32,
    last_ack: u32,
    dup_ack_count: u8,
    recent_seqs: Vec<(u32, u32)>,
}

impl TcpFlowState {
    fn new() -> Self {
        Self {
            next_seq: 0,
            last_ack: 0,
            dup_ack_count: 0,
            recent_seqs: Vec::with_capacity(10),
        }
    }
    fn is_retransmission(&self, seq: u32, payload_len: u32) -> bool {
        if payload_len == 0 {
            return false;
        }
        for (old_seq, old_len) in &self.recent_seqs {
            if seq == *old_seq && payload_len == *old_len {
                return true;
            }
            if seq < self.next_seq && seq + payload_len > *old_seq {
                return true;
            }
        }
        false
    }
    const fn is_out_of_order(&self, seq: u32, payload_len: u32) -> bool {
        if payload_len == 0 || self.next_seq == 0 {
            return false;
        }
        seq > self.next_seq
    }
    fn update(&mut self, seq: u32, ack: u32, payload_len: u32, has_ack_flag: bool) {
        if payload_len > 0 {
            self.recent_seqs.push((seq, payload_len));
            if self.recent_seqs.len() > 10 {
                self.recent_seqs.remove(0);
            }
            let seq_end = seq.wrapping_add(payload_len);
            if self.next_seq == 0 || seq == self.next_seq {
                self.next_seq = seq_end;
            }
        }
        if has_ack_flag {
            if ack == self.last_ack && payload_len == 0 {
                self.dup_ack_count += 1;
            } else {
                self.dup_ack_count = 0;
                self.last_ack = ack;
            }
        }
    }
}

pub struct TcpFlowTracker {
    flows: HashMap<FlowKey, TcpFlowState>,
}

impl Default for TcpFlowTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpFlowTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }
    pub fn analyze_packet(&mut self, packet: &mut PacketInfo) {
        let Some(tcp) = &packet.tcp_details else {
            return;
        };
        let (Some(src_port), Some(dst_port)) = (packet.src_port, packet.dst_port) else {
            return;
        };
        let flow_key = FlowKey::new(
            packet.src_addr.clone(),
            src_port,
            packet.dst_addr.clone(),
            dst_port,
        );
        let flow_state = self
            .flows
            .entry(flow_key.clone())
            .or_insert_with(TcpFlowState::new);
        let mut anomaly_reasons: Vec<String> = Vec::new();
        if tcp.flags & 0x04 != 0 {
            anomaly_reasons.push("RST".to_string());
            packet.is_abnormal = true;
        }
        if flow_state.is_retransmission(tcp.seq, tcp.payload_len) {
            anomaly_reasons.push("Retransmission".to_string());
            packet.is_abnormal = true;
        }
        if flow_state.is_out_of_order(tcp.seq, tcp.payload_len) {
            anomaly_reasons.push("Out-of-Order".to_string());
            packet.is_abnormal = true;
        }
        if flow_state.dup_ack_count >= 2 && tcp.flags & 0x10 != 0 {
            anomaly_reasons.push(format!("Dup ACK #{}", flow_state.dup_ack_count + 1));
            packet.is_abnormal = true;
        }
        if tcp.window == 0 && tcp.flags & 0x10 != 0 {
            anomaly_reasons.push("ZeroWindow".to_string());
            packet.is_abnormal = true;
        }
        if !anomaly_reasons.is_empty() {
            packet.info = format!("{} [{}]", packet.info, anomaly_reasons.join(", "));
        }
        flow_state.update(tcp.seq, tcp.ack, tcp.payload_len, tcp.flags & 0x10 != 0);
        if tcp.flags & 0x05 != 0 {
            self.flows.remove(&flow_key);
            self.flows.remove(&flow_key.reverse());
        }
    }
    pub fn cleanup(&mut self, max_flows: usize) {
        if self.flows.len() > max_flows {
            let to_remove = self.flows.len() - max_flows;
            let keys: Vec<_> = self.flows.keys().take(to_remove).cloned().collect();
            for key in keys {
                self.flows.remove(&key);
            }
        }
    }
}

// ============================================================================
// Multicast Detection
// ============================================================================

/// Check if an IP address is multicast
fn is_multicast_address(addr: &str) -> bool {
    if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
        return ip.is_multicast();
    }
    false
}

// ============================================================================
// SOME/IP Decoder
// ============================================================================

/// A discovered SOME/IP endpoint (address + port + transport protocol)
#[derive(Debug, Clone)]
pub struct SomeIpEndpoint {
    pub addr: String,
    pub port: u16,
    pub protocol: &'static str, // "TCP" or "UDP"
}

impl SomeIpEndpoint {
    /// Key format used for `HashSet` lookups: "TCP:10.0.0.1:30000"
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}:{}:{}", self.protocol, self.addr, self.port)
    }
}

#[derive(Debug, Clone)]
pub struct SomeIpSdInfo {
    pub message_type: String,
    pub entries: Vec<String>,
    pub endpoints: Vec<SomeIpEndpoint>,
}

/// Decode SOME/IP SD (Service Discovery) payload using `someip_parse` library
fn decode_someip_sd(payload: &[u8]) -> Option<SomeIpSdInfo> {
    use someip_parse::sd::{SdEntrySlice, SdHeader, SdOptionSlice};
    use someip_parse::sd::entries::{EventGroupEntryType, SdServiceEntryType};
    use someip_parse::sd::options::TransportProtocol;
    use someip_parse::SomeipMsgSlice;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Format a slice of SD option slices as compact endpoint strings.
    fn format_endpoints(opts: &[SdOptionSlice]) -> Vec<String> {
        opts.iter()
            .filter_map(|opt| match opt {
                SdOptionSlice::Ipv4Endpoint(e) => Some(format!(
                    "{}/{}:{}",
                    Ipv4Addr::from(e.ipv4_address()),
                    proto_str(e.transport_protocol()),
                    e.port(),
                )),
                SdOptionSlice::Ipv6Endpoint(e) => Some(format!(
                    "[{}]/{}:{}",
                    Ipv6Addr::from(e.ipv6_address()),
                    proto_str(e.transport_protocol()),
                    e.port(),
                )),
                SdOptionSlice::Ipv4Multicast(e) => Some(format!(
                    "mcast:{}/{}:{}",
                    Ipv4Addr::from(e.ipv4_address()),
                    proto_str(e.transport_protocol()),
                    e.port(),
                )),
                SdOptionSlice::Ipv6Multicast(e) => Some(format!(
                    "mcast:[{}]/{}:{}",
                    Ipv6Addr::from(e.ipv6_address()),
                    proto_str(e.transport_protocol()),
                    e.port(),
                )),
                SdOptionSlice::Configuration(_)
                | SdOptionSlice::LoadBalancing(_)
                | SdOptionSlice::Ipv4SdEndpoint(_)
                | SdOptionSlice::Ipv6SdEndpoint(_)
                | SdOptionSlice::Unknown(_) => None,
            })
            .collect()
    }

    /// Extract `SomeIpEndpoint` objects from a slice of SD option slices.
    fn extract_endpoints(opts: &[SdOptionSlice]) -> Vec<SomeIpEndpoint> {
        opts.iter()
            .filter_map(|opt| match opt {
                SdOptionSlice::Ipv4Endpoint(e) => Some(SomeIpEndpoint {
                    addr: Ipv4Addr::from(e.ipv4_address()).to_string(),
                    port: e.port(),
                    protocol: proto_str(e.transport_protocol()),
                }),
                SdOptionSlice::Ipv6Endpoint(e) => Some(SomeIpEndpoint {
                    addr: Ipv6Addr::from(e.ipv6_address()).to_string(),
                    port: e.port(),
                    protocol: proto_str(e.transport_protocol()),
                }),
                SdOptionSlice::Ipv4Multicast(e) => Some(SomeIpEndpoint {
                    addr: Ipv4Addr::from(e.ipv4_address()).to_string(),
                    port: e.port(),
                    protocol: proto_str(e.transport_protocol()),
                }),
                SdOptionSlice::Ipv6Multicast(e) => Some(SomeIpEndpoint {
                    addr: Ipv6Addr::from(e.ipv6_address()).to_string(),
                    port: e.port(),
                    protocol: proto_str(e.transport_protocol()),
                }),
                SdOptionSlice::Configuration(_)
                | SdOptionSlice::LoadBalancing(_)
                | SdOptionSlice::Ipv4SdEndpoint(_)
                | SdOptionSlice::Ipv6SdEndpoint(_)
                | SdOptionSlice::Unknown(_) => None,
            })
            .collect()
    }

    const fn proto_str(p: TransportProtocol) -> &'static str {
        match p {
            TransportProtocol::Tcp => "TCP",
            TransportProtocol::Udp => "UDP",
            TransportProtocol::Generic(_) => "?",
        }
    }

    /// Collect endpoint options for an entry's two option runs.
    fn entry_endpoints(opts: &[SdOptionSlice], idx1: u8, num1: u8, idx2: u8, num2: u8) -> String {
        let run1_start = idx1 as usize;
        let run1_end = (run1_start + num1 as usize).min(opts.len());
        let run2_start = idx2 as usize;
        let run2_end = (run2_start + num2 as usize).min(opts.len());

        let mut endpoints = format_endpoints(&opts[run1_start..run1_end]);
        endpoints.extend(format_endpoints(&opts[run2_start..run2_end]));

        if endpoints.is_empty() {
            String::new()
        } else {
            format!(" @ {}", endpoints.join(", "))
        }
    }

    // Parse SOME/IP message
    let Ok(msg) = SomeipMsgSlice::from_slice(payload) else {
        return None;
    };

    // Check if this is a SOME/IP-SD message
    if !msg.is_someip_sd() {
        return None;
    }

    let someip_payload = msg.payload();

    // Parse SD header using the library
    let mut cursor = std::io::Cursor::new(someip_payload);
    let Ok(sd_header) = SdHeader::read(&mut cursor) else {
        return None;
    };

    // Collect options for indexed access by entry option runs
    let options: Vec<SdOptionSlice> = sd_header.options().collect();

    // Format entries for display
    let entries = sd_header
        .entries()
        .map(|entry| match entry {
            SdEntrySlice::Service(s) => {
                let entry_type = match s.entry_type() {
                    SdServiceEntryType::FindService => "FindService",
                    SdServiceEntryType::OfferService => "OfferService",
                };
                let endpoints = entry_endpoints(
                    &options,
                    s.start_index_options_1(),
                    s.number_of_options_1().value(),
                    s.start_index_options_2(),
                    s.number_of_options_2().value(),
                );
                format!(
                    "{}(0x{:04x}:0x{:04x} v{}.{} TTL={}{})",
                    entry_type,
                    s.service_id(),
                    s.instance_id(),
                    s.major_version(),
                    s.minor_version(),
                    s.ttl().value(),
                    endpoints,
                )
            }
            SdEntrySlice::Eventgroup(e) => {
                let entry_type = match e.entry_type() {
                    EventGroupEntryType::SubscribeOrStop => "Subscribe",
                    EventGroupEntryType::SubscribeAckOrNack => "SubscribeAck",
                };
                let endpoints = entry_endpoints(
                    &options,
                    e.index_first_option_run(),
                    e.number_of_options_1().value(),
                    e.index_second_option_run(),
                    e.number_of_options_2().value(),
                );
                format!(
                    "{}(0x{:04x}:0x{:04x} eg=0x{:04x} TTL={}{})",
                    entry_type,
                    e.service_id(),
                    e.instance_id(),
                    e.eventgroup_id(),
                    e.ttl().value(),
                    endpoints,
                )
            }
        })
        .collect();

    let msg_type = match msg.message_type() {
        someip_parse::MessageType::Request => "REQUEST",
        someip_parse::MessageType::RequestNoReturn => "REQUEST_NO_RETURN",
        someip_parse::MessageType::Notification => "NOTIFICATION",
        someip_parse::MessageType::Response => "RESPONSE",
        someip_parse::MessageType::Error => "ERROR",
    };

    // Extract all endpoints from SD options for lazy discovery
    let discovered_endpoints = extract_endpoints(&options);

    Some(SomeIpSdInfo {
        message_type: msg_type.to_string(),
        entries,
        endpoints: discovered_endpoints,
    })
}

/// Decode a non-SD SOME/IP message and return a formatted summary string.
fn decode_someip(payload: &[u8]) -> Option<String> {
    use someip_parse::SomeipMsgSlice;

    let Ok(msg) = SomeipMsgSlice::from_slice(payload) else {
        return None;
    };

    // Skip SD messages — those are handled by decode_someip_sd
    if msg.is_someip_sd() {
        return None;
    }

    let msg_type = match msg.message_type() {
        someip_parse::MessageType::Request => "REQ",
        someip_parse::MessageType::RequestNoReturn => "FIRE&FORGET",
        someip_parse::MessageType::Notification => "NOTIFY",
        someip_parse::MessageType::Response => "RESP",
        someip_parse::MessageType::Error => "ERR",
    };

    let service_id = msg.service_id();
    let method_or_event = msg.event_or_method_id();
    let client_id = (msg.request_id() >> 16) as u16;
    let session_id = (msg.request_id() & 0xFFFF) as u16;
    let return_code = msg.return_code();
    let payload_len = msg.payload().len();

    let id_label = if msg.is_event() { "evt" } else { "method" };
    let tp = if msg.is_tp() { " TP" } else { "" };

    let rc_str = match return_code {
        0x00 => String::new(),
        0x01 => " RC=NOT_OK".to_string(),
        0x02 => " RC=UNKNOWN_SERVICE".to_string(),
        0x03 => " RC=UNKNOWN_METHOD".to_string(),
        _ => format!(" RC=0x{return_code:02x}"),
    };

    Some(format!(
        "{msg_type} svc=0x{service_id:04x} {id_label}=0x{method_or_event:04x} client=0x{client_id:04x} sess=0x{session_id:04x}{tp}{rc_str} Len={payload_len}",
    ))
}

// ============================================================================
// SOME/IP endpoint pre-discovery
// ============================================================================

/// Scan parsed packets for SOME/IP-SD messages on the well-known SD port and
/// populate the file state with discovered SOME/IP endpoints.
fn pre_discover_someip_endpoints(lines: &[PcapLogLine], file_state: &PcapFileState) {
    let mut endpoints = Vec::new();
    for line in lines {
        let pi = &line.packet_info;
        if pi.protocol == "UDP"
            && (pi.src_port == Some(SOMEIP_SD_PORT) || pi.dst_port == Some(SOMEIP_SD_PORT))
        {
            if let Some(ref payload) = pi.transport_payload {
                if let Some(sd_info) = decode_someip_sd(payload) {
                    endpoints.extend(sd_info.endpoints);
                }
            }
        }
    }
    if !endpoints.is_empty() {
        tracing::info!(
            "Pre-discovered {} SOME/IP endpoints from SD messages",
            endpoints.len()
        );
        file_state.add_someip_endpoints(&endpoints);
    }
}

// ============================================================================
// Packet parsing helpers
// ============================================================================

fn parse_packet_data(data: &[u8], timestamp: DateTime<Local>) -> Option<PacketInfo> {
    profiling::scope!("parse_packet_data");
    if data.len() < 14 {
        return None;
    }
    let src_mac = format_mac(&data[6..12]);
    let dst_mac = format_mac(&data[0..6]);
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut payload_offset = 14;
    let mut vlan_id = None;
    if ethertype == 0x8100 && data.len() >= 18 {
        let tci = u16::from_be_bytes([data[14], data[15]]);
        vlan_id = Some(tci & 0x0FFF);
        ethertype = u16::from_be_bytes([data[16], data[17]]);
        payload_offset = 18;
    }
    let payload = &data[payload_offset..];
    match ethertype {
        0x0800 => {
            let mut pi = parse_ipv4_packet(payload, timestamp, vlan_id)?;
            pi.src_mac = Some(src_mac);
            pi.dst_mac = Some(dst_mac);
            Some(pi)
        }
        0x86DD => {
            let mut pi = parse_ipv6_packet(payload, timestamp, vlan_id)?;
            pi.src_mac = Some(src_mac);
            pi.dst_mac = Some(dst_mac);
            Some(pi)
        }
        0x0806 => Some(PacketInfo {
            timestamp,
            // For ARP the "addresses" are the MACs themselves; no separate MAC field.
            src_addr: src_mac,
            src_port: None,
            dst_addr: dst_mac,
            dst_port: None,
            src_mac: None,
            dst_mac: None,
            protocol: "ARP".to_string(),
            vlan_id,
            length: data.len() as u32,
            info: "ARP Request/Reply".to_string(),
            tcp_details: None,
            is_abnormal: false,
            transport_payload: None,
        }),
        _ => Some(PacketInfo {
            timestamp,
            src_addr: src_mac,
            src_port: None,
            dst_addr: dst_mac,
            dst_port: None,
            src_mac: None,
            dst_mac: None,
            protocol: format!("0x{ethertype:04x}"),
            vlan_id,
            length: data.len() as u32,
            info: String::new(),
            tcp_details: None,
            is_abnormal: false,
            transport_payload: None,
        }),
    }
}

fn format_mac(bytes: &[u8]) -> String {
    if bytes.len() >= 6 {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    } else {
        "??:??:??:??:??:??".to_string()
    }
}

fn parse_ipv4_packet(
    data: &[u8],
    timestamp: DateTime<Local>,
    vlan_id: Option<u16>,
) -> Option<PacketInfo> {
    profiling::scope!("parse_ipv4_packet");
    if data.len() < 20 {
        return None;
    }
    let ihl = (data[0] & 0x0F) as usize * 4;
    if data.len() < ihl {
        return None;
    }
    let protocol = data[9];
    let src_ip = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
    let dst_ip = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);
    let total_len = u16::from_be_bytes([data[2], data[3]]);
    let transport_data = &data[ihl..];
    let (proto_name, src_port, dst_port, info, tcp_details, transport_payload) = match protocol {
        6 => {
            let (p, sp, dp, i, td, payload) = parse_tcp_info(transport_data);
            (p, sp, dp, i, td, payload)
        }
        17 => {
            let (p, sp, dp, i, payload) = parse_udp_info(transport_data);
            (p, sp, dp, i, None, payload)
        }
        1 => (
            "ICMP".to_string(),
            None,
            None,
            parse_icmp_info(transport_data),
            None,
            None,
        ),
        _ => (
            format!("IP/{protocol}"),
            None,
            None,
            String::new(),
            None,
            None,
        ),
    };
    let is_abnormal = tcp_details
        .as_ref()
        .is_some_and(|tcp| tcp.flags & 0x04 != 0);
    Some(PacketInfo {
        timestamp,
        src_addr: src_ip,
        src_port,
        dst_addr: dst_ip,
        dst_port,
        src_mac: None,
        dst_mac: None,
        protocol: proto_name,
        vlan_id,
        length: u32::from(total_len),
        info,
        tcp_details,
        is_abnormal,
        transport_payload,
    })
}

fn parse_ipv6_packet(
    data: &[u8],
    timestamp: DateTime<Local>,
    vlan_id: Option<u16>,
) -> Option<PacketInfo> {
    profiling::scope!("parse_ipv6_packet");
    if data.len() < 40 {
        return None;
    }
    let next_header = data[6];
    let payload_len = u16::from_be_bytes([data[4], data[5]]);
    let src_ip = format_ipv6(&data[8..24]);
    let dst_ip = format_ipv6(&data[24..40]);
    let transport_data = &data[40..];
    let (proto_name, src_port, dst_port, info, tcp_details, transport_payload) = match next_header {
        6 => {
            let (p, sp, dp, i, td, payload) = parse_tcp_info(transport_data);
            (p, sp, dp, i, td, payload)
        }
        17 => {
            let (p, sp, dp, i, payload) = parse_udp_info(transport_data);
            (p, sp, dp, i, None, payload)
        }
        58 => ("ICMPv6".to_string(), None, None, String::new(), None, None),
        _ => (
            format!("IPv6/{next_header}"),
            None,
            None,
            String::new(),
            None,
            None,
        ),
    };
    let is_abnormal = tcp_details
        .as_ref()
        .is_some_and(|tcp| tcp.flags & 0x04 != 0);
    Some(PacketInfo {
        timestamp,
        src_addr: src_ip,
        src_port,
        dst_addr: dst_ip,
        dst_port,
        src_mac: None,
        dst_mac: None,
        protocol: proto_name,
        vlan_id,
        length: u32::from(payload_len) + 40,
        info,
        tcp_details,
        is_abnormal,
        transport_payload,
    })
}

fn format_ipv6(bytes: &[u8]) -> String {
    if bytes.len() >= 16 {
        let groups: Vec<String> = (0..8)
            .map(|i| {
                let val = u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
                format!("{val:x}")
            })
            .collect();
        groups.join(":")
    } else {
        "::".to_string()
    }
}

#[allow(
    clippy::type_complexity,
    reason = "the tuple is private and immediately destructured by its sole caller"
)]
fn parse_tcp_info(
    data: &[u8],
) -> (
    String,
    Option<u16>,
    Option<u16>,
    String,
    Option<TcpDetails>,
    Option<Vec<u8>>,
) {
    if data.len() < 20 {
        return ("TCP".to_string(), None, None, String::new(), None, None);
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = ((data[12] >> 4) & 0x0F) as usize * 4;
    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    let payload_len = if data.len() > data_offset {
        (data.len() - data_offset) as u32
    } else {
        0
    };
    let tcp_payload = if data.len() > data_offset {
        Some(data[data_offset..].to_vec())
    } else {
        None
    };
    let tcp_details = TcpDetails {
        seq,
        ack,
        flags,
        window,
        payload_len,
    };
    (
        "TCP".to_string(),
        Some(src_port),
        Some(dst_port),
        String::new(),
        Some(tcp_details),
        tcp_payload,
    )
}

fn parse_udp_info(data: &[u8]) -> (String, Option<u16>, Option<u16>, String, Option<Vec<u8>>) {
    if data.len() < 8 {
        return ("UDP".to_string(), None, None, String::new(), None);
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let payload = if data.len() > 8 {
        Some(data[8..].to_vec())
    } else {
        None
    };
    (
        "UDP".to_string(),
        Some(src_port),
        Some(dst_port),
        String::new(),
        payload,
    )
}

fn parse_icmp_info(data: &[u8]) -> String {
    if data.len() < 2 {
        return String::new();
    }
    match (data[0], data[1]) {
        (0, _) => "Echo Reply".to_string(),
        (8, _) => "Echo Request".to_string(),
        (3, 0) => "Dest Unreachable (Net)".to_string(),
        (3, 1) => "Dest Unreachable (Host)".to_string(),
        (3, 3) => "Dest Unreachable (Port)".to_string(),
        (11, _) => "Time Exceeded".to_string(),
        (t, c) => format!("Type={t} Code={c}"),
    }
}

fn pcap_ts_to_datetime(sec: u32, usec: u32) -> Option<DateTime<Local>> {
    Local.timestamp_opt(i64::from(sec), usec * 1000).single()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PcapFormat {
    Legacy,
    PcapNG,
}

fn detect_pcap_format(path: &Path) -> anyhow::Result<PcapFormat> {
    use anyhow::Context as _;
    use std::io::Read;
    let mut file =
        File::open(path).with_context(|| format!("Failed to open file: {}", path.display()))?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)
        .context("Failed to read magic")?;
    match &magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => Ok(PcapFormat::Legacy),
        [0xa1, 0xb2, 0xc3, 0xd4] => Ok(PcapFormat::Legacy),
        [0x4d, 0x3c, 0xb2, 0xa1] => Ok(PcapFormat::Legacy),
        [0xa1, 0xb2, 0x3c, 0x4d] => Ok(PcapFormat::Legacy),
        [0x0a, 0x0d, 0x0d, 0x0a] => Ok(PcapFormat::PcapNG),
        _ => Err(anyhow::anyhow!("Unknown pcap format")),
    }
}

/// Parse all packets from a pcap/pcapng file and return them as typed log lines.
///
/// # Errors
///
/// Returns an error when the capture cannot be opened, decoded, or parsed.
pub fn parse_pcap_to_lines<P: AsRef<Path>>(path: P) -> anyhow::Result<Vec<PcapLogLine>> {
    let path = path.as_ref();
    let format = detect_pcap_format(path)?;
    let lines = match format {
        PcapFormat::Legacy => parse_legacy_pcap_to_lines(path),
        PcapFormat::PcapNG => parse_pcapng_to_lines(path),
    }?;
    if lines.is_empty() {
        return Err(anyhow::anyhow!("No valid packets found in pcap file"));
    }
    Ok(lines)
}

fn parse_legacy_pcap_to_lines(path: &Path) -> anyhow::Result<Vec<PcapLogLine>> {
    profiling::scope!("parse_legacy_pcap_to_lines");
    use anyhow::Context as _;
    tracing::info!("Starting legacy pcap parsing: {}", path.display());
    let file = File::open(path)
        .with_context(|| format!("Failed to open pcap file: {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut pcap_reader = LegacyPcapReader::new(65536, reader)
        .map_err(|e| anyhow::anyhow!("Failed to create pcap reader: {e:?}"))?;
    let mut lines = Vec::new();
    let mut line_number = 1usize;
    let mut flow_tracker = TcpFlowTracker::new();
    loop {
        match pcap_reader.next() {
            Ok((offset, block)) => {
                if let PcapBlockOwned::Legacy(packet) = block {
                    let timestamp = pcap_ts_to_datetime(packet.ts_sec, packet.ts_usec)
                        .unwrap_or_else(Local::now);
                    if let Some(mut packet_info) = parse_packet_data(packet.data, timestamp) {
                        flow_tracker.analyze_packet(&mut packet_info);
                        lines.push(PcapLogLine::new(packet_info, line_number));
                        line_number += 1;
                    }
                }
                if !lines.is_empty() && lines.len() % 10_000 == 0 {
                    flow_tracker.cleanup(10_000);
                }
                pcap_reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                pcap_reader
                    .refill()
                    .map_err(|e| anyhow::anyhow!("Read error: {e}"))?;
            }
            Err(e) => {
                tracing::warn!("Pcap parse error: {e:?}");
                break;
            }
        }
    }
    tracing::info!("Parsed {} legacy pcap packets", lines.len());
    Ok(lines)
}

fn parse_pcapng_to_lines(path: &Path) -> anyhow::Result<Vec<PcapLogLine>> {
    profiling::scope!("parse_pcapng_to_lines");
    use anyhow::Context as _;
    tracing::info!("Starting pcapng parsing: {}", path.display());
    let file = File::open(path)
        .with_context(|| format!("Failed to open pcapng file: {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut pcap_reader = PcapNGReader::new(65536, reader)
        .map_err(|e| anyhow::anyhow!("Failed to create pcapng reader: {e:?}"))?;
    let mut lines = Vec::new();
    let mut line_number = 1usize;
    let mut if_tsresol: u64 = 1_000_000;
    let mut flow_tracker = TcpFlowTracker::new();
    loop {
        match pcap_reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::NG(pcap_parser::Block::InterfaceDescription(idb)) => {
                        for opt in &idb.options {
                            if opt.code.0 == 9 && !opt.value.is_empty() {
                                let resol = opt.value[0];
                                if_tsresol = if resol & 0x80 != 0 {
                                    1u64 << (resol & 0x7F)
                                } else {
                                    10u64.pow(u32::from(resol))
                                };
                            }
                        }
                    }
                    PcapBlockOwned::NG(pcap_parser::Block::EnhancedPacket(epb)) => {
                        let ts_raw = (u64::from(epb.ts_high) << 32) | u64::from(epb.ts_low);
                        let sec = ts_raw / if_tsresol;
                        let nsec = ((ts_raw % if_tsresol) * 1_000_000_000) / if_tsresol;
                        let timestamp = Local
                            .timestamp_opt(sec.cast_signed(), nsec as u32)
                            .single()
                            .unwrap_or_else(Local::now);
                        if let Some(mut packet_info) = parse_packet_data(epb.data, timestamp) {
                            flow_tracker.analyze_packet(&mut packet_info);
                            lines.push(PcapLogLine::new(packet_info, line_number));
                            line_number += 1;
                        }
                    }
                    PcapBlockOwned::NG(pcap_parser::Block::SimplePacket(spb)) => {
                        let timestamp = Local::now();
                        if let Some(mut packet_info) = parse_packet_data(spb.data, timestamp) {
                            flow_tracker.analyze_packet(&mut packet_info);
                            lines.push(PcapLogLine::new(packet_info, line_number));
                            line_number += 1;
                        }
                    }
                    PcapBlockOwned::NG(_)
                    | PcapBlockOwned::Legacy(_)
                    | PcapBlockOwned::LegacyHeader(_) => {}
                }
                if !lines.is_empty() && lines.len() % 10_000 == 0 {
                    flow_tracker.cleanup(10_000);
                }
                pcap_reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                pcap_reader
                    .refill()
                    .map_err(|e| anyhow::anyhow!("Read error: {e}"))?;
            }
            Err(e) => {
                tracing::warn!("Pcapng parse error: {e:?}");
                break;
            }
        }
    }
    tracing::info!("Parsed {} pcapng packets", lines.len());
    Ok(lines)
}
