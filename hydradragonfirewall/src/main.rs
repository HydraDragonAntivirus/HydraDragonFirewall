use eframe::egui;
use windivert::prelude::*;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread;
use std::time::{Duration, SystemTime};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;

// ============================================================================
mod injector;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

#[derive(Clone, Debug, PartialEq)]
enum Protocol {
    TCP,
    UDP,
    ICMP,
    Raw(u8),
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct PacketInfo {
    timestamp: SystemTime,
    protocol: Protocol,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    size: usize,
    outbound: bool,
    process_id: u32,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct DnsQuery {
    timestamp: SystemTime,
    domain: String,
    blocked: bool,
}

#[derive(Clone, Debug, PartialEq)]
enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct LogEntry {
    timestamp: SystemTime,
    level: LogLevel,
    message: String,
}

// ============================================================================
// APPLICATION TRACKING
// ============================================================================

#[derive(Clone, Debug, PartialEq)]
enum AppDecision {
    Pending,
    Allow,
    Block,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct PendingApp {
    process_id: u32,
    name: String,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    protocol: Protocol,
}

// ============================================================================
// FIREWALL RULES
// ============================================================================

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct FirewallRule {
    name: String,
    enabled: bool,
    block: bool,
    protocol: Option<Protocol>,
    dst_port: Option<u16>,
    app_name: Option<String>,
}

impl FirewallRule {
    fn matches(&self, packet: &PacketInfo) -> bool {
        if !self.enabled {
            return false;
        }

        if let Some(ref proto) = self.protocol {
            if proto != &packet.protocol {
                return false;
            }
        }

        if let Some(port) = self.dst_port {
            if port != packet.dst_port {
                return false;
            }
        }

        true
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

struct Statistics {
    packets_total: AtomicU64,
    packets_blocked: AtomicU64,
    packets_allowed: AtomicU64,
    icmp_blocked: AtomicU64,
    dns_queries: AtomicU64,
    dns_blocked: AtomicU64,
    tcp_connections: AtomicU64,
}

impl Default for Statistics {
    fn default() -> Self {
        Self {
            packets_total: AtomicU64::new(0),
            packets_blocked: AtomicU64::new(0),
            packets_allowed: AtomicU64::new(0),
            icmp_blocked: AtomicU64::new(0),
            dns_queries: AtomicU64::new(0),
            dns_blocked: AtomicU64::new(0),
            tcp_connections: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// DNS HANDLER
// ============================================================================

struct DnsHandler {
    queries: RwLock<VecDeque<DnsQuery>>,
    blocked_domains: RwLock<HashSet<String>>,
}

impl DnsHandler {
    fn new() -> Self {
        let mut blocked = HashSet::new();
        blocked.insert("malware".to_string());
        blocked.insert("virus".to_string());
        blocked.insert("trojan".to_string());
        blocked.insert("hack".to_string());
        blocked.insert("exploit".to_string());
        blocked.insert("phish".to_string());
        
        Self {
            queries: RwLock::new(VecDeque::new()),
            blocked_domains: RwLock::new(blocked),
        }
    }

    fn should_block(&self, domain: &str) -> bool {
        let blocked = self.blocked_domains.read().unwrap();
        let domain_lower = domain.to_lowercase();
        
        for pattern in blocked.iter() {
            if domain_lower.contains(pattern) {
                return true;
            }
        }
        false
    }

    fn log_query(&self, domain: String, blocked: bool) {
        let mut queries = self.queries.write().unwrap();
        queries.push_back(DnsQuery {
            timestamp: SystemTime::now(),
            domain,
            blocked,
        });
        if queries.len() > 500 {
            queries.pop_front();
        }
    }

    fn get_recent(&self) -> Vec<DnsQuery> {
        let queries = self.queries.read().unwrap();
        queries.iter().rev().take(20).cloned().collect()
    }
}

// ============================================================================
// APPLICATION MANAGER
// ============================================================================

struct AppManager {
    decisions: RwLock<HashMap<String, AppDecision>>,
    pending: RwLock<VecDeque<PendingApp>>,
    known_apps: RwLock<HashSet<String>>,
    port_map: RwLock<HashMap<u16, u32>>,
}

impl AppManager {
    fn new() -> Self {
        let mut decisions = HashMap::new();
        // Pre-approve system processes
        decisions.insert("system".to_string(), AppDecision::Allow);
        decisions.insert("svchost.exe".to_string(), AppDecision::Allow);
        decisions.insert("dns.exe".to_string(), AppDecision::Allow);
        decisions.insert("services.exe".to_string(), AppDecision::Allow);
        decisions.insert("lsass.exe".to_string(), AppDecision::Allow);
        decisions.insert("wininit.exe".to_string(), AppDecision::Allow);
        decisions.insert("csrss.exe".to_string(), AppDecision::Allow);
        
        Self {
            decisions: RwLock::new(decisions),
            pending: RwLock::new(VecDeque::new()),
            known_apps: RwLock::new(HashSet::new()),
            port_map: RwLock::new(HashMap::new()),
        }
    }

    fn update_port_mapping(&self, port: u16, pid: u32) {
        if port == 0 || pid == 0 { return; }
        let mut map = self.port_map.write().unwrap();
        map.insert(port, pid);
    }
    
    fn get_pid_for_port(&self, port: u16) -> Option<u32> {
        self.port_map.read().unwrap().get(&port).cloned()
    }

    fn get_app_name(process_id: u32) -> String {
        if process_id == 0 || process_id == 4 {
            return "System".to_string();
        }

        #[cfg(windows)]
        {
            use std::ffi::OsString;
            use std::os::windows::ffi::OsStringExt;
            
            unsafe {
                let handle = OpenProcess(0x0400 | 0x0010, 0, process_id);
                if !handle.is_null() {
                    let mut buffer: [u16; 260] = [0; 260];
                    let mut size = 260u32;
                    if QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) != 0 {
                        CloseHandle(handle);
                        let path = OsString::from_wide(&buffer[..size as usize]);
                        if let Some(path_str) = path.to_str() {
                            if let Some(name) = std::path::Path::new(path_str).file_name() {
                                return name.to_string_lossy().to_string();
                            }
                        }
                    }
                    CloseHandle(handle);
                }
            }
        }
        
        format!("PID:{}", process_id)
    }

    fn check_app(&self, packet: &PacketInfo) -> AppDecision {
        let mut pid = packet.process_id;
        
        // If PID is 0 (from NETWORK layer), try to resolve via port mapping
        if pid == 0 {
            if packet.outbound {
                // Outbound: src_port is local
                if let Some(p) = self.get_pid_for_port(packet.src_port) {
                    pid = p;
                }
            } else {
                // Inbound: dst_port is local
                if let Some(p) = self.get_pid_for_port(packet.dst_port) {
                    pid = p;
                }
            }
        }
        
        let app_name = Self::get_app_name(pid).to_lowercase();
        
        // Check if we have a decision
        {
            let decisions = self.decisions.read().unwrap();
            if let Some(decision) = decisions.get(&app_name) {
                return decision.clone();
            }
        }
        
        // Check if already pending
        {
            let known = self.known_apps.read().unwrap();
            if known.contains(&app_name) {
                return AppDecision::Pending;
            }
        }
        
        // New app - add to pending
        {
            let mut known = self.known_apps.write().unwrap();
            known.insert(app_name.clone());
        }
        
        {
            let mut pending = self.pending.write().unwrap();
            pending.push_back(PendingApp {
                process_id: pid,
                name: Self::get_app_name(pid),
                dst_ip: packet.dst_ip,
                dst_port: packet.dst_port,
                protocol: packet.protocol.clone(),
            });
        }
        
        AppDecision::Pending
    }

    fn set_decision(&self, app_name: &str, decision: AppDecision) {
        let name_lower = app_name.to_lowercase();
        
        {
            let mut decisions = self.decisions.write().unwrap();
            decisions.insert(name_lower.clone(), decision);
        }
        
        {
            let mut pending = self.pending.write().unwrap();
            pending.retain(|p| p.name.to_lowercase() != name_lower);
        }
    }

    fn get_pending(&self) -> Vec<PendingApp> {
        self.pending.read().unwrap().iter().cloned().collect()
    }

    fn pending_count(&self) -> usize {
        self.pending.read().unwrap().len()
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut std::ffi::c_void;
    fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    fn QueryFullProcessImageNameW(hProcess: *mut std::ffi::c_void, dwFlags: u32, lpExeName: *mut u16, lpdwSize: *mut u32) -> i32;
}

// ============================================================================
// PACKET PARSER
// ============================================================================

fn parse_packet(data: &[u8], outbound: bool, process_id: u32) -> Option<PacketInfo> {
    if data.len() < 20 {
        return None;
    }

    let ip_version = (data[0] >> 4) & 0x0F;
    if ip_version != 4 {
        return None;
    }

    let protocol_num = data[9];
    let protocol = match protocol_num {
        6 => Protocol::TCP,
        17 => Protocol::UDP,
        1 => Protocol::ICMP,
        n => Protocol::Raw(n),
    };

    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let ip_header_len = ((data[0] & 0x0F) as usize) * 4;

    let (src_port, dst_port) = if ip_header_len + 4 <= data.len() {
        match protocol {
            Protocol::TCP | Protocol::UDP => {
                let src = u16::from_be_bytes([data[ip_header_len], data[ip_header_len + 1]]);
                let dst = u16::from_be_bytes([data[ip_header_len + 2], data[ip_header_len + 3]]);
                (src, dst)
            },
            _ => (0, 0),
        }
    } else {
        (0, 0)
    };

    Some(PacketInfo {
        timestamp: SystemTime::now(),
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        size: data.len(),
        outbound,
        process_id,
    })
}

fn parse_dns_query(data: &[u8], offset: usize) -> Option<String> {
    let mut domain = String::new();
    let mut pos = offset + 12;
    
    if pos >= data.len() {
        return None;
    }

    loop {
        if pos >= data.len() {
            return None;
        }
        
        let len = data[pos] as usize;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        
        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        
        if !domain.is_empty() {
            domain.push('.');
        }
        
        for i in 0..len {
            if pos + i < data.len() {
                let c = data[pos + i];
                if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' {
                    domain.push(c as char);
                }
            }
        }
        
        pos += len;
    }

    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

// ============================================================================
// FIREWALL ENGINE
// ============================================================================

enum EngineMessage {
    Log(LogLevel, String),
    PacketBlocked(PacketInfo, String),
    DnsBlocked(String),
    StatsUpdate,
    NewPendingApp(PendingApp),
}

struct FirewallEngine {
    stats: Arc<Statistics>,
    rules: Arc<RwLock<Vec<FirewallRule>>>,
    dns_handler: Arc<DnsHandler>,
    app_manager: Arc<AppManager>,
    stop_signal: Arc<AtomicBool>,
}

impl FirewallEngine {
    fn new() -> Self {
        let mut default_rules = Vec::new();
        
        default_rules.push(FirewallRule {
            name: "Block ICMP (Ping)".to_string(),
            enabled: true,
            block: true,
            protocol: Some(Protocol::ICMP),
            dst_port: None,
            app_name: None,
        });

        default_rules.push(FirewallRule {
            name: "Block Raw Sockets".to_string(),
            enabled: true,
            block: true,
            protocol: Some(Protocol::Raw(255)),
            dst_port: None,
            app_name: None,
        });

        Self {
            stats: Arc::new(Statistics::default()),
            rules: Arc::new(RwLock::new(default_rules)),
            dns_handler: Arc::new(DnsHandler::new()),
            app_manager: Arc::new(AppManager::new()),
            stop_signal: Arc::new(AtomicBool::new(false)),
        }
    }

    fn start(&self, tx: Sender<EngineMessage>) {
        let stats = Arc::clone(&self.stats);
        let rules = Arc::clone(&self.rules);
        let dns_handler = Arc::clone(&self.dns_handler);
        let app_manager = Arc::clone(&self.app_manager);
        let stop = Arc::clone(&self.stop_signal);

        // ====================================================================
        // SOCKET LAYER MONITOR (for PID tracking)
        // ====================================================================
        let am_socket = Arc::clone(&self.app_manager);
        let stop_socket = Arc::clone(&self.stop_signal);
        thread::spawn(move || {
            // Setup flags separately to avoid builder chaining type issues
            let flags = WinDivertFlags::new();
            flags.set_sniff();
            flags.set_recv_only();
            let handle_result = WinDivert::socket("true", 0, flags);
            
            if let Ok(handle) = handle_result {
                while !stop_socket.load(Ordering::Relaxed) {
                    // Socket layer has no data payload, so recv_ex likely takes batch size (usize)
                    // based on build error "expected usize"
                    if let Ok(packets) = handle.recv_ex(10) {
                        for packet in packets {
                            // Extract PID and Port from socket event
                            // Address type for SocketLayer should have these methods
                            let addr = &packet.address;
                            let pid = addr.process_id(); 
                            let port = addr.local_port();
                            
                            if pid > 0 && port > 0 {
                                am_socket.update_port_mapping(port, pid);
                            }
                        }
                    } else {
                        // Short sleep on error/empty to prevent tight loop if failing
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        });

        // ====================================================================
        // FLOW LAYER MONITOR (for Connection PID tracking)
        // ====================================================================
        let am_flow = Arc::clone(&self.app_manager);
        let stop_flow = Arc::clone(&self.stop_signal);
        thread::spawn(move || {
            let flags = WinDivertFlags::new();
            flags.set_sniff();
            flags.set_recv_only();
            let handle_result = WinDivert::flow("true", 0, flags);
            
            if let Ok(handle) = handle_result {
                while !stop_flow.load(Ordering::Relaxed) {
                    if let Ok(packets) = handle.recv_ex(10) {
                        for packet in packets {
                            let addr = &packet.address;
                            let pid = addr.process_id();
                            let port = addr.local_port();
                            
                            if pid > 0 && port > 0 {
                                am_flow.update_port_mapping(port, pid);
                            }
                        }
                    } else {
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        });

        // ====================================================================
        // NAMED PIPE SERVER (IPC for Hooked DLLs)
        // ====================================================================
        let _am_pipe = Arc::clone(&self.app_manager);
        let log_tx_pipe = tx.clone();
        
        thread::spawn(move || {
            use windows::Win32::System::Pipes::{CreateNamedPipeA, ConnectNamedPipe, DisconnectNamedPipe};
            use windows::Win32::Foundation::CloseHandle;
            
            let pipe_name = windows::core::s!("\\\\.\\pipe\\HydraDragonFirewall");
            
            loop {
                unsafe {
                    // Manual constants
                    const PIPE_ACCESS_DUPLEX: u32 = 3;
                    const PIPE_TYPE_MESSAGE: u32 = 4;
                    const PIPE_READMODE_MESSAGE: u32 = 2;
                    const PIPE_WAIT: u32 = 0;
                    const PIPE_UNLIMITED_INSTANCES: u32 = 255;

                    // Use transmute to coerce u32 into required newtypes
                    let pipe_handle_res = CreateNamedPipeA(
                        pipe_name,
                        std::mem::transmute(PIPE_ACCESS_DUPLEX),
                        std::mem::transmute(PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT),
                        PIPE_UNLIMITED_INSTANCES,
                        512,
                        512,
                        0,
                        None
                    );
                    
                    if let Ok(pipe_handle) = pipe_handle_res {
                        if !pipe_handle.is_invalid() {
                            // Connect
                            let connect_res = ConnectNamedPipe(pipe_handle, None);
                            let mut connected = false;
                            
                            if connect_res.is_ok() {
                                connected = true;
                            } else {
                                let err = connect_res.unwrap_err();
                                // Check for ERROR_PIPE_CONNECTED
                                if err.code() == windows::core::HRESULT::from_win32(windows::Win32::Foundation::ERROR_PIPE_CONNECTED.0) {
                                     connected = true;
                                }
                            }

                            if connected {
                                 let mut buffer = [0u8; 512];
                                 let mut bytes_read = 0;
                                 let read_res = windows::Win32::Storage::FileSystem::ReadFile(
                                     pipe_handle,
                                     Some(&mut buffer),
                                     Some(&mut bytes_read),
                                     None
                                 );
                                 
                                 if read_res.is_ok() && bytes_read > 0 {
                                     let msg = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
                                     let _ = log_tx_pipe.send(EngineMessage::Log(LogLevel::Info, format!("🪝 HOOK: {}", msg)));
                                 }
                                 
                                 let _ = DisconnectNamedPipe(pipe_handle);
                            }
                            let _ = CloseHandle(pipe_handle);
                        } else {
                            thread::sleep(Duration::from_millis(100)); // Error backoff
                        }
                    } else {
                         thread::sleep(Duration::from_millis(100)); // Creation failed
                    }
                }
            }
        });

        // ====================================================================
        // NETWORK LAYER (Main Firewall Logic)
        // ====================================================================
        thread::spawn(move || {
            let _ = tx.send(EngineMessage::Log(LogLevel::Info, 
                "Initializing WinDivert network driver...".into()));

            let filter = "ip";
            let handle = match WinDivert::network(filter, 1000, WinDivertFlags::new()) {
                Ok(h) => {
                    let _ = tx.send(EngineMessage::Log(LogLevel::Success,
                        "✅ WinDivert driver initialized".into()));
                    let _ = tx.send(EngineMessage::Log(LogLevel::Success,
                        "✅ Application-level filtering active".into()));
                    h
                },
                Err(e) => {
                    let _ = tx.send(EngineMessage::Log(LogLevel::Error,
                        format!("❌ WinDivert error: {}\n⚠️ Must run as Administrator!", e)));
                    return;
                }
            };

            let mut buffer = vec![0u8; 65535];
            let mut counter = 0u64;

            let _ = tx.send(EngineMessage::Log(LogLevel::Success,
                "🔥 Firewall protection ACTIVE".into()));

            while !stop.load(Ordering::Relaxed) {
                let recv_result = handle.recv_ex(Some(&mut buffer), 0);
                
                let packets = match recv_result {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                for packet in packets {
                    counter += 1;
                    stats.packets_total.fetch_add(1, Ordering::Relaxed);

                    let data = &packet.data;
                    let addr = &packet.address;
                    let outbound = addr.outbound();
                    // Use 0 as fallback - process_id may not be available in this windivert version
                    let process_id: u32 = 0;

                    let packet_info = match parse_packet(data, outbound, process_id) {
                        Some(p) => p,
                        None => {
                            stats.packets_blocked.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };

                    let mut should_block = false;
                    let mut block_reason = String::new();
                    let app_name = AppManager::get_app_name(process_id);

                    // Check application-level decision for outbound
                    if outbound {
                        let decision = app_manager.check_app(&packet_info);
                        match decision {
                            AppDecision::Block => {
                                should_block = true;
                                block_reason = format!("App blocked: {}", app_name);
                            },
                            AppDecision::Pending => {
                                should_block = true;
                                block_reason = format!("App pending: {}", app_name);
                                let pending = app_manager.get_pending();
                                if let Some(p) = pending.last() {
                                    let _ = tx.send(EngineMessage::NewPendingApp(p.clone()));
                                }
                            },
                            AppDecision::Allow => {}
                        }
                    }

                    // DNS analysis
                    if !should_block && packet_info.protocol == Protocol::UDP && packet_info.dst_port == 53 && outbound {
                        stats.dns_queries.fetch_add(1, Ordering::Relaxed);
                        let ip_hdr_len = ((data[0] & 0x0F) as usize) * 4;
                        let dns_offset = ip_hdr_len + 8;
                        
                        if let Some(domain) = parse_dns_query(data, dns_offset) {
                            if dns_handler.should_block(&domain) {
                                should_block = true;
                                block_reason = format!("Blocked DNS: {}", domain);
                                stats.dns_blocked.fetch_add(1, Ordering::Relaxed);
                                dns_handler.log_query(domain.clone(), true);
                                let _ = tx.send(EngineMessage::DnsBlocked(domain));
                            } else {
                                dns_handler.log_query(domain, false);
                            }
                        }
                    }

                    // Apply firewall rules
                    if !should_block {
                        let rules_guard = rules.read().unwrap();
                        for rule in rules_guard.iter() {
                            if rule.matches(&packet_info) && rule.block {
                                should_block = true;
                                block_reason = format!("Rule: {}", rule.name);
                                break;
                            }
                        }
                    }

                    // Update stats
                    match packet_info.protocol {
                        Protocol::TCP => { stats.tcp_connections.fetch_add(1, Ordering::Relaxed); },
                        Protocol::ICMP if should_block => { stats.icmp_blocked.fetch_add(1, Ordering::Relaxed); },
                        _ => {}
                    };

                    if should_block {
                        stats.packets_blocked.fetch_add(1, Ordering::Relaxed);
                        let _ = tx.send(EngineMessage::PacketBlocked(packet_info, block_reason));
                    } else {
                        stats.packets_allowed.fetch_add(1, Ordering::Relaxed);
                        let _ = handle.send(&packet);
                    }

                    if counter % 100 == 0 {
                        let _ = tx.send(EngineMessage::StatsUpdate);
                    }
                }
            }

            let _ = tx.send(EngineMessage::Log(LogLevel::Info, "Engine stopped".into()));
        });
    }

    fn stop(&self) {
        self.stop_signal.store(true, Ordering::Relaxed);
    }

    fn get_stats(&self) -> (u64, u64, u64, u64, u64, u64, u64) {
        (
            self.stats.packets_total.load(Ordering::Relaxed),
            self.stats.packets_blocked.load(Ordering::Relaxed),
            self.stats.packets_allowed.load(Ordering::Relaxed),
            self.stats.dns_queries.load(Ordering::Relaxed),
            self.stats.dns_blocked.load(Ordering::Relaxed),
            self.stats.icmp_blocked.load(Ordering::Relaxed),
            self.stats.tcp_connections.load(Ordering::Relaxed),
        )
    }

    #[allow(dead_code)]
    fn get_rules(&self) -> Vec<FirewallRule> {
        self.rules.read().unwrap().clone()
    }

    fn get_dns_queries(&self) -> Vec<DnsQuery> {
        self.dns_handler.get_recent()
    }

    fn allow_app(&self, app_name: &str) {
        self.app_manager.set_decision(app_name, AppDecision::Allow);
    }

    fn block_app(&self, app_name: &str) {
        self.app_manager.set_decision(app_name, AppDecision::Block);
    }

    fn get_pending_apps(&self) -> Vec<PendingApp> {
        self.app_manager.get_pending()
    }

    fn pending_count(&self) -> usize {
        self.app_manager.pending_count()
    }
}

// ============================================================================
// GUI APPLICATION
// ============================================================================

struct FirewallApp {
    engine: Option<Arc<FirewallEngine>>,
    rx: Option<Receiver<EngineMessage>>,
    running: bool,
    
    logs: VecDeque<LogEntry>,
    blocked_packets: VecDeque<(PacketInfo, String)>,
    
    total: u64,
    blocked: u64,
    allowed: u64,
    dns_queries: u64,
    dns_blocked: u64,
    icmp_blocked: u64,
    tcp_conns: u64,
    
    tab: usize,
    show_app_prompt: bool,
    current_pending_app: Option<PendingApp>,
}

impl Default for FirewallApp {
    fn default() -> Self {
        Self {
            engine: None,
            rx: None,
            running: false,
            logs: VecDeque::new(),
            blocked_packets: VecDeque::new(),
            total: 0,
            blocked: 0,
            allowed: 0,
            dns_queries: 0,
            dns_blocked: 0,
            icmp_blocked: 0,
            tcp_conns: 0,
            tab: 0,
            show_app_prompt: false,
            current_pending_app: None,
        }
    }
}

impl FirewallApp {
    fn start(&mut self) {
        if self.running { return; }

        let (tx, rx) = channel();
        let engine = Arc::new(FirewallEngine::new());
        engine.start(tx);
        
        self.engine = Some(engine);
        self.rx = Some(rx);
        self.running = true;
    }

    fn stop(&mut self) {
        if !self.running { return; }
        if let Some(engine) = &self.engine {
            engine.stop();
        }
        self.running = false;
        self.add_log(LogLevel::Info, "Firewall stopped".into());
    }

    fn add_log(&mut self, level: LogLevel, message: String) {
        self.logs.push_back(LogEntry {
            timestamp: SystemTime::now(),
            level,
            message,
        });
        if self.logs.len() > 1000 {
            self.logs.pop_front();
        }
    }

    fn process_messages(&mut self) {
        // Collect messages first to avoid borrow conflict
        let messages: Vec<EngineMessage> = if let Some(rx) = &self.rx {
            let mut msgs = Vec::new();
            while let Ok(msg) = rx.try_recv() {
                msgs.push(msg);
            }
            msgs
        } else {
            Vec::new()
        };

        for msg in messages {
            match msg {
                EngineMessage::Log(level, message) => {
                    self.add_log(level, message);
                },
                EngineMessage::PacketBlocked(packet, reason) => {
                    self.blocked_packets.push_back((packet, reason));
                    if self.blocked_packets.len() > 200 {
                        self.blocked_packets.pop_front();
                    }
                },
                EngineMessage::DnsBlocked(domain) => {
                    self.add_log(LogLevel::Warning, format!("🚫 Blocked DNS: {}", domain));
                },
                EngineMessage::StatsUpdate => {
                    if let Some(engine) = &self.engine {
                        let (t, b, a, dq, db, ib, tc) = engine.get_stats();
                        self.total = t;
                        self.blocked = b;
                        self.allowed = a;
                        self.dns_queries = dq;
                        self.dns_blocked = db;
                        self.icmp_blocked = ib;
                        self.tcp_conns = tc;
                    }
                },
                EngineMessage::NewPendingApp(app) => {
                    if self.current_pending_app.is_none() {
                        self.current_pending_app = Some(app);
                        self.show_app_prompt = true;
                    }
                },
            }
        }
    }
}

impl eframe::App for FirewallApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_messages();
        ctx.request_repaint_after(Duration::from_millis(200));

        // Application permission dialog
        if self.show_app_prompt {
            if let Some(app) = self.current_pending_app.clone() {
                egui::Window::new("🔒 Application Access Request")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.add_space(10.0);
                            ui.label(egui::RichText::new("An application is requesting network access:")
                                .size(14.0));
                            ui.add_space(15.0);
                            
                            egui::Frame::new()
                                .fill(egui::Color32::from_gray(40))
                                .corner_radius(8.0)
                                .inner_margin(15.0)
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new("📦").size(32.0));
                                        ui.label(egui::RichText::new(&app.name)
                                            .size(18.0).strong().color(egui::Color32::WHITE));
                                    });
                                });
                            
                            ui.add_space(15.0);
                            ui.horizontal(|ui| {
                                ui.label("Destination:");
                                ui.label(egui::RichText::new(format!("{}:{}", app.dst_ip, app.dst_port))
                                    .color(egui::Color32::LIGHT_BLUE));
                            });
                            
                            ui.add_space(20.0);
                            ui.horizontal(|ui| {
                                if ui.add_sized([120.0, 40.0], 
                                    egui::Button::new(egui::RichText::new("✅ Allow").size(16.0).color(egui::Color32::WHITE))
                                        .fill(egui::Color32::from_rgb(34, 197, 94))
                                ).clicked() {
                                    if let Some(engine) = &self.engine {
                                        engine.allow_app(&app.name);
                                    }
                                    self.add_log(LogLevel::Success, format!("✅ Allowed: {}", app.name));
                                    self.show_app_prompt = false;
                                    self.current_pending_app = None;
                                }
                                
                                ui.add_space(20.0);
                                
                                if ui.add_sized([120.0, 40.0],
                                    egui::Button::new(egui::RichText::new("🚫 Block").size(16.0).color(egui::Color32::WHITE))
                                        .fill(egui::Color32::from_rgb(220, 38, 38))
                                ).clicked() {
                                    if let Some(engine) = &self.engine {
                                        engine.block_app(&app.name);
                                    }
                                    self.add_log(LogLevel::Warning, format!("🚫 Blocked: {}", app.name));
                                    self.show_app_prompt = false;
                                    self.current_pending_app = None;
                                }
                            });
                        });
                    });
            }
        }

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("🛡️ HydraDragon Firewall");
                ui.separator();
                
                let (text, _color) = if self.running {
                    ("⏹ Stop", egui::Color32::from_rgb(220, 38, 38))
                } else {
                    ("▶ Start", egui::Color32::from_rgb(34, 197, 94))
                };
                
                if ui.button(egui::RichText::new(text).color(egui::Color32::WHITE)).clicked() {
                    if self.running { self.stop(); } else { self.start(); }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let pending = self.engine.as_ref().map(|e| e.pending_count()).unwrap_or(0);
                    if pending > 0 {
                        ui.label(egui::RichText::new(format!("⏳ {} apps pending", pending))
                            .color(egui::Color32::YELLOW));
                        ui.separator();
                    }
                    
                    if self.running {
                        ui.label(egui::RichText::new("● ACTIVE").color(egui::Color32::GREEN).strong());
                    } else {
                        ui.label(egui::RichText::new("● STOPPED").color(egui::Color32::RED).strong());
                    }
                });
            });
        });

        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, 0, "📊 Dashboard");
                ui.selectable_value(&mut self.tab, 1, "📱 Applications");
                ui.selectable_value(&mut self.tab, 2, "🚫 Blocked");
                ui.selectable_value(&mut self.tab, 3, "📋 Logs");
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.tab {
                0 => self.show_dashboard(ui),
                1 => self.show_applications(ui),
                2 => self.show_blocked(ui),
                3 => self.show_logs(ui),
                _ => {},
            }
        });
    }
}

impl FirewallApp {
    fn show_dashboard(&self, ui: &mut egui::Ui) {
        ui.heading("Statistics");
        ui.add_space(10.0);

        egui::Grid::new("stats").num_columns(4).spacing([15.0, 15.0]).show(ui, |ui| {
            self.stat_box(ui, "Total Packets", self.total, egui::Color32::LIGHT_BLUE);
            self.stat_box(ui, "Blocked", self.blocked, egui::Color32::RED);
            self.stat_box(ui, "Allowed", self.allowed, egui::Color32::GREEN);
            self.stat_box(ui, "TCP Connections", self.tcp_conns, egui::Color32::YELLOW);
            ui.end_row();

            self.stat_box(ui, "DNS Queries", self.dns_queries, egui::Color32::LIGHT_BLUE);
            self.stat_box(ui, "DNS Blocked", self.dns_blocked, egui::Color32::RED);
            self.stat_box(ui, "ICMP Blocked", self.icmp_blocked, egui::Color32::RED);
            let block_rate = if self.total > 0 {
                (self.blocked as f32 / self.total as f32 * 100.0) as u64
            } else { 0 };
            self.stat_box(ui, "Block Rate %", block_rate, egui::Color32::YELLOW);
        });

        ui.add_space(20.0);
        ui.separator();

        if let Some(engine) = &self.engine {
            ui.heading("Recent DNS Queries");
            egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                for query in engine.get_dns_queries() {
                    let color = if query.blocked { egui::Color32::RED } else { egui::Color32::GREEN };
                    ui.horizontal(|ui| {
                        ui.colored_label(color, if query.blocked { "🚫" } else { "✅" });
                        ui.label(&query.domain);
                    });
                }
            });
        }
    }

    fn stat_box(&self, ui: &mut egui::Ui, label: &str, value: u64, color: egui::Color32) {
        egui::Frame::new()
            .fill(egui::Color32::from_gray(30))
            .corner_radius(5.0)
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new(label).size(12.0));
                    ui.label(egui::RichText::new(format!("{}", value)).size(24.0).color(color).strong());
                });
            });
    }

    fn show_applications(&self, ui: &mut egui::Ui) {
        ui.heading("Pending Applications");
        ui.add_space(10.0);

        if let Some(engine) = &self.engine {
            let pending = engine.get_pending_apps();
            if pending.is_empty() {
                ui.label("No applications pending approval.");
            } else {
                for app in &pending {
                    egui::Frame::new()
                        .fill(egui::Color32::from_rgb(60, 50, 20))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::YELLOW))
                        .corner_radius(5.0)
                        .inner_margin(10.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("📦").size(20.0));
                                ui.vertical(|ui| {
                                    ui.label(egui::RichText::new(&app.name).strong());
                                    ui.label(format!("→ {}:{}", app.dst_ip, app.dst_port));
                                });
                                
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button("🚫 Block").clicked() {
                                        engine.block_app(&app.name);
                                    }
                                    if ui.button("✅ Allow").clicked() {
                                        engine.allow_app(&app.name);
                                    }
                                });
                            });
                        });
                    ui.add_space(5.0);
                }
            }
        }
    }

    fn show_blocked(&self, ui: &mut egui::Ui) {
        ui.heading("Blocked Packets");
        egui::ScrollArea::vertical().show(ui, |ui| {
            for (packet, reason) in self.blocked_packets.iter().rev().take(50) {
                egui::Frame::new()
                    .fill(egui::Color32::from_rgb(40, 20, 20))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::RED))
                    .corner_radius(3.0)
                    .inner_margin(8.0)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("🚫");
                            ui.vertical(|ui| {
                                ui.label(egui::RichText::new(format!("{:?}", packet.protocol))
                                    .color(egui::Color32::RED).strong());
                                ui.label(format!("{} → {}", packet.src_ip, packet.dst_ip));
                                ui.label(egui::RichText::new(reason).size(11.0).italics());
                            });
                        });
                    });
                ui.add_space(5.0);
            }
        });
    }

    fn show_logs(&self, ui: &mut egui::Ui) {
        ui.heading("System Logs");
        egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
            for log in &self.logs {
                let color = match log.level {
                    LogLevel::Info => egui::Color32::LIGHT_GRAY,
                    LogLevel::Success => egui::Color32::GREEN,
                    LogLevel::Warning => egui::Color32::YELLOW,
                    LogLevel::Error => egui::Color32::RED,
                };
                ui.colored_label(color, &log.message);
            }
        });
    }
}

// ============================================================================
// MAIN
// ============================================================================

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_title("HydraDragon Firewall"),
        ..Default::default()
    };
    
    eframe::run_native(
        "HydraDragon Firewall",
        options,
        Box::new(|_| Ok(Box::new(FirewallApp::default()))),
    )
}
