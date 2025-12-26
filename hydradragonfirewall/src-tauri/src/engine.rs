use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use std::path::PathBuf;
use std::fs;
use serde::{Serialize, Deserialize};
use tauri::{AppHandle, Emitter};
use windivert::prelude::*;
use crate::web_filter::WebFilter;
use crate::injector::Injector;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Raw(u8),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketInfo {
    pub timestamp: u64, 
    pub protocol: Protocol,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub size: usize,
    pub outbound: bool,
    pub process_id: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsQuery {
    pub timestamp: u64,
    pub domain: String,
    pub blocked: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: String,
    pub timestamp: u64,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AppDecision {
    Pending,
    Allow,
    Block,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingApp {
    pub process_id: u32,
    pub name: String,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub protocol: Protocol,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub block: bool,
    pub protocol: Option<Protocol>,
    pub remote_ips: Vec<String>,    // Supports CIDR or exact IPs
    pub remote_ports: Vec<u16>,     // Supports multiple ports
    pub app_name: Option<String>,
}

impl FirewallRule {
    pub fn matches(&self, packet: &PacketInfo, app_name: &str) -> bool {
        if !self.enabled { return false; }

        // Protocol Match
        if let Some(ref proto) = self.protocol {
            if proto != &packet.protocol { return false; }
        }

        // Remote IP Match (Multiple)
        if !self.remote_ips.is_empty() {
            let mut matched_ip = false;
            let dst_ip_str = packet.dst_ip.to_string();
            for pattern in &self.remote_ips {
                if pattern == "any" || pattern == "*" || pattern == &dst_ip_str {
                    matched_ip = true;
                    break;
                }
                // CIDR check could be added here later
            }
            if !matched_ip { return false; }
        }

        // Remote Port Match (Multiple)
        if !self.remote_ports.is_empty() {
            if !self.remote_ports.contains(&packet.dst_port) {
                return false;
            }
        }

        // App Name Match
        if let Some(ref rule_app) = self.app_name {
            if !app_name.to_lowercase().contains(&rule_app.to_lowercase()) {
                return false;
            }
        }

        true
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WhitelistEntry {
    pub timestamp: u64,
    pub item: String, // IP or Domain
    pub reason: String,
    pub category: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirewallSettings {
    pub whitelisted_ips: HashSet<String>,
    pub whitelisted_domains: HashSet<String>,
    pub whitelisted_ports: HashSet<u16>,
    pub app_decisions: HashMap<String, AppDecision>,
    pub website_path: String,
    pub rules: Vec<FirewallRule>,
    pub metadata: HashMap<String, String>,
}

impl Default for FirewallSettings {
    fn default() -> Self {
        let mut ips = HashSet::new();
        ips.insert("127.0.0.1".to_string());
        ips.insert("::1".to_string());

        let mut ports = HashSet::new();
        ports.insert(8080);

        let mut apps = HashMap::new();
        apps.insert("system".to_string(), AppDecision::Allow);
        apps.insert("hydradragonfirewall.exe".to_string(), AppDecision::Allow);

        let mut metadata = HashMap::new();
        metadata.insert("version".to_string(), "1.0.0".to_string());
        metadata.insert("description".to_string(), "HydraDragon Advanced Firewall Settings".to_string());

        Self {
            whitelisted_ips: ips,
            whitelisted_domains: HashSet::new(),
            whitelisted_ports: ports,
            app_decisions: apps,
            website_path: String::new(),
            rules: Vec::new(),
            metadata,
        }
    }
}

pub struct Statistics {
    pub packets_total: AtomicU64,
    pub packets_blocked: AtomicU64,
    pub packets_allowed: AtomicU64,
    pub icmp_blocked: AtomicU64,
    pub dns_queries: AtomicU64,
    pub dns_blocked: AtomicU64,
    pub tcp_connections: AtomicU64,
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

pub struct DnsHandler {
    queries: RwLock<VecDeque<DnsQuery>>,
    blocked_domains: RwLock<HashSet<String>>,
}

impl DnsHandler {
    pub fn new() -> Self {
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

    pub fn should_block(&self, domain: &str) -> bool {
        let blocked = self.blocked_domains.read().unwrap();
        let domain_lower = domain.to_lowercase();
        
        for pattern in blocked.iter() {
            if domain_lower.contains(pattern) {
                return true;
            }
        }
        false
    }

    pub fn log_query(&self, domain: String, blocked: bool) {
        let mut queries = self.queries.write().unwrap();
        queries.push_back(DnsQuery {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
            domain,
            blocked,
        });
        if queries.len() > 500 {
            queries.pop_front();
        }
    }
}

pub struct AppManager {
    pub decisions: RwLock<HashMap<String, AppDecision>>,
    pub pending: RwLock<VecDeque<PendingApp>>,
    pub known_apps: RwLock<HashSet<String>>,
    pub port_map: RwLock<HashMap<u16, u32>>,
}

impl AppManager {
    pub fn new(initial_decisions: HashMap<String, AppDecision>) -> Self {
        Self {
            decisions: RwLock::new(initial_decisions),
            pending: RwLock::new(VecDeque::new()),
            known_apps: RwLock::new(HashSet::new()),
            port_map: RwLock::new(HashMap::new()),
        }
    }

    pub fn update_port_mapping(&self, port: u16, pid: u32) {
        if port == 0 || pid == 0 { return; }
        let mut map = self.port_map.write().unwrap();
        map.insert(port, pid);
    }

    pub fn get_pid_for_port(&self, port: u16) -> Option<u32> {
        self.port_map.read().unwrap().get(&port).cloned()
    }

    pub fn get_app_name(process_id: u32) -> String {
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
                    let success = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) != 0;
                    CloseHandle(handle);
                    
                    if success {
                        let path = OsString::from_wide(&buffer[..size as usize]);
                        if let Some(path_str) = path.to_str() {
                            if let Some(name) = std::path::Path::new(path_str).file_name() {
                                return name.to_string_lossy().to_string();
                            }
                        }
                    }
                }
            }
        }

        format!("PID:{}", process_id)
    }

    pub fn check_app(&self, packet: &PacketInfo) -> (AppDecision, String) {
        let mut pid = packet.process_id;

        if pid == 0 {
            if packet.outbound {
                if let Some(p) = self.get_pid_for_port(packet.src_port) { pid = p; }
            } else {
                if let Some(p) = self.get_pid_for_port(packet.dst_port) { pid = p; }
            }
        }

        let app_name = Self::get_app_name(pid);
        let app_name_lower = app_name.to_lowercase();

        // Explicit self-bypass: always allow the firewall itself and system processes
        if pid == std::process::id() 
            || app_name_lower == "hydradragonfirewall.exe" 
            || app_name_lower == "system" 
            || pid == 0 
            || pid == 4 
        {
            return (AppDecision::Allow, app_name);
        }

        {
            let decisions = self.decisions.read().unwrap();
            if let Some(decision) = decisions.get(&app_name_lower) {
                return (decision.clone(), app_name);
            }
        }

        {
             let mut known = self.known_apps.write().unwrap();
             if !known.contains(&app_name_lower) {
                 known.insert(app_name_lower.clone());
                 let mut pending = self.pending.write().unwrap();
                 pending.push_back(PendingApp {
                    process_id: pid,
                    name: app_name.clone(),
                    dst_ip: packet.dst_ip,
                    dst_port: packet.dst_port,
                    protocol: packet.protocol.clone(),
                 });
             }
        }

        (AppDecision::Pending, app_name)
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut std::ffi::c_void;
    fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    fn QueryFullProcessImageNameW(hProcess: *mut std::ffi::c_void, dwFlags: u32, lpExeName: *mut u16, lpdwSize: *mut u32) -> i32;
}

pub struct FirewallEngine {
    pub stats: Arc<Statistics>,
    pub rules: Arc<RwLock<Vec<FirewallRule>>>,
    pub dns_handler: Arc<DnsHandler>,
    pub app_manager: Arc<AppManager>,
    pub web_filter: Arc<WebFilter>,
    pub whitelist: Arc<RwLock<Vec<WhitelistEntry>>>,
    pub settings: Arc<RwLock<FirewallSettings>>,
    pub stop_signal: Arc<AtomicBool>,
}

impl FirewallEngine {
    pub fn new() -> Self {
        let stats = Arc::new(Statistics::default());
        let dns_handler = Arc::new(DnsHandler::new());
        let web_filter = Arc::new(WebFilter::new());
        let whitelist = Arc::new(RwLock::new(Vec::new()));
        let stop_signal = Arc::new(AtomicBool::new(false));

        // Load settings with fallback to default
        let mut settings_data = Self::load_settings().unwrap_or_default();
        
        // Ensure essential apps are ALWAYS allowed
        settings_data.app_decisions.insert("system".to_string(), AppDecision::Allow);
        settings_data.app_decisions.insert("hydradragonfirewall.exe".to_string(), AppDecision::Allow);
        
        // Populate default rules if none exist
        if settings_data.rules.is_empty() {
            settings_data.rules.push(FirewallRule {
                name: "Block ICMP (Ping)".to_string(),
                description: "Blocks all incoming and outgoing ICMP echo requests.".to_string(),
                enabled: true,
                block: true,
                protocol: Some(Protocol::ICMP),
                remote_ips: vec![],
                remote_ports: vec![],
                app_name: None,
            });
        }

        let app_decisions = settings_data.app_decisions.clone();
        let app_manager = Arc::new(AppManager::new(app_decisions));
        let rules = Arc::new(RwLock::new(settings_data.rules.clone()));
        let settings = Arc::new(RwLock::new(settings_data));

        Self {
            stats,
            rules,
            dns_handler,
            app_manager,
            web_filter,
            whitelist,
            settings,
            stop_signal,
        }
    }

    pub fn load_settings() -> Option<FirewallSettings> {
        let path = PathBuf::from("settings.json");
        if let Ok(content) = fs::read_to_string(&path) {
            serde_json::from_str(&content).ok()
        } else {
            None
        }
    }

    pub fn save_settings(&self) {
        let current_settings = self.settings.read().unwrap();
        let settings = FirewallSettings {
            whitelisted_ips: current_settings.whitelisted_ips.clone(),
            whitelisted_domains: current_settings.whitelisted_domains.clone(),
            whitelisted_ports: current_settings.whitelisted_ports.clone(),
            app_decisions: self.app_manager.decisions.read().unwrap().clone(),
            website_path: current_settings.website_path.clone(),
            rules: self.rules.read().unwrap().clone(),
            metadata: current_settings.metadata.clone(),
        };

        if let Ok(content) = serde_json::to_string_pretty(&settings) {
            let _ = fs::write("settings.json", content);
        }
    }

    pub fn is_loopback(ip: Ipv4Addr) -> bool {
        ip.is_loopback() || ip == Ipv4Addr::new(127, 0, 0, 1) || ip == Ipv4Addr::new(0, 0, 0, 0)
    }
    
    pub fn add_whitelist_entry(&self, item: String, reason: String, category: String) {
        let mut wl = self.whitelist.write().unwrap();
        wl.push(WhitelistEntry {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
            item,
            reason,
            category
        });
        // TODO: Persist to disk
    }

    pub fn is_whitelisted(&self, item: &str) -> bool {
        let wl = self.whitelist.read().unwrap();
        wl.iter().any(|entry| entry.item == item)
    }

    pub fn start(&self, app_handle: AppHandle) {
        let stats = Arc::clone(&self.stats);
        let _rules = Arc::clone(&self.rules);
        let _dns = Arc::clone(&self.dns_handler);
        let am = Arc::clone(&self.app_manager);
        let _wf = Arc::clone(&self.web_filter);
        let stop = Arc::clone(&self.stop_signal);
        let _whitelist = Arc::clone(&self.whitelist);
        let tx = app_handle.clone();
        let settings_arc = Arc::clone(&self.settings);

        // ==================================================================== 
        // WEB FILTER LOADER - Explicit Stack Size to Prevent Overflow
        // ====================================================================
        let wf_loader = Arc::clone(&self.web_filter);
        let tx_loader = app_handle.clone();
        
        let settings_arc_loader = Arc::clone(&settings_arc);
        std::thread::Builder::new()
            .name("web_filter_loader".to_string())
            .stack_size(8 * 1024 * 1024) // 8MB Stack
            .spawn(move || {
                // use PathBuf and fs from top-level imports line 7 and 8
                
                // Try paths: 1. From settings, 2. Auto-discovery
                let mut paths = Vec::new();
                
                {
                    let s = settings_arc_loader.read().unwrap();
                    if !s.website_path.is_empty() {
                        paths.push(PathBuf::from(&s.website_path));
                    }
                }
                
                // Get current executable directory
                if let Ok(exe_path) = std::env::current_exe() {
                   if let Some(exe_dir) = exe_path.parent() {
                       paths.push(exe_dir.join("website"));
                       paths.push(exe_dir.join("../website"));
                       paths.push(exe_dir.join("../../website"));
                   }
                }
                
                // Get current working directory
                if let Ok(cwd) = std::env::current_dir() {
                    paths.push(cwd.join("website"));
                    paths.push(cwd.join("../website"));
                    paths.push(cwd.join("../../website"));
                    paths.push(cwd.join("Active Workspaces/website"));
                }
                
                // Common development paths
                if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
                    let home_path = PathBuf::from(home);
                    paths.push(home_path.join("Documents/HydraDragon/website"));
                    paths.push(home_path.join("Desktop/HydraDragon/website"));
                    paths.push(home_path.join("Projects/HydraDragon/website"));
                }
                
                // Absolute paths for malware databases
                paths.push(PathBuf::from("C:/MalwareDB/website"));
                paths.push(PathBuf::from("C:/Program Files/HydraDragon/website"));
                paths.push(PathBuf::from("C:/ProgramData/HydraDragon/website"));
                
                let mut loaded = false;
                let mut total_loaded = 0;
                
                for base_path in paths {
                    if !base_path.exists() {
                        continue;
                    }
                    
                    let path_str = base_path.to_string_lossy().to_string();
                    let ts = Self::now_ts();
                    let _ = tx_loader.emit("log", LogEntry { 
                        id: format!("{}-scan", ts),
                        timestamp: ts, 
                        level: LogLevel::Info, 
                        message: format!("Scanning for CSV files in: {}...", path_str) 
                    });
                    
                    // Scan for CSV files only
                    if let Ok(entries) = fs::read_dir(&base_path) {
                        let csv_files: Vec<PathBuf> = entries
                            .filter_map(|e| e.ok())
                            .map(|e| e.path())
                            .filter(|p| {
                                p.is_file() && 
                                p.extension()
                                    .and_then(|ext| ext.to_str())
                                    .map(|ext| ext.eq_ignore_ascii_case("csv"))
                                    .unwrap_or(false)
                            })
                            .collect();
                        
                        if csv_files.is_empty() {
                            let ts = Self::now_ts();
                            let _ = tx_loader.emit("log", LogEntry { 
                                id: format!("{}-csv-none", ts),
                                timestamp: ts, 
                                level: LogLevel::Warning, 
                                message: format!("⚠️ No CSV files found in {}", path_str) 
                            });
                            continue;
                        }
                        
                        let ts = Self::now_ts();
                        let _ = tx_loader.emit("log", LogEntry { 
                            id: format!("{}-csv-found", ts),
                            timestamp: ts, 
                            level: LogLevel::Info, 
                            message: format!("Found {} CSV file(s) in {}", csv_files.len(), path_str) 
                        });
                        
                        // Load each CSV file
                        for _csv_file in csv_files {
                             match wf_loader.load_from_website_folder(&path_str) {
                                Ok(count) => {
                                    total_loaded = count;
                                    let ts = Self::now_ts();
                                    let _ = tx_loader.emit("log", LogEntry { 
                                        id: format!("{}-csv-loaded", ts),
                                        timestamp: ts, 
                                        level: LogLevel::Success, 
                                        message: format!("✅ Loaded {} entries from CSV files", count) 
                                    });
                                    loaded = true;
                                    break;
                                },
                                Err(e) => {
                                    let ts = Self::now_ts();
                                    let _ = tx_loader.emit("log", LogEntry { 
                                        id: format!("{}-web-load-fail", ts),
                                        timestamp: ts, 
                                        level: LogLevel::Warning, 
                                        message: format!("⚠️ Failed to load CSV files: {}", e) 
                                    });
                                }
                             }
                        }
                        
                        if loaded {
                            let ts = Self::now_ts();
                            let _ = tx_loader.emit("log", LogEntry { 
                                id: format!("{}-web-total-loaded", ts),
                                timestamp: ts, 
                                level: LogLevel::Success, 
                                message: format!("✅ WebFilter loaded {} total malicious signatures from {}", total_loaded, path_str) 
                            });
                            break;
                        }
                    }
                }
                
                if !loaded {
                    let ts = Self::now_ts();
                    let _ = tx_loader.emit("log", LogEntry { 
                        id: format!("{}-web-not-found", ts),
                        timestamp: ts, 
                        level: LogLevel::Warning, 
                        message: "⚠️ WebFilter database not found. Firewall running with limited protection.".into() 
                    });
                }
        }).expect("failed to spawn web_filter_loader thread");

        // Socket and Flow layers temporarily disabled for passthrough testing
        // These will be re-enabled once basic packet forwarding is confirmed working
        let _am_socket = Arc::clone(&am);
        let _stop_socket = Arc::clone(&stop);
        let _am_flow = Arc::clone(&am);
        let _stop_flow = Arc::clone(&stop);
        /*
        // Socket Layer (PID Tracking)
        std::thread::Builder::new()
            .name("socket_layer".to_string())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
             let flags = WinDivertFlags::new();
             flags.set_sniff();
             flags.set_recv_only();
             if let Ok(handle) = WinDivert::socket("true", 0, flags) {
                 while !stop_socket.load(std::sync::atomic::Ordering::Relaxed) {
                     if let Ok(packet) = handle.recv() {
                         let packets = vec![packet];
                         for packet in packets {
                             let addr = &packet.address;
                             let pid = addr.process_id();
                             let port = addr.local_port();
                             if pid > 0 && port > 0 {
                                 am_socket.update_port_mapping(port, pid);
                             }
                         }
                     }
                 }
             }
        }).expect("failed to spawn socket thread");
        
        // Flow Layer (PID Tracking)
        std::thread::Builder::new()
            .name("flow_layer".to_string())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
            let flags = WinDivertFlags::new();
            flags.set_sniff();
            flags.set_recv_only();
            if let Ok(handle) = WinDivert::flow("true", 0, flags) {
                 while !stop_flow.load(std::sync::atomic::Ordering::Relaxed) {
                     if let Ok(packet) = handle.recv() {
                         let packets = vec![packet];
                         for packet in packets {
                             let addr = &packet.address;
                             let pid = addr.process_id();
                             let port = addr.local_port();
                             if pid > 0 && port > 0 {
                                 am_flow.update_port_mapping(port, pid);
                             }
                         }
                     }
                 }
            }
        }).expect("failed to spawn flow thread");
        */

        // Main Firewall Loop - FULL IMPLEMENTATION
        std::thread::Builder::new()
            .name("firewall_main".to_string())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
            let ts = Self::now_ts();
            let _ = tx.emit("log", LogEntry { 
                id: format!("{}-init-divert", ts),
                timestamp: ts, 
                level: LogLevel::Info, 
                message: "Initializing WinDivert (Full Mode)...".into() 
            });

            let flags = WinDivertFlags::default();
            let filter = "true and !loopback and !ip.Addr == 127.0.0.1";
            let priority = 0;
            
            let ts = Self::now_ts();
            let _ = tx.emit("log", LogEntry { 
                id: format!("{}-divert-active", ts),
                timestamp: ts, 
                level: LogLevel::Success, 
                message: "🛡️ Firewall Engine ACTIVE. Intercepting traffic...".into() 
            });

            match WinDivert::network(filter, priority, flags) {
                Ok(handle) => {
                    let mut buffer = vec![0u8; 65535];
                    while !stop.load(Ordering::Relaxed) {
                        match handle.recv_ex(Some(&mut buffer), 10) {
                            Ok(packets) => {
                                for packet in packets {
                                    let mut action_blocked = false;
                                    let mut reason = "Allow (Default)".to_string();

                                    // 1. Parse packet basic info
                                    // Use 0 as a placeholder for PID as NetworkLayer doesn't provide it directly in 0.6.0
                                    if let Some(mut info) = Self::parse_packet(&packet.data, packet.address.outbound(), 0) {
                                        // 2. Resolve App Name and Decision
                                        let (app_decision, app_name) = am.check_app(&info);
                                        // Process ID is not directly available at NetworkLayer in this version
                                        info.process_id = 0; 

                                        // 3. DNS Inspection (UDP 53)
                                        if info.protocol == Protocol::UDP && (info.dst_port == 53 || info.src_port == 53) {
                                            stats.dns_queries.fetch_add(1, Ordering::Relaxed);
                                            // Simple DNS inspection could go here
                                        }

                                        // 4. Payload Inspection (Web Filter)
                                        if !action_blocked {
                                            if let Some(malicious_reason) = _wf.check_payload(&packet.data) {
                                                action_blocked = true;
                                                reason = malicious_reason;
                                            }
                                        }

                                        // 5. User Decision Overrides (App Wise)
                                        if !action_blocked {
                                            if app_decision == AppDecision::Block {
                                                action_blocked = true;
                                                reason = format!("Blocked App: {}", app_name);
                                            }
                                        }

                                        // 6. Check Global Rules
                                        if !action_blocked {
                                            let current_rules = _rules.read().unwrap();
                                            for rule in current_rules.iter() {
                                                if rule.matches(&info, &app_name) {
                                                    if rule.block {
                                                        action_blocked = true;
                                                        reason = format!("Rule Match: {}", rule.name);
                                                        break;
                                                    } else {
                                                        reason = format!("Rule Allowed: {}", rule.name);
                                                        break;
                                                    }
                                                }
                                            }
                                        }

                                        // 7. Update Statistics
                                        stats.packets_total.fetch_add(1, Ordering::Relaxed);
                                        if action_blocked {
                                            stats.packets_blocked.fetch_add(1, Ordering::Relaxed);
                                            if info.protocol == Protocol::ICMP {
                                                stats.icmp_blocked.fetch_add(1, Ordering::Relaxed);
                                            }
                                            
                                            // Optional: Log block event to UI
                                            let ts = Self::now_ts();
                                            let _ = tx.emit("log", LogEntry {
                                                id: format!("{}-blocked", ts),
                                                timestamp: ts,
                                                level: LogLevel::Warning,
                                                message: format!("🚫 {} | src:{} dst:{}", reason, info.src_ip, info.dst_ip)
                                            });
                                        } else {
                                            stats.packets_allowed.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }

                                    // 6. Enforce Action
                                    if !action_blocked {
                                        let _ = handle.send(&packet);
                                    }
                                    // If blocked, we simply drop (don't send).
                                }
                            }
                            Err(_) => {
                                std::thread::sleep(Duration::from_millis(1));
                            }
                        }
                    }
                },
                Err(e) => {
                    let ts = Self::now_ts();
                    let _ = tx.emit("log", LogEntry { 
                        id: format!("{}-divert-fail", ts),
                        timestamp: ts, 
                        level: LogLevel::Error, 
                        message: format!("❌ Failed to open WinDivert handle: {}", e) 
                    });
                     std::thread::sleep(Duration::from_secs(5));
                }
            }
        }).expect("failed to spawn main firewall thread");
    }

    // DEBUG HELPER: Force compiler to show us the signature of WinDivertHelperCalcChecksums


    pub fn inject_dll(&self, pid: u32, dll_path: &str) -> bool {
        Injector::inject(pid, dll_path).is_ok()
    }

    fn now_ts() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
    }

    #[allow(dead_code)]
    fn log_to_file(message: &str) {
        let ts = Self::now_ts();
        let log_line = format!("[{}] {}\n", ts, message);
        let _ = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("firewall.log")
            .and_then(|mut f| std::io::Write::write_all(&mut f, log_line.as_bytes()));
    }

    #[allow(dead_code)]
    fn parse_packet(data: &[u8], outbound: bool, process_id: u32) -> Option<PacketInfo> {
        if data.len() < 20 { return None; }
        let ip_version = (data[0] >> 4) & 0x0F;
        if ip_version != 4 { return None; }

        let protocol = match data[9] {
            6 => Protocol::TCP,
            17 => Protocol::UDP,
            1 => Protocol::ICMP,
            n => Protocol::Raw(n),
        };

        let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let header_len = ((data[0] & 0x0F) as usize) * 4;

        let (src_port, dst_port) = if header_len + 4 <= data.len() {
            match protocol {
                Protocol::TCP | Protocol::UDP => {
                    (
                        u16::from_be_bytes([data[header_len], data[header_len + 1]]),
                        u16::from_be_bytes([data[header_len + 2], data[header_len + 3]])
                    )
                },
                _ => (0, 0)
            }
        } else { (0, 0) };

        Some(PacketInfo {
            timestamp: Self::now_ts(),
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
}

