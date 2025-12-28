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
// Imports updated below

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
    /// Hostname extracted from HTTP Host header or TLS SNI
    pub hostname: Option<String>,
    /// Full URL (HTTP only, HTTPS only has hostname)
    pub full_url: Option<String>,
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
    pub remote_ips: Vec<String>,
    pub remote_ports: Vec<u16>,
    pub app_name: Option<String>,
    /// Hostname pattern for URL-based filtering (supports wildcards like *.facebook.com)
    pub hostname_pattern: Option<String>,
    /// URL pattern for HTTP filtering (supports wildcards)
    pub url_pattern: Option<String>,
}

impl FirewallRule {
    pub fn matches(&self, packet: &PacketInfo, app_name: &str) -> bool {
        if !self.enabled { return false; }

        if let Some(ref proto) = self.protocol {
            if proto != &packet.protocol { return false; }
        }

        if !self.remote_ips.is_empty() {
            let mut matched_ip = false;
            let dst_ip_str = packet.dst_ip.to_string();
            for pattern in &self.remote_ips {
                if pattern == "any" || pattern == "*" || pattern == &dst_ip_str {
                    matched_ip = true;
                    break;
                }
            }
            if !matched_ip { return false; }
        }

        if !self.remote_ports.is_empty() {
            if !self.remote_ports.contains(&packet.dst_port) {
                return false;
            }
        }

        if let Some(ref rule_app) = self.app_name {
            if !app_name.to_lowercase().contains(&rule_app.to_lowercase()) {
                return false;
            }
        }

        // Hostname pattern matching (for HTTPS SNI and HTTP Host)
        if let Some(ref pattern) = self.hostname_pattern {
            if let Some(ref hostname) = packet.hostname {
                if !Self::wildcard_match(pattern, hostname) {
                    return false;
                }
            } else {
                // No hostname in packet but rule requires it
                return false;
            }
        }

        // URL pattern matching (for HTTP only)
        if let Some(ref pattern) = self.url_pattern {
            if let Some(ref url) = packet.full_url {
                if !Self::wildcard_match(pattern, url) {
                    return false;
                }
            } else {
                // No URL in packet but rule requires it
                return false;
            }
        }

        true
    }

    /// Simple wildcard matching (supports * for any characters)
    fn wildcard_match(pattern: &str, text: &str) -> bool {
        let pattern_lower = pattern.to_lowercase();
        let text_lower = text.to_lowercase();
        
        if pattern_lower == "*" || pattern_lower == "any" {
            return true;
        }
        
        // Handle *.example.com pattern
        if pattern_lower.starts_with("*.") {
            let suffix = &pattern_lower[1..]; // Keep the dot
            return text_lower.ends_with(suffix) || text_lower == &pattern_lower[2..];
        }
        
        // Handle *keyword* pattern
        if pattern_lower.starts_with('*') && pattern_lower.ends_with('*') {
            let keyword = &pattern_lower[1..pattern_lower.len()-1];
            return text_lower.contains(keyword);
        }
        
        // Handle keyword* pattern
        if pattern_lower.ends_with('*') {
            let prefix = &pattern_lower[..pattern_lower.len()-1];
            return text_lower.starts_with(prefix);
        }
        
        // Handle *keyword pattern
        if pattern_lower.starts_with('*') {
            let suffix = &pattern_lower[1..];
            return text_lower.ends_with(suffix);
        }
        
        // Exact match
        text_lower == pattern_lower
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WhitelistEntry {
    pub timestamp: u64,
    pub item: String,
    pub reason: String,
    pub category: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallSettings {
    pub whitelisted_ips: HashSet<String>,
    pub whitelisted_domains: HashSet<String>,
    pub whitelisted_ports: HashSet<u16>,
    pub blocked_keywords: HashSet<String>, // New: Dynamic DNS blocking keywords
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
        ports.insert(8080); // Default development port

        let mut apps = HashMap::new();
        // Default allow rules moved here from hardcoded values
        apps.insert("system".to_string(), AppDecision::Allow);
        apps.insert("hydradragonfirewall.exe".to_string(), AppDecision::Allow);
        apps.insert("svchost.exe".to_string(), AppDecision::Allow);

        let mut keywords = HashSet::new();
        // Default bad keywords
        keywords.insert("malware".to_string());
        keywords.insert("virus".to_string());
        keywords.insert("trojan".to_string());
        keywords.insert("phishing".to_string());

        let mut metadata = HashMap::new();
        metadata.insert("version".to_string(), "2.0.0".to_string());
        metadata.insert("description".to_string(), "HydraDragon Next-Gen Firewall Configuration".to_string());
        metadata.insert("theme".to_string(), "cyberpunk".to_string());

        Self {
            whitelisted_ips: ips,
            whitelisted_domains: HashSet::new(),
            whitelisted_ports: ports,
            blocked_keywords: keywords,
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
    pub last_log_time: AtomicU64, // Rate limiting
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
            last_log_time: AtomicU64::new(0),
        }
    }
}

pub struct DnsHandler {
    queries: RwLock<VecDeque<DnsQuery>>,
    // No longer stores hardcoded blocked domains, reads from settings
}

impl DnsHandler {
    pub fn new() -> Self {
        Self {
            queries: RwLock::new(VecDeque::new()),
        }
    }

    pub fn should_block(&self, domain: &str, settings: &FirewallSettings) -> bool {
        let domain_lower = domain.to_lowercase();
        
        // Check dynamic keywords from settings
        for pattern in &settings.blocked_keywords {
            if domain_lower.contains(&pattern.to_lowercase()) {
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

// ============================================================================
// APP NAME CACHE - CRITICAL FIX #1
// ============================================================================
pub struct AppNameCache {
    cache: RwLock<HashMap<u32, (String, SystemTime)>>,
    cache_duration: Duration,
}

impl AppNameCache {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            cache_duration: Duration::from_secs(30),
        }
    }

    pub fn get_or_fetch(&self, pid: u32) -> String {
        // Fast path: check cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some((name, timestamp)) = cache.get(&pid) {
                if timestamp.elapsed().unwrap_or(Duration::MAX) < self.cache_duration {
                    return name.clone();
                }
            }
        }

        // Slow path: fetch and cache
        let name = Self::fetch_app_name(pid);
        let mut cache = self.cache.write().unwrap();
        cache.insert(pid, (name.clone(), SystemTime::now()));
        
        // Limit cache size
        if cache.len() > 1000 {
            cache.clear();
        }
        
        name
    }

    fn fetch_app_name(process_id: u32) -> String {
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
}

pub struct AppManager {
    pub decisions: RwLock<HashMap<String, AppDecision>>,
    pub pending: RwLock<VecDeque<PendingApp>>,
    pub known_apps: RwLock<HashSet<String>>,
    pub port_map: RwLock<HashMap<u16, u32>>,
    pub name_cache: AppNameCache,
}

impl AppManager {
    pub fn new(initial_decisions: HashMap<String, AppDecision>) -> Self {
        Self {
            decisions: RwLock::new(initial_decisions),
            pending: RwLock::new(VecDeque::new()),
            known_apps: RwLock::new(HashSet::new()),
            port_map: RwLock::new(HashMap::new()),
            name_cache: AppNameCache::new(),
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

    // OPTIMIZED: Now uses cache
    pub fn check_app(&self, packet: &PacketInfo) -> (AppDecision, String) {
        let mut pid = packet.process_id;

        if pid == 0 {
            if packet.outbound {
                if let Some(p) = self.get_pid_for_port(packet.src_port) { pid = p; }
            } else {
                if let Some(p) = self.get_pid_for_port(packet.dst_port) { pid = p; }
            }
        }

        let app_name = self.name_cache.get_or_fetch(pid);
        let app_name_lower = app_name.to_lowercase();

        // Self-bypass
        if pid == std::process::id() 
            || app_name_lower == "hydradragonfirewall.exe" 
            || app_name_lower == "system" 
            || pid == 0 
            || pid == 4 
        {
            return (AppDecision::Allow, app_name);
        }

        // Check decision cache
        {
            let decisions = self.decisions.read().unwrap();
            if let Some(decision) = decisions.get(&app_name_lower) {
                return (decision.clone(), app_name);
            }
        }

        // Add to pending if new
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
    pub fn resolve_decision(&self, name: &str, decision: AppDecision) {
        let name_lower = name.to_lowercase();
        let mut decisions = self.decisions.write().unwrap();
        decisions.insert(name_lower, decision);
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
// PACKET PROCESSING RESULT - Using raw bytes for cross-thread safety
// ============================================================================
#[allow(dead_code)]
struct PacketDecision {
    packet_data: Vec<u8>,
    address_data: Vec<u8>, // Serialized address for cross-thread safety
    should_forward: bool,
    _reason: String,
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

// RADICAL REFACTOR: Wrapper to make WinDivert Send + Sync (Safe for WinDivert handles)
struct WinDivertArc<L: windivert::layer::WinDivertLayerTrait>(Arc<WinDivert<L>>);
unsafe impl<L: windivert::layer::WinDivertLayerTrait> Send for WinDivertArc<L> {}
unsafe impl<L: windivert::layer::WinDivertLayerTrait> Sync for WinDivertArc<L> {}
impl<L: windivert::layer::WinDivertLayerTrait> Clone for WinDivertArc<L> {
    fn clone(&self) -> Self {
        WinDivertArc(Arc::clone(&self.0))
    }
}
impl<L: windivert::layer::WinDivertLayerTrait> std::ops::Deref for WinDivertArc<L> {
    type Target = WinDivert<L>;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl FirewallEngine {
    pub fn new() -> Self {
        let stats = Arc::new(Statistics::default());
        let dns_handler = Arc::new(DnsHandler::new());
        let web_filter = Arc::new(WebFilter::new());
        let whitelist = Arc::new(RwLock::new(Vec::new()));
        let stop_signal = Arc::new(AtomicBool::new(false));

        let mut settings_data = Self::load_settings().unwrap_or_default();
        
        // Default allow rules are now handled in Default impl or loaded from disk.
        // We do NOT hardcode them here to allow user to override/remove them.
        if settings_data.app_decisions.is_empty() {
             settings_data.app_decisions.insert("system".to_string(), AppDecision::Allow);
             settings_data.app_decisions.insert("hydradragonfirewall.exe".to_string(), AppDecision::Allow);
        }
        
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
                hostname_pattern: None,
                url_pattern: None,
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

    pub fn apply_settings(&self, new_settings: FirewallSettings) {
        // Sync App Decisions
        {
            let mut decisions = self.app_manager.decisions.write().unwrap();
            *decisions = new_settings.app_decisions.clone();
        }

        // Sync Rules
        {
            let mut rules = self.rules.write().unwrap();
            *rules = new_settings.rules.clone();
        }

        // Sync Core Settings
        {
            let mut settings = self.settings.write().unwrap();
            *settings = new_settings;
        }
    }

    pub fn save_settings(&self) {
        let current_settings = self.settings.read().unwrap();
        let settings = FirewallSettings {
            whitelisted_ips: current_settings.whitelisted_ips.clone(),
            whitelisted_domains: current_settings.whitelisted_domains.clone(),
            whitelisted_ports: current_settings.whitelisted_ports.clone(),
            blocked_keywords: current_settings.blocked_keywords.clone(), // Save new field
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
    }

    pub fn is_whitelisted(&self, item: &str) -> bool {
        let wl = self.whitelist.read().unwrap();
        wl.iter().any(|entry| entry.item == item)
    }

    pub fn resolve_app_decision(&self, name: String, decision: String) {
        let app_decision = match decision.as_str() {
            "Allow" => AppDecision::Allow,
            "Block" => AppDecision::Block,
            _ => AppDecision::Pending,
        };
        self.app_manager.resolve_decision(&name, app_decision);
        self.save_settings();
    }

    pub fn get_settings(&self) -> FirewallSettings {
        self.settings.read().unwrap().clone()
    }
}

impl FirewallEngine {
    pub fn start(&self, app_handle: AppHandle) {
        let stats = Arc::clone(&self.stats);
        let rules = Arc::clone(&self.rules);
        let _dns = Arc::clone(&self.dns_handler);
        let am = Arc::clone(&self.app_manager);
        let wf = Arc::clone(&self.web_filter);
        let stop = Arc::clone(&self.stop_signal);
        let tx = app_handle.clone();
        let settings_arc = Arc::clone(&self.settings);
        let whitelist_arc = Arc::clone(&self.whitelist);

        // Web Filter Loader Thread
        let wf_loader = Arc::clone(&self.web_filter);
        let tx_loader = app_handle.clone();
        let settings_arc_loader = Arc::clone(&settings_arc);
        
        std::thread::Builder::new()
            .name("web_filter_loader".to_string())
            .spawn(move || {
                let ts = Self::now_ts();
                // Prioritize the user's explicit request: "website"
                // We check settings first, but default strictly to "website" if empty/invalid.
                let path_str = {
                    let s = settings_arc_loader.read().unwrap();
                    if s.website_path.is_empty() {
                         "website".to_string()
                    } else {
                         s.website_path.clone()
                    }
                };

                let _ = tx_loader.emit("log", LogEntry { 
                    id: format!("{}-web-load-start", ts), timestamp: ts, level: LogLevel::Info, 
                    message: format!("Loading threat intelligence from: {}", path_str) 
                });

                // Execute the load
                match wf_loader.load_from_website_folder(&path_str) {
                    Ok(count) => {
                         let _ = tx_loader.emit("log", LogEntry { 
                            id: format!("{}-web-load-success", Self::now_ts()), 
                            timestamp: Self::now_ts(), 
                            level: LogLevel::Success, 
                            message: format!("WebFilter Loaded: {} rules active.", count) 
                        });
                    },
                    Err(e) => {
                         let _ = tx_loader.emit("log", LogEntry { 
                            id: format!("{}-web-load-error", Self::now_ts()), 
                            timestamp: Self::now_ts(), 
                            level: LogLevel::Error, 
                            message: format!("Failed to load 'website' folder: {}", e) 
                        });
                    }
                }
            }).expect("failed to spawn web_filter_loader thread");

        // OPEN WINDIVERT HANDLE ONCE
        let divert = match WinDivert::network("true", 0, WinDivertFlags::new()) {
            Ok(d) => WinDivertArc(Arc::new(d)),
            Err(e) => {
                let ts = Self::now_ts();
                let _ = tx.emit("log", LogEntry { 
                    id: format!("{}-divert-fail", ts), timestamp: ts, level: LogLevel::Error, 
                    message: format!("❌ WinDivert Open Failed: {:?}", e)
                });
                return;
            }
        };

        let ts = Self::now_ts();
        let _ = tx.emit("log", LogEntry { 
            id: format!("{}-divert-active", ts), timestamp: ts, level: LogLevel::Success, 
            message: "🛡️ Firewall Engine ACTIVE (RADICAL Parallel Mode Enabled)".into() 
        });

        // Worker Pool - RADICAL REFACTOR: Each worker is a fully independent capture loop
        let num_workers = 8; // Increased workers for parallel processing
        for worker_id in 0..num_workers {
            let stats_w = Arc::clone(&stats);
            let rules_w = Arc::clone(&rules);
            let am_w = Arc::clone(&am);
            let wf_w = Arc::clone(&wf);
            let stop_w = Arc::clone(&stop);
            let settings_w = Arc::clone(&settings_arc);
            let dns_w = Arc::clone(&_dns);
            let tx_log = app_handle.clone();
            let wl_w = Arc::clone(&whitelist_arc);
            let divert_w = divert.clone();
            
            std::thread::Builder::new()
                .name(format!("packet_worker_{}", worker_id))
                .spawn(move || {
                    let mut buffer = vec![0u8; 65535];
                    while !stop_w.load(Ordering::Relaxed) {
                        // Each thread competition for packets on the shared handle
                        match divert_w.recv(Some(&mut buffer)) {
                            Ok(packet) => {
                                let outbound = packet.address.outbound();
                                
                                // Serialize Address for Decision Logic 
                                // (Still keep some structure from previous for compatibility)
                                let addr_bytes = unsafe {
                                    std::slice::from_raw_parts(
                                        &packet.address as *const _ as *const u8,
                                        std::mem::size_of_val(&packet.address)
                                    ).to_vec()
                                };

                                let decision = Self::process_packet_decision(
                                    &packet.data,
                                    &addr_bytes,
                                    outbound,
                                    &stats_w,
                                    &rules_w,
                                    &am_w,
                                    &wf_w,
                                    &settings_w,
                                    &dns_w,
                                    &wl_w,
                                    &tx_log
                                );

                                if decision.should_forward {
                                    // REINJECT IMMEDIATELY from the SAME thread
                                    let reinject_packet = windivert::packet::WinDivertPacket {
                                        address: packet.address,
                                        data: std::borrow::Cow::Borrowed(&decision.packet_data),
                                    };
                                    if let Err(_e) = divert_w.send(&reinject_packet) {
                                         // Log error selectively?
                                    }
                                } else {
                                    // Packet is blocked - we just don't call divert.send()
                                    // WinDivert drops it automatically since we didn't send it.
                                }
                            }
                            Err(_e) => {
                                let err_str = _e.to_string();
                                if err_str.contains("timeout") || err_str.contains("122") {
                                    std::thread::sleep(Duration::from_millis(1));
                                } else {
                                     // Hard error - log once and maybe exit thread?
                                }
                            }
                        }
                    }
                }).expect("failed to spawn packet worker");
        }
    }

    fn process_packet_decision(
        data: &[u8],
        address_data: &[u8],
        outbound: bool,
        stats: &Arc<Statistics>,
        rules: &Arc<RwLock<Vec<FirewallRule>>>,
        am: &Arc<AppManager>,
        wf: &Arc<WebFilter>,
        settings: &Arc<RwLock<FirewallSettings>>,
        _dns_handler: &Arc<DnsHandler>,
        whitelist: &Arc<RwLock<Vec<WhitelistEntry>>>,
        tx: &AppHandle,
    ) -> PacketDecision {
        let mut should_forward = true;
        let mut reason = "Allow".to_string();

        if let Some(info) = Self::parse_packet(data, outbound, 0) {
            // 1. Check Global Whitelist (Dynamic)
            {
                let wl = whitelist.read().unwrap();
                for entry in wl.iter() {
                    if entry.item == info.src_ip.to_string() || entry.item == info.dst_ip.to_string() {
                         return PacketDecision {
                            packet_data: data.to_vec(),
                            address_data: address_data.to_vec(),
                            should_forward: true,
                            _reason: format!("Whitelisted: {}", entry.item),
                        };
                    }
                    if let Some(ref host) = info.hostname {
                        if host == &entry.item {
                            return PacketDecision {
                                packet_data: data.to_vec(),
                                address_data: address_data.to_vec(),
                                should_forward: true,
                                _reason: format!("Whitelisted Host: {}", entry.item),
                            };
                        }
                    }
                }
            }

            // 2. Check Static Whitelist and Keywords from Settings
            let settings_lock = settings.read().unwrap();
            
            // Static IP/Domain Whitelist
            if settings_lock.whitelisted_ips.contains(&info.src_ip.to_string()) || 
               settings_lock.whitelisted_ips.contains(&info.dst_ip.to_string()) {
                return PacketDecision {
                    packet_data: data.to_vec(),
                    address_data: address_data.to_vec(),
                    should_forward: true,
                    _reason: "Static Whitelist IP".to_string(),
                };
            }
            if let Some(ref host) = info.hostname {
                if settings_lock.whitelisted_domains.contains(host) {
                    return PacketDecision {
                        packet_data: data.to_vec(),
                        address_data: address_data.to_vec(),
                        should_forward: true,
                        _reason: "Static Whitelist Domain".to_string(),
                    };
                }
            }

            // Keyword Blocking (Hostname/URL)
            for keyword in &settings_lock.blocked_keywords {
                let kw_lower = keyword.to_lowercase();
                if let Some(ref host) = info.hostname {
                    if host.to_lowercase().contains(&kw_lower) {
                        should_forward = false;
                        reason = format!("Keyword Blocked (Host): {}", keyword);
                        break;
                    }
                }
                if let Some(ref url) = info.full_url {
                    if url.to_lowercase().contains(&kw_lower) {
                        should_forward = false;
                        reason = format!("Keyword Blocked (URL): {}", keyword);
                        break;
                    }
                }
            }

            if should_forward {
                if let Some(mal_reason) = wf.check_payload(data, &*settings_lock) {
                    should_forward = false;
                    reason = mal_reason;
                }
            }
            drop(settings_lock);

            // 3. App Decision Check
            let (app_decision, app_name) = am.check_app(&info);
            
            if should_forward && app_decision == AppDecision::Allow {
                stats.packets_total.fetch_add(1, Ordering::Relaxed);
                stats.packets_allowed.fetch_add(1, Ordering::Relaxed);
                return PacketDecision {
                    packet_data: data.to_vec(),
                    address_data: address_data.to_vec(),
                    should_forward: true,
                    _reason: format!("App Allowed: {}", app_name),
                };
            }

            // 4. Web Filter Checks (Hostname/URL lists)
            if should_forward {
                if let Some(ref hostname) = info.hostname {
                    if let Some(block_reason) = wf.check_hostname(hostname) {
                        should_forward = false;
                        reason = block_reason;
                    }
                }
            }

            if should_forward {
                if let Some(ref url) = info.full_url {
                    if let Some(block_reason) = wf.check_url(url) {
                        should_forward = false;
                        reason = block_reason;
                    }
                }
            }

            if should_forward && app_decision == AppDecision::Block {
                should_forward = false;
                reason = format!("Blocked App: {}", app_name);
            }

            // 5. Custom Firewall Rules
            if should_forward {
                let current_rules = rules.read().unwrap();
                for rule in current_rules.iter() {
                    if rule.matches(&info, &app_name) {
                        if rule.block {
                            should_forward = false;
                            reason = format!("Rule: {}", rule.name);
                            break;
                        } else {
                            reason = format!("Rule Allowed: {}", rule.name);
                            break;
                        }
                    }
                }
            }

            stats.packets_total.fetch_add(1, Ordering::Relaxed);
            if should_forward {
                stats.packets_allowed.fetch_add(1, Ordering::Relaxed);
            } else {
                stats.packets_blocked.fetch_add(1, Ordering::Relaxed);
                
                // RATE LIMITING
                let now = Self::now_ts();
                let last = stats.last_log_time.load(Ordering::Relaxed);
                
                if now > last + 50 {
                   if stats.last_log_time.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                        let host_info = info.hostname.as_ref()
                            .map(|h| format!(" [{}]", h))
                            .or_else(|| info.full_url.as_ref().map(|u| format!(" [{}]", u)))
                            .unwrap_or_default();
                        let _ = tx.emit("log", LogEntry {
                            id: format!("{}-blocked", now),
                            timestamp: now,
                            level: LogLevel::Warning,
                            message: format!("🚫 {}{}  | {}->{}:{}", reason, host_info, info.src_ip, info.dst_ip, info.dst_port)
                        });
                   }
                }
            }
        }

        PacketDecision {
            packet_data: data.to_vec(),
            address_data: address_data.to_vec(),
            should_forward,
            _reason: reason,
        }
    }



    pub fn inject_dll(&self, pid: u32, dll_path: &str) -> bool {
        Injector::inject(pid, dll_path).is_ok()
    }

    fn now_ts() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
    }

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

        // Extract hostname and URL from TCP payloads
        let (hostname, full_url) = if matches!(protocol, Protocol::TCP) && header_len + 20 < data.len() {
            // TCP header is at least 20 bytes, data offset is in bits 4-7 of byte 12
            let tcp_header_start = header_len;
            let tcp_data_offset = if tcp_header_start + 12 < data.len() {
                ((data[tcp_header_start + 12] >> 4) as usize) * 4
            } else {
                20
            };
            let payload_start = header_len + tcp_data_offset;
            
            if payload_start < data.len() {
                let payload = &data[payload_start..];
                
                // Check for HTTPS (port 443) - TLS SNI extraction
                if dst_port == 443 || src_port == 443 {
                    let sni = crate::tls_parser::extract_sni(payload);
                    (sni, None)
                }
                // Check for HTTP (port 80) - Full URL extraction
                else if dst_port == 80 || src_port == 80 {
                    if let Some(http_info) = crate::http_parser::extract_http_info(payload) {
                        (http_info.host.clone(), http_info.full_url)
                    } else {
                        (None, None)
                    }
                }
                else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

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
            hostname,
            full_url,
        })
    }
}
