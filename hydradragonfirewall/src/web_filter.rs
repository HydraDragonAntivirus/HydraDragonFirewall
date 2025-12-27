use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::fs::File;
use std::path::Path;
use std::io::BufReader;
use regex::Regex;
use glob::glob;
use serde::Deserialize;
use lazy_static::lazy_static;

#[derive(Debug, Deserialize)]
struct CsvRecord {
    #[serde(alias = "address")] 
    address: String,
    // We ignore other fields like ref_ids for now
}

// Use lazy_static to compile regex patterns lazily (on first use, not on startup)
// This prevents stack overflow during initialization
lazy_static! {
    static ref DISCORD_WEBHOOK_REGEX: Regex = 
        Regex::new(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+").unwrap();
    static ref DISCORD_ATTACHMENT_REGEX: Regex = 
        Regex::new(r"https://cdn\.discordapp\.com/attachments/\d+/\d+/[A-Za-z0-9._-]+").unwrap();
    static ref TELEGRAM_TOKEN_REGEX: Regex = 
        Regex::new(r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}").unwrap();
}

#[derive(Clone)]
pub struct WebFilter {
    ipv4_blocklist: Arc<RwLock<HashSet<Ipv4Addr>>>,
    ipv6_blocklist: Arc<RwLock<HashSet<Ipv6Addr>>>,
    domain_blocklist: Arc<RwLock<HashSet<String>>>,
}

impl WebFilter {
    pub fn new() -> Self {
        // No regex compilation here - patterns are lazily compiled on first use
        Self {
            ipv4_blocklist: Arc::new(RwLock::new(HashSet::new())),
            ipv6_blocklist: Arc::new(RwLock::new(HashSet::new())),
            domain_blocklist: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub fn load_from_website_folder(&self, base_path: &str) -> std::io::Result<usize> {
        let pattern = format!("{}\\*.optimized.csv", base_path);
        let mut count = 0;

        for entry in glob(&pattern).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))? {
            match entry {
                Ok(path) => {
                    if let Ok(c) = self.load_csv(&path) {
                        count += c;
                    }
                }
                Err(e) => eprintln!("Error reading glob entry: {:?}", e),
            }
        }
        Ok(count)
    }

    fn load_csv(&self, path: &Path) -> std::io::Result<usize> {
        let file = File::open(path)?;
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(true)
            .from_reader(BufReader::new(file));

        let mut count = 0;
        let filename = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        
        // Determine type based on filename (heuristic)
        let is_ipv4 = filename.contains("IPv4");
        let is_ipv6 = filename.contains("IPv6");
        let is_domain = filename.contains("Domain") || filename.contains("SubDomain"); // Covers MaliciousDomains, etc.
        let is_whitelist = filename.contains("WhiteList");

        if is_whitelist {
             return Ok(0); // Setup lists later if needed, for now just block blocklists
        }

        let mut ipv4_lock = self.ipv4_blocklist.write().unwrap();
        let mut ipv6_lock = self.ipv6_blocklist.write().unwrap();
        let mut domain_lock = self.domain_blocklist.write().unwrap();

        for result in rdr.deserialize() {
            let record: CsvRecord = match result {
                Ok(r) => r,
                Err(_) => continue,
            };

            let addr_str = record.address.trim();
            if addr_str.is_empty() { continue; }

            if is_ipv4 {
                if let Ok(ip) = addr_str.parse::<Ipv4Addr>() {
                    ipv4_lock.insert(ip);
                    count += 1;
                }
            } else if is_ipv6 {
                 if let Ok(ip) = addr_str.parse::<Ipv6Addr>() {
                    ipv6_lock.insert(ip);
                    count += 1;
                }
            } else if is_domain {
                domain_lock.insert(addr_str.to_lowercase());
                count += 1;
            } else {
                // Try auto-detect
                if let Ok(ip) = addr_str.parse::<Ipv4Addr>() {
                    ipv4_lock.insert(ip);
                } else if let Ok(ip) = addr_str.parse::<Ipv6Addr>() {
                    ipv6_lock.insert(ip);
                } else {
                    domain_lock.insert(addr_str.to_lowercase());
                }
                count += 1;
            }
        }
        
        Ok(count)
    }

    pub fn is_blocked_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => self.ipv4_blocklist.read().unwrap().contains(&ipv4),
            IpAddr::V6(ipv6) => self.ipv6_blocklist.read().unwrap().contains(&ipv6),
        }
    }

    pub fn check_payload(&self, payload: &[u8], settings: &crate::engine::FirewallSettings) -> Option<String> {
        // 1. Convert to string (lossy) to check regex
        // We only check the first 2KB for efficiency
        let scan_len = std::cmp::min(payload.len(), 4096); // Increased default scan
        if scan_len == 0 { return None; }
        
        let text = String::from_utf8_lossy(&payload[..scan_len]);
        let text_lower = text.to_lowercase();
        
        // Dynamic Keyword Scan from Settings
        for keyword in &settings.blocked_keywords {
            if text_lower.contains(&keyword.to_lowercase()) {
                return Some(format!("Blocked Keyword: {}", keyword));
            }
        }

        // Check regexes using lazy_static patterns (compiled on first use)
        // These can be toggled in future updates via settings if needed
        if DISCORD_WEBHOOK_REGEX.is_match(&text) {
            return Some(format!("Regex Match: Discord Webhook"));
        }
        if DISCORD_ATTACHMENT_REGEX.is_match(&text) {
            return Some(format!("Regex Match: Discord Attachment"));
        }
        if TELEGRAM_TOKEN_REGEX.is_match(&text) {
            return Some(format!("Regex Match: Telegram Token"));
        }

        // 2. Check for Host header (HTTP)
        // Find "Host: "
        if let Some(host_idx) = text_lower.find("host: ") {
            let start = host_idx + 6;
            if let Some(end) = text[start..].find("\r\n") {
                 let host = text[start..start+end].trim().to_lowercase();
                 // Remove port if present
                 let host_name = host.split(':').next().unwrap_or(&host);
                 
                 if self.domain_blocklist.read().unwrap().contains(host_name) {
                     return Some(format!("Blocked Domain: {}", host_name));
                 }
                 
                 // Also check dynamic keywords in Host header specifically
                 for keyword in &settings.blocked_keywords {
                    if host_name.contains(&keyword.to_lowercase()) {
                        return Some(format!("Blocked Host Keyword: {}", keyword));
                    }
                }
            }
        }
        
        None
    }
}