use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::fs::File;
use std::path::Path;
use std::io::BufReader;
use regex::Regex;
use glob::glob;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CsvRecord {
    #[serde(alias = "address")] 
    address: String,
    // We ignore other fields like ref_ids for now
}

#[derive(Clone)]
pub struct WebFilter {
    ipv4_blocklist: Arc<RwLock<HashSet<Ipv4Addr>>>,
    ipv6_blocklist: Arc<RwLock<HashSet<Ipv6Addr>>>,
    domain_blocklist: Arc<RwLock<HashSet<String>>>,
    regex_patterns: Arc<Vec<Regex>>,
}

impl WebFilter {
    pub fn new() -> Self {
        // Compile regex patterns from antivirus.py logic
        let mut patterns = Vec::new();
        // Discord Webhook
        patterns.push(Regex::new(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+").unwrap());
        // Discord Attachment
        patterns.push(Regex::new(r"https://cdn\.discordapp\.com/attachments/\d+/\d+/[A-Za-z0-9._-]+").unwrap());
        // Telegram Token
        patterns.push(Regex::new(r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}").unwrap());
        
        Self {
            ipv4_blocklist: Arc::new(RwLock::new(HashSet::new())),
            ipv6_blocklist: Arc::new(RwLock::new(HashSet::new())),
            domain_blocklist: Arc::new(RwLock::new(HashSet::new())),
            regex_patterns: Arc::new(patterns),
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

    pub fn check_payload(&self, payload: &[u8]) -> Option<String> {
        // 1. Convert to string (lossy) to check regex
        // We only check the first 2KB for efficiency
        let scan_len = std::cmp::min(payload.len(), 2048);
        if scan_len == 0 { return None; }
        
        let text = String::from_utf8_lossy(&payload[..scan_len]);
        
        // Check regexes
        for pattern in self.regex_patterns.iter() {
            if pattern.is_match(&text) {
                return Some(format!("Regex Match: {}", pattern.as_str()));
            }
        }

        // 2. Check for Host header (HTTP)
        // Find "Host: "
        if let Some(host_idx) = text.to_lowercase().find("host: ") {
            let start = host_idx + 6;
            if let Some(end) = text[start..].find("\r\n") {
                 let host = text[start..start+end].trim().to_lowercase();
                 // Remove port if present
                 let host_name = host.split(':').next().unwrap_or(&host);
                 
                 if self.domain_blocklist.read().unwrap().contains(host_name) {
                     return Some(format!("Blocked Domain: {}", host_name));
                 }
            }
        }
        
        // 2b. Check SNI (very basic)
        // Client Hello starts with 0x16 (Handshake) 0x03 (Version). 
        // Extension 0x0000 is SNI.
        // This is complex to parse robustly without a library, but text search might catch it 
        // if the domain is present in cleartext (which it is in SNI).
        
        // Simple search for blocked domains in payload (O(N*M) - expensive, but maybe okay for small blocklists? 
        // No, domain list is huge (100k+). We rely on Host header or exact SNI extraction or simple "Is this string in list" 
        // Regex search is better.)
        
        // For now, relying on Host header and Payload Regexes as "Optimized Version".
        // Full domain Search is too slow without Aho-Corasick.
        
        None
    }
}
