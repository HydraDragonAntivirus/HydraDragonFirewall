//! HTTP Parser Module - Extracts full URLs from HTTP requests
//! 
//! This module parses HTTP request packets to extract the hostname (from Host header)
//! and the full URL path, enabling the firewall to filter HTTP traffic by URL.

/// Result of parsing an HTTP request
#[derive(Debug, Clone)]
pub struct HttpRequestInfo {
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Request path (e.g., "/path/to/resource")
    pub path: String,
    /// Host from the Host header
    pub host: Option<String>,
    /// Full reconstructed URL
    pub full_url: Option<String>,
}

/// HTTP methods we recognize
const HTTP_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"];

/// Extracts HTTP request information from a packet payload.
/// 
/// # Arguments
/// * `data` - Raw packet payload (TCP payload)
/// 
/// # Returns
/// * `Some(HttpRequestInfo)` - If this is a valid HTTP request
/// * `None` - If the packet is not an HTTP request
pub fn extract_http_info(data: &[u8]) -> Option<HttpRequestInfo> {
    // Convert to string for parsing
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => {
            // Try to parse just the ASCII portion
            let ascii_end = data.iter().position(|&b| b > 127).unwrap_or(data.len());
            if ascii_end < 16 {
                return None;
            }
            std::str::from_utf8(&data[..ascii_end]).ok()?
        }
    };

    // Find the request line (first line)
    let first_line = text.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    
    if parts.len() < 3 {
        return None;
    }

    let method = parts[0];
    let path = parts[1];
    let version = parts[2];

    // Validate HTTP method
    if !HTTP_METHODS.contains(&method) {
        return None;
    }

    // Validate HTTP version
    if !version.starts_with("HTTP/") {
        return None;
    }

    // Extract Host header
    let host = extract_host_header(text);

    // Reconstruct full URL
    let full_url = host.as_ref().map(|h| {
        if path.starts_with("http://") || path.starts_with("https://") {
            // Absolute URL (used in CONNECT or proxy requests)
            path.to_string()
        } else {
            format!("http://{}{}", h, path)
        }
    });

    Some(HttpRequestInfo {
        method: method.to_string(),
        path: path.to_string(),
        host,
        full_url,
    })
}

/// Extracts the Host header value from HTTP headers
fn extract_host_header(text: &str) -> Option<String> {
    for line in text.lines().skip(1) {
        // Empty line marks end of headers
        if line.is_empty() || line == "\r" {
            break;
        }

        // Parse header
        if let Some(colon_pos) = line.find(':') {
            let header_name = line[..colon_pos].trim().to_lowercase();
            let header_value = line[colon_pos + 1..].trim();

            if header_name == "host" {
                // Remove port if present for cleaner hostname
                let host = header_value.split(':').next().unwrap_or(header_value);
                return Some(host.to_string());
            }
        }
    }
    None
}

/// Quick check if the packet looks like an HTTP request
pub fn is_http_request(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    
    // Check for common HTTP methods
    let prefix = &data[..4.min(data.len())];
    matches!(prefix, 
        b"GET " | b"POST" | b"PUT " | b"HEAD" | b"DELE" | b"OPTI" | b"PATC" | b"CONN" | b"TRAC"
    )
}

/// Extracts just the hostname from HTTP data (convenience function)
pub fn extract_hostname(data: &[u8]) -> Option<String> {
    extract_http_info(data).and_then(|info| info.host)
}

/// Extracts the full URL from HTTP data (convenience function)
pub fn extract_full_url(data: &[u8]) -> Option<String> {
    extract_http_info(data).and_then(|info| info.full_url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_get() {
        let request = b"GET /test/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let info = extract_http_info(request).unwrap();
        assert_eq!(info.method, "GET");
        assert_eq!(info.path, "/test/path");
        assert_eq!(info.host, Some("example.com".to_string()));
        assert_eq!(info.full_url, Some("http://example.com/test/path".to_string()));
    }

    #[test]
    fn test_is_http_request() {
        assert!(is_http_request(b"GET /"));
        assert!(is_http_request(b"POST /"));
        assert!(!is_http_request(b"\x16\x03\x01"));
    }
}
