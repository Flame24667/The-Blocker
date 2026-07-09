use blocker_db::{BlockedDomainSummary, BlockerDb, StoredBlockEvent};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

#[derive(Debug, Clone)]
pub struct ApiServerConfig {
    pub listen_addr: SocketAddr,
    pub db_path: String,
}

#[derive(Debug)]
pub enum ApiServerError {
    Io(std::io::Error),
    Db(String),
    InvalidRequest(String),
}

impl std::fmt::Display for ApiServerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiServerError::Io(error) => write!(formatter, "I/O error: {error}"),
            ApiServerError::Db(error) => write!(formatter, "database error: {error}"),
            ApiServerError::InvalidRequest(error) => write!(formatter, "invalid request: {error}"),
        }
    }
}

impl std::error::Error for ApiServerError {}

impl From<std::io::Error> for ApiServerError {
    fn from(error: std::io::Error) -> Self {
        ApiServerError::Io(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpRequest {
    method: String,
    target: String,
}

#[derive(Debug, Clone)]
struct HttpResponse {
    status_code: u16,
    status_text: &'static str,
    content_type: &'static str,
    body: String,
}

pub fn run_api_server(config: ApiServerConfig) -> Result<(), ApiServerError> {
    let listener = TcpListener::bind(config.listen_addr)?;

    println!("The Blocker API server is running");
    println!("  listening: {}", config.listen_addr);
    println!("  db: {}", config.db_path);
    println!();
    println!("Press Ctrl+C to stop.");
    println!();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_connection(stream, &config.db_path) {
                    eprintln!("API request failed: {error}");
                }
            }
            Err(error) => {
                eprintln!("API accept failed: {error}");
            }
        }
    }

    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    db_path: &str,
) -> Result<(), ApiServerError> {
    let mut buffer = [0u8; 16 * 1024];
    let read_len = stream.read(&mut buffer)?;

    if read_len == 0 {
        return Ok(());
    }

    let request_text = String::from_utf8_lossy(&buffer[..read_len]);
    let request = parse_http_request(&request_text)?;

    let response = handle_api_request(db_path, &request);
    let response_bytes = response.to_http_bytes();

    stream.write_all(&response_bytes)?;
    stream.flush()?;

    Ok(())
}

fn parse_http_request(request_text: &str) -> Result<HttpRequest, ApiServerError> {
    let first_line = request_text
        .lines()
        .next()
        .ok_or_else(|| ApiServerError::InvalidRequest("missing request line".to_string()))?;

    let mut parts = first_line.split_whitespace();

    let method = parts
        .next()
        .ok_or_else(|| ApiServerError::InvalidRequest("missing method".to_string()))?;

    let target = parts
        .next()
        .ok_or_else(|| ApiServerError::InvalidRequest("missing target".to_string()))?;

    Ok(HttpRequest {
        method: method.to_string(),
        target: target.to_string(),
    })
}

fn handle_api_request(db_path: &str, request: &HttpRequest) -> HttpResponse {
    if request.method == "OPTIONS" {
        return HttpResponse::no_content();
    }

    let (path, query) = split_target(&request.target);

    match (request.method.as_str(), path) {
        ("GET", "/health") => HttpResponse::json(
            200,
            "OK",
            r#"{"ok":true,"app":"The Blocker API"}"#.to_string(),
        ),

        ("GET", "/events") => {
            let limit = query_param(query, "limit")
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(50);

            match open_db(db_path).and_then(|db| db.recent_events(limit).map_err(|e| e.to_string())) {
                Ok(events) => HttpResponse::json(200, "OK", events_to_json(&events)),
                Err(error) => error_response(500, "Internal Server Error", &error),
            }
        }

        ("GET", "/blocked-domains") => {
            let limit = query_param(query, "limit")
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(50);

            match open_db(db_path).and_then(|db| {
                db.blocked_domain_summaries(limit)
                    .map_err(|error| error.to_string())
            }) {
                Ok(summaries) => {
                    HttpResponse::json(200, "OK", blocked_domain_summaries_to_json(&summaries))
                }
                Err(error) => error_response(500, "Internal Server Error", &error),
            }
        }

        ("GET", "/allowlist") => {
            match open_db(db_path).and_then(|db| db.list_allow_domains().map_err(|e| e.to_string())) {
                Ok(domains) => HttpResponse::json(200, "OK", domains_to_json("allowlist", &domains)),
                Err(error) => error_response(500, "Internal Server Error", &error),
            }
        }

        ("GET", "/blocklist") => {
            match open_db(db_path).and_then(|db| {
                db.list_block_domains()
                    .map_err(|error| error.to_string())
            }) {
                Ok(domains) => HttpResponse::json(
                    200,
                    "OK",
                    domains_to_json("blocklist", &domains),
                ),
                Err(error) => error_response(500, "Internal Server Error", &error),
            }
        }

        ("GET", "/status") => {
            match open_db(db_path).and_then(|db| {
                let protection_enabled = db
                    .is_protection_enabled()
                    .map_err(|error| error.to_string())?;

                Ok(protection_enabled)
            }) {
                Ok(protection_enabled) => HttpResponse::json(
                    200,
                    "ok",
                    format!(
                        r#"{{"ok":true,"protection_enabled":{}}}"#,
                        protection_enabled
                    ),
                ),
                Err(error) => error_response(500, "Internal Server Error", &error),
            }
        }

        ("GET", "/blocked-response") => {
            HttpResponse::json(
                500,
                "Internal Server Error",
                r#"{"ok":false,"blocked":true,"error":"blocked_by_the_blocker"}"#.to_string(),
            )
        }

        ("POST", "/blocklist/add") => {
            let Some(domain) = query_param(query, "domain") else {
                return error_response(400, "Bad Request", "missing domain");
            };

            match open_db(db_path).and_then(|db| {
                db.remove_allow_domain(&domain)
                    .map_err(|error| error.to_string())?;

                db.add_block_domain(&domain)
                    .map_err(|error| error.to_string())
            }) {
                Ok(added) => HttpResponse::json(
                    200,
                    "OK",
                    format!(
                        r#"{{"ok":true,"domain":"{}","added":{}}}"#,
                        json_escape(&domain),
                        added
                    ),
                ),
                Err(error) => error_response(500, "Internal Server Error", &error),
            }
        }

        ("POST", "/blocklist/remove") => {
            let Some(domain) = query_param(query, "domain") else {
                return error_response(400, "Bad Request", "missing domain");
            };

            match open_db(db_path).and_then(|db| {
                db.remove_block_domain(&domain)
                    .map_err(|error| error.to_string())
            }) {
                Ok(removed) => HttpResponse::json(
                    200,
                    "Ok",
                    format!(
                        r#"{{"ok":true,"domain":"{}","removed":{}}}"#,
                        json_escape(&domain),
                        removed
                    ),
                ),
                Err(error) => error_response(500, "Internal Server Error", &error),
            }
        }

        ("POST", "/allow") => {
            let Some(domain) = query_param(query, "domain") else {
                return error_response(400, "Bad Request", "missing domain");
            };

            match open_db(db_path).and_then(|db| {
                db.remove_block_domain(&domain)
                    .map_err(|error| error.to_string())?;

                db.add_allow_domain(&domain)
                    .map_err(|error| error.to_string())
            }) {
                Ok(added) => HttpResponse::json(
                    200,
                    "Ok",
                    format!(
                        r#"{{"ok":true,"domain":"{}","added":{}}}"#,
                        json_escape(&domain),
                        added
                    ),
                ),
                Err(error) => error_response(500, "Internal Server Error", &error),
            }
        }

        ("POST", "/unallow") => {
            let Some(domain) = query_param(query, "domain") else {
                return error_response(400, "Bad Request", "missing domain query parameter");
            };

            match open_db(db_path).and_then(|db| db.remove_allow_domain(&domain).map_err(|e| e.to_string())) {
                Ok(removed) => HttpResponse::json(
                    200,
                    "OK",
                    format!(
                        r#"{{"ok":true,"domain":"{}","removed":{}}}"#,
                        json_escape(&domain),
                        removed
                    ),
                ),
                Err(error) => error_response(500, "Internal Server Error", &error),
            }
        }

        ("POST", "/protection/enable") => {
            match open_db(db_path).and_then(|db| {
                db.set_protection_enabled(true)
                    .map_err(|error| error.to_string())
            }) {
                Ok(()) => HttpResponse::json(
                    200,
                    "OK",
                    r#"{"ok":true,"protection_enabled":true}"#.to_string(),
                ),
                Err(error) => error_response(500, "Internal Server Error", &error),
            }
        }

        ("POST", "/protection/disable") => {
            match open_db(db_path).and_then(|db| {
                db.set_protection_enabled(false)
                    .map_err(|error| error.to_string())
            }) {
                Ok(()) => HttpResponse::json(
                    200,
                    "OK",
                    r#"{"ok":true,"protection_enabled":false}"#.to_string(),
                ),
                Err(error) => error_response(500, "Internal Server Error", &error),
            }
        }

        _ => error_response(404, "Not Found", "route not found"),
    }
}

fn open_db(db_path: &str) -> Result<BlockerDb, String> {
    BlockerDb::open(db_path).map_err(|error| error.to_string())
}

fn split_target(target: &str) -> (&str, Option<&str>) {
    if let Some((path, query)) = target.split_once('?') {
        (path, Some(query))
    } else {
        (target, None)
    }
}

fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    let query = query?;

    for part in query.split('&') {
        let (name, value) = part.split_once('=').unwrap_or((part, ""));

        if percent_decode(name) == key {
            return Some(percent_decode(value));
        }
    }

    None
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = Vec::new();
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let high = from_hex(bytes[index + 1]);
                let low = from_hex(bytes[index + 2]);

                if let (Some(high), Some(low)) = (high, low) {
                    output.push((high << 4) | low);
                    index += 3;
                } else {
                    output.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&output).into_owned()
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn events_to_json(events: &[StoredBlockEvent]) -> String {
    let items = events
        .iter()
        .map(event_to_json)
        .collect::<Vec<_>>()
        .join(",");

    format!(r#"{{"events":[{items}]}}"#)
}

fn event_to_json(event: &StoredBlockEvent) -> String {
    format!(
        r#"{{
"id":{},
"domain":"{}",
"action":"{}",
"matched_rule":{},
"rule_source":{},
"category":{},
"occurred_at_unix":{}
}}"#,
        event.id,
        json_escape(&event.domain),
        json_escape(&event.action),
        json_optional_string(event.matched_rule.as_deref()),
        json_optional_string(event.rule_source.as_deref()),
        json_optional_string(event.category.as_deref()),
        event.occurred_at_unix,
    )
    .replace('\n', "")
}

fn domains_to_json(key: &str, domains: &[String]) -> String {
    let items = domains
        .iter()
        .map(|domain| format!(r#""{}""#, json_escape(domain)))
        .collect::<Vec<_>>()
        .join(",");

    format!(r#"{{"{key}":[{items}]}}"#)
}

fn json_optional_string(value: Option<&str>) -> String {
    match value {
        Some(value) => format!(r#""{}""#, json_escape(value)),
        None => "null".to_string(),
    }
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::new();

    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", ch as u32));
            }
            ch => escaped.push(ch),
        }
    }

    escaped
}

fn error_response(
    status_code: u16,
    status_text: &'static str,
    message: &str,
) -> HttpResponse {
    HttpResponse::json(
        status_code,
        status_text,
        format!(
            r#"{{"ok":false,"error":"{}"}}"#,
            json_escape(message)
        ),
    )
}

fn blocked_domain_summaries_to_json(summaries: &[BlockedDomainSummary]) -> String {
    let items = summaries
        .iter()
        .map(blocked_domain_summary_to_json)
        .collect::<Vec<_>>()
        .join(",");

    format!(r#"{{"blocked_domains":[{items}]}}"#)
}

fn blocked_domain_summary_to_json(summary: &BlockedDomainSummary) -> String {
    format!(
        r#"{{
        "domain":"{}",
        "block_count":{},
        "last_blocked_at_unix":{},
        "matched_rule":{},
        "rule_source":{},
        "category":{}
        }}"#,
        json_escape(&summary.domain),
        summary.block_count,
        summary.last_blocked_at_unix,
        json_optional_string(summary.matched_rule.as_deref()),
        json_optional_string(summary.rule_source.as_deref()),
        json_optional_string(summary.category.as_deref()),
    )
    .replace('\n', "")
}

impl HttpResponse {
    fn json(status_code: u16, status_text: &'static str, body: String) -> Self {
        Self {
            status_code,
            status_text,
            content_type: "application/json; charset=utf-8",
            body,
        }
    }

    fn no_content() -> Self {
        Self {
            status_code: 204,
            status_text: "No Content",
            content_type: "text/plain; charset=utf-8",
            body: String::new(),
        }
    }

    fn to_http_bytes(&self) -> Vec<u8> {
        let response = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
             Access-Control-Allow-Headers: Content-Type\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            self.status_code,
            self.status_text,
            self.content_type,
            self.body.as_bytes().len(),
            self.body,
        );

        response.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_query_params() {
        let query = Some("domain=ads.example.com&limit=10");

        assert_eq!(
            query_param(query, "domain"),
            Some("ads.example.com".to_string())
        );
        assert_eq!(query_param(query, "limit"), Some("10".to_string()));
    }

    #[test]
    fn decodes_percent_values() {
        assert_eq!(percent_decode("safe%2Eexample%2Ecom"), "safe.example.com");
        assert_eq!(percent_decode("hello+world"), "hello world");
    }

    #[test]
    fn escapes_json_strings() {
        assert_eq!(json_escape(r#"a"b\c"#), r#"a\"b\\c"#);
    }
}