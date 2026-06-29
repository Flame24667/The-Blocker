use crate::BlockerError;

/// Normalize user input or DNS query names into a canonical domain.
///
/// Accepted examples:
/// - `Ads.Example.Com.` -> `ads.example.com`
/// - `https://ads.example.com/path` -> `ads.example.com`
/// - `ads.example.com:443` -> `ads.example.com`
///
/// This intentionally stays ASCII-only for the first core milestone.
/// IDN/punycode support can be added later with a dedicated dependency.
pub fn normalize_domain(input: &str) -> Result<String, BlockerError> {
    let mut value = input.trim();

    if value.is_empty() {
        return Err(BlockerError::EmptyDomain);
    }

    // Strip URL scheme if a full URL was pasted into allowlist/blocklist UI.
    if let Some(scheme_pos) = value.find("://") {
        value = &value[(scheme_pos + 3)..];
    }

    // Strip path/query/fragment.
    let end = value
        .find(|c| matches!(c, '/' | '?' | '#'))
        .unwrap_or(value.len());
    value = &value[..end];

    // Strip userinfo if present: user:pass@example.com
    if let Some(at_pos) = value.rfind('@') {
        value = &value[(at_pos + 1)..];
    }

    // Strip port for ordinary domain:port input.
    // IPv6 is not handled here because ad/tracker rules are domain-based.
    if let Some(colon_pos) = value.rfind(':') {
        if value[colon_pos + 1..].chars().all(|c| c.is_ascii_digit()) {
            value = &value[..colon_pos];
        }
    }

    let value = value
        .trim()
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();

    validate_domain(&value)?;
    Ok(value)
}

fn validate_domain(domain: &str) -> Result<(), BlockerError> {
    if domain.is_empty() {
        return Err(BlockerError::EmptyDomain);
    }

    if domain.len() > 253 {
        return Err(BlockerError::InvalidDomain(domain.to_string()));
    }

    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(BlockerError::InvalidDomain(domain.to_string()));
        }

        let valid_chars = label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');

        if !valid_chars || label.starts_with('-') || label.ends_with('-') {
            return Err(BlockerError::InvalidDomain(domain.to_string()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_trailing_dot() {
        assert_eq!(normalize_domain("Ads.Example.Com.").unwrap(), "ads.example.com");
    }

    #[test]
    fn normalizes_url_input() {
        assert_eq!(
            normalize_domain("https://ads.example.com/path?x=1").unwrap(),
            "ads.example.com"
        );
    }

    #[test]
    fn normalizes_port_input() {
        assert_eq!(normalize_domain("ads.example.com:443").unwrap(), "ads.example.com");
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(normalize_domain("   "), Err(BlockerError::EmptyDomain));
    }
}
