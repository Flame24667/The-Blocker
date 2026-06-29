use crate::{Rule, RuleSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleLoadIssue {
    pub line_number: usize,
    pub line: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleLoadReport {
    pub added_block_rules: usize,
    pub added_allow_rules: usize,
    pub ignored_lines: usize,
    pub skipped_rules: Vec<RuleLoadIssue>,
}

impl RuleLoadReport {
    pub fn total_added(&self) -> usize {
        self.added_block_rules + self.added_allow_rules
    }

    pub fn skipped_count(&self) -> usize {
        self.skipped_rules.len()
    }
}

#[derive(Debug, Clone)]
pub struct LoadedRules {
    pub blocklist: RuleSet,
    pub allowlist: RuleSet,
    pub report: RuleLoadReport,
}

pub fn load_rules_from_text(
    text: &str,
    source: Option<&str>,
    category: Option<&str>,
) -> LoadedRules {
    let mut blocklist = RuleSet::new();
    let mut allowlist = RuleSet::new();
    let mut report = RuleLoadReport::default();

    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;

        match parse_rule_line(raw_line) {
            ParsedLine::Ignore => {
                report.ignored_lines += 1;
            }
            ParsedLine::Skip(reason) => {
                report.skipped_rules.push(RuleLoadIssue {
                    line_number,
                    line: raw_line.to_string(),
                    reason,
                });
            }
            ParsedLine::Rule {
                domain,
                is_allow_rule,
            } => {
                let rule = match Rule::new(&domain, source, category) {
                    Ok(rule) => rule,
                    Err(_) => {
                        report.skipped_rules.push(RuleLoadIssue {
                            line_number,
                            line: raw_line.to_string(),
                            reason: "invalid domain rule".to_string(),
                        });
                        continue;
                    }
                };

                if is_allow_rule {
                    if allowlist.add(rule) {
                        report.added_allow_rules += 1;
                    }
                } else if blocklist.add(rule) {
                    report.added_block_rules += 1;
                }
            }
        }
    }

    LoadedRules {
        blocklist,
        allowlist,
        report,
    }
}

enum ParsedLine {
    Ignore,
    Skip(String),
    Rule {
        domain: String,
        is_allow_rule: bool,
    },
}

fn parse_rule_line(raw_line: &str) -> ParsedLine {
    let line = raw_line.trim();

    if line.is_empty() {
        return ParsedLine::Ignore;
    }

    if line.starts_with('#') || line.starts_with('!') || line.starts_with('[') {
        return ParsedLine::Ignore;
    }

    if is_cosmetic_filter(line) {
        return ParsedLine::Skip(
            "cosmetic filter syntax is not supported by DNS-level blocking".to_string(),
        );
    }

    let line = strip_inline_comment(line).trim();

    if line.is_empty() {
        return ParsedLine::Ignore;
    }

    let (is_allow_rule, candidate) = if let Some(rest) = line.strip_prefix("@@") {
        (true, rest.trim())
    } else {
        (false, line)
    };

    let candidate = if let Some((before_options, _options)) = candidate.split_once('$') {
        before_options.trim()
    } else {
        candidate
    };

    if let Some(domain) = parse_hosts_line(candidate) {
        return ParsedLine::Rule {
            domain,
            is_allow_rule,
        };
    }

    if let Some(domain) = parse_adblock_domain_anchor(candidate) {
        return ParsedLine::Rule {
            domain,
            is_allow_rule,
        };
    }

    if looks_like_plain_domain_candidate(candidate) {
        return ParsedLine::Rule {
            domain: clean_plain_domain_candidate(candidate),
            is_allow_rule,
        };
    }

    ParsedLine::Skip("unsupported rule syntax".to_string())
}

fn strip_inline_comment(line: &str) -> &str {
    let space_comment = line.find(" #");
    let tab_comment = line.find("\t#");

    match (space_comment, tab_comment) {
        (Some(a), Some(b)) => &line[..a.min(b)],
        (Some(a), None) => &line[..a],
        (None, Some(b)) => &line[..b],
        (None, None) => line,
    }
}

fn is_cosmetic_filter(line: &str) -> bool {
    line.contains("##")
        || line.contains("#@#")
        || line.contains("#?#")
        || line.contains("#$#")
}

fn parse_hosts_line(line: &str) -> Option<String> {
    let mut parts = line.split_whitespace();

    let first = parts.next()?;
    let second = parts.next()?;

    if is_redirect_address(first) && !second.eq_ignore_ascii_case("localhost") {
        Some(second.to_string())
    } else {
        None
    }
}

fn is_redirect_address(value: &str) -> bool {
    value == "0.0.0.0"
        || value == "::"
        || value == "::1"
        || value == "127.0.0.1"
        || value.starts_with("127.")
}

fn parse_adblock_domain_anchor(line: &str) -> Option<String> {
    let rest = line.strip_prefix("||")?;

    let mut domain = String::new();

    for ch in rest.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            domain.push(ch);
        } else {
            break;
        }
    }

    let domain = domain
    .trim()
    .trim_start_matches('.')
    .trim_end_matches('.');

    if domain.is_empty() {
        None
    } else {
        Some(domain.to_string())
    }
}

fn looks_like_plain_domain_candidate(candidate: &str) -> bool {
    let candidate = candidate.trim();

    if candidate.is_empty() {
        return false;
    }

    if candidate.split_whitespace().count() != 1 {
        return false;
    }

    if candidate.starts_with('/') {
        return false;
    }

    if candidate.contains('*') && !candidate.starts_with("*.") {
        return false;
    }

    if candidate.contains('^') && !candidate.ends_with('^') {
        return false;
    }

    if candidate.contains('|') && !candidate.ends_with('|') {
        return false;
    }

    if candidate.contains('/')
        && !candidate.starts_with("http://")
        && !candidate.starts_with("https://")
    {
        return false;
    }

    true
}

fn clean_plain_domain_candidate(candidate: &str) -> String {
    candidate
        .trim()
        .trim_start_matches("*.")
        .trim_end_matches('^')
        .trim_end_matches('|')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_plain_domain_rules() {
        let text = r#"
            ads.example.com
            tracker.example.com
        "#;

        let loaded = load_rules_from_text(text, Some("test-list"), Some("ad"));

        assert_eq!(loaded.report.added_block_rules, 2);
        assert_eq!(loaded.report.added_allow_rules, 0);
        assert!(loaded.blocklist.find_match("ads.example.com").unwrap().is_some());
    }

    #[test]
    fn loads_hosts_file_rules() {
        let text = r#"
            0.0.0.0 ads.example.com
            127.0.0.1 tracker.example.com
        "#;

        let loaded = load_rules_from_text(text, Some("hosts"), Some("tracker"));

        assert_eq!(loaded.report.added_block_rules, 2);
        assert!(loaded.blocklist.find_match("tracker.example.com").unwrap().is_some());
    }

    #[test]
    fn loads_adblock_domain_anchor_rules() {
        let text = r#"
            ||doubleclick.net^
            ||analytics.example.com^$script,third-party
        "#;

        let loaded = load_rules_from_text(text, Some("adblock-style"), Some("tracker"));

        assert_eq!(loaded.report.added_block_rules, 2);
        assert!(loaded.blocklist.find_match("ads.doubleclick.net").unwrap().is_some());
        assert!(loaded.blocklist.find_match("analytics.example.com").unwrap().is_some());
    }

    #[test]
    fn loads_exception_rules_as_allowlist() {
        let text = r#"
            ||ads.example.com^
            @@||safe.ads.example.com^
        "#;

        let loaded = load_rules_from_text(text, Some("test-list"), Some("ad"));

        assert_eq!(loaded.report.added_block_rules, 1);
        assert_eq!(loaded.report.added_allow_rules, 1);
        assert!(loaded.blocklist.find_match("ads.example.com").unwrap().is_some());
        assert!(loaded.allowlist.find_match("safe.ads.example.com").unwrap().is_some());
    }

    #[test]
    fn skips_cosmetic_filters() {
        let text = r#"
            example.com##.ad-banner
            ads.example.com
        "#;

        let loaded = load_rules_from_text(text, Some("test-list"), Some("ad"));

        assert_eq!(loaded.report.added_block_rules, 1);
        assert_eq!(loaded.report.skipped_count(), 1);
    }

    #[test]
    fn ignores_comments_and_empty_lines() {
        let text = r#"
            # hosts comment
            ! adblock comment

            ads.example.com # inline comment
        "#;

        let loaded = load_rules_from_text(text, Some("test-list"), Some("ad"));

        assert_eq!(loaded.report.added_block_rules, 1);
        assert!(loaded.report.ignored_lines >= 3);
    }
}