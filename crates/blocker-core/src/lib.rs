//! Core blocking engine for The Blocker.
//!
//! This crate intentionally has no platform-specific code. Windows service,
//! DNS resolver, tray UI, Android VPN service, and future platform integrations
//! should call this engine instead of duplicating blocking logic.

mod domain;
mod engine;
mod error;
mod event;
mod loader;
mod rule;

pub use domain::normalize_domain;
pub use engine::{BlockDecision, BlockerEngine};
pub use error::BlockerError;
pub use event::{BlockAction, BlockEvent};
pub use loader::{load_rules_from_text, LoadedRules, RuleLoadIssue, RuleLoadReport};
pub use rule::{Rule, RuleSet};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_overrides_blocklist() {
        let mut engine = BlockerEngine::new();
        engine.add_block_rule("ads.example.com", Some("test"), Some("ad")).unwrap();
        engine.add_allow_rule("ads.example.com", Some("user"), None).unwrap();

        let decision = engine.check_domain("ads.example.com").unwrap();
        assert!(matches!(decision, BlockDecision::Allowed { .. }));
    }

    #[test]
    fn parent_domain_rule_matches_subdomain() {
        let mut engine = BlockerEngine::new();
        engine.add_block_rule("doubleclick.net", Some("test"), Some("tracker")).unwrap();

        let decision = engine.check_domain("stats.doubleclick.net").unwrap();
        assert!(matches!(decision, BlockDecision::Blocked { .. }));
    }

    #[test]
    fn unrelated_domain_is_allowed_by_default() {
        let engine = BlockerEngine::new();
        let decision = engine.check_domain("example.org").unwrap();
        assert_eq!(decision, BlockDecision::AllowedByDefault);
    }
}
