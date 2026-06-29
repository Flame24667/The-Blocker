use crate::{normalize_domain, BlockAction, BlockEvent, BlockerError, Rule, RuleSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockDecision {
    Blocked {
        domain: String,
        matched_rule: String,
        source: Option<String>,
        category: Option<String>,
    },
    Allowed {
        domain: String,
        matched_rule: String,
        source: Option<String>,
    },
    AllowedByDefault,
}

#[derive(Debug, Clone, Default)]
pub struct BlockerEngine {
    blocklist: RuleSet,
    allowlist: RuleSet,
}

impl BlockerEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_rules(blocklist: RuleSet, allowlist: RuleSet) -> Self {
        Self { blocklist, allowlist }
    }

    pub fn add_block_rule(
        &mut self,
        domain: &str,
        source: Option<&str>,
        category: Option<&str>,
    ) -> Result<(), BlockerError> {
        self.blocklist.add(Rule::new(domain, source, category)?);
        Ok(())
    }

    pub fn add_allow_rule(
        &mut self,
        domain: &str,
        source: Option<&str>,
        category: Option<&str>,
    ) -> Result<(), BlockerError> {
        self.allowlist.add(Rule::new(domain, source, category)?);
        Ok(())
    }

    pub fn remove_allow_rule(&mut self, domain: &str) -> Result<bool, BlockerError> {
        self.allowlist.remove(domain)
    }

    pub fn check_domain(&self, raw_domain: &str) -> Result<BlockDecision, BlockerError> {
        let domain = normalize_domain(raw_domain)?;

        if let Some(rule) = self.allowlist.find_match(&domain)? {
            return Ok(BlockDecision::Allowed {
                domain,
                matched_rule: rule.domain().to_string(),
                source: rule.source().map(str::to_string),
            });
        }

        if let Some(rule) = self.blocklist.find_match(&domain)? {
            return Ok(BlockDecision::Blocked {
                domain,
                matched_rule: rule.domain().to_string(),
                source: rule.source().map(str::to_string),
                category: rule.category().map(str::to_string),
            });
        }

        Ok(BlockDecision::AllowedByDefault)
    }

    pub fn check_domain_with_event(&self, raw_domain: &str) -> Result<BlockEvent, BlockerError> {
        let normalized = normalize_domain(raw_domain)?;

        match self.check_domain(&normalized)? {
            BlockDecision::Blocked {
                matched_rule,
                source,
                category,
                ..
            } => Ok(BlockEvent::new(
                normalized,
                BlockAction::Blocked,
                Some(matched_rule),
                source,
                category,
            )),
            BlockDecision::Allowed {
                matched_rule,
                source,
                ..
            } => Ok(BlockEvent::new(
                normalized,
                BlockAction::AllowedByUserRule,
                Some(matched_rule),
                source,
                None,
            )),
            BlockDecision::AllowedByDefault => Ok(BlockEvent::new(
                normalized,
                BlockAction::AllowedByDefault,
                None,
                None,
                None,
            )),
        }
    }

    pub fn blocklist(&self) -> &RuleSet {
        &self.blocklist
    }

    pub fn allowlist(&self) -> &RuleSet {
        &self.allowlist
    }

    pub fn load_rules_from_text(
        &mut self,
        text: &str,
        source: Option<&str>,
        category: Option<&str>,
    ) -> crate::RuleLoadReport {
        let loaded = crate::load_rules_from_text(text, source, category);

        let mut report = loaded.report;
        report.added_block_rules = 0;
        report.added_allow_rules = 0;

        for rule in loaded.blocklist.iter() {
            if self.blocklist.add(rule.clone()) {
                report.added_block_rules += 1;
            }
        }

        for rule in loaded.allowlist.iter() {
            if self.allowlist.add(rule.clone()) {
                report.added_allow_rules += 1;
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_decision_contains_rule_metadata() {
        let mut engine = BlockerEngine::new();
        engine
            .add_block_rule("tracker.example.com", Some("easyprivacy"), Some("tracker"))
            .unwrap();

        let decision = engine.check_domain("tracker.example.com").unwrap();

        assert_eq!(
            decision,
            BlockDecision::Blocked {
                domain: "tracker.example.com".to_string(),
                matched_rule: "tracker.example.com".to_string(),
                source: Some("easyprivacy".to_string()),
                category: Some("tracker".to_string()),
            }
        );
    }

    #[test]
    fn event_maps_blocked_decision() {
        let mut engine = BlockerEngine::new();
        engine.add_block_rule("ads.example.com", Some("test"), Some("ad")).unwrap();

        let event = engine.check_domain_with_event("ads.example.com").unwrap();
        assert_eq!(event.action, BlockAction::Blocked);
        assert_eq!(event.matched_rule.as_deref(), Some("ads.example.com"));
    }

    #[test]
    fn engine_loads_rules_from_text() {
        let mut engine = BlockerEngine::new();

        let text = r#"
        ||doubleclick.net^
        @@||safe.doubleclick.net^
        "#;

        let report = engine.load_rules_from_text(text, Some("test-list"), Some("tracker"));

        assert_eq!(report.added_block_rules, 1);
        assert_eq!(report.added_allow_rules, 1);

        let blocked = engine.check_domain("ads.doubleclick.net").unwrap();
        assert!(matches!(blocked, BlockDecision::Blocked { .. }));

        let allowed = engine.check_domain("safe.doubleclick.net").unwrap();
        assert!(matches!(allowed, BlockDecision::Allowed { .. }));
    }
}
