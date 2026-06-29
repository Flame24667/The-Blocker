use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockAction {
    Blocked,
    AllowedByUserRule,
    AllowedByDefault,
}

#[derive(Debug, Clone)]
pub struct BlockEvent {
    pub domain: String,
    pub action: BlockAction,
    pub matched_rule: Option<String>,
    pub rule_source: Option<String>,
    pub category: Option<String>,
    pub occurred_at: SystemTime,
}

impl BlockEvent {
    pub fn new(
        domain: String,
        action: BlockAction,
        matched_rule: Option<String>,
        rule_source: Option<String>,
        category: Option<String>,
    ) -> Self {
        Self {
            domain,
            action,
            matched_rule,
            rule_source,
            category,
            occurred_at: SystemTime::now(),
        }
    }
}
