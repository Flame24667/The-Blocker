use crate::{normalize_domain, BlockerError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    domain: String,
    source: Option<String>,
    category: Option<String>,
}

impl Rule {
    pub fn new(
        raw_domain: &str,
        source: Option<&str>,
        category: Option<&str>,
    ) -> Result<Self, BlockerError> {
        let cleaned = raw_domain
            .trim()
            .strip_prefix("*.")
            .unwrap_or(raw_domain.trim());

        let domain = normalize_domain(cleaned)
            .map_err(|_| BlockerError::InvalidRule(raw_domain.to_string()))?;

        Ok(Self {
            domain,
            source: source.map(str::to_string),
            category: category.map(str::to_string),
        })
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    pub fn category(&self) -> Option<&str> {
        self.category.as_deref()
    }

    pub fn matches(&self, query_domain: &str) -> bool {
        query_domain == self.domain
            || query_domain
                .strip_suffix(&self.domain)
                .is_some_and(|prefix| prefix.ends_with('.'))
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    // pub fn add(&mut self, rule: Rule) {
    //     if !self.rules.iter().any(|existing| existing.domain == rule.domain) {
    //         self.rules.push(rule);
    //     }
    // }
    pub fn add(&mut self, rule: Rule) -> bool {
        if self.rules.iter().any(|existing| existing.domain == rule.domain) {
            return false;
        }

        self.rules.push(rule);
        true
    }

    pub fn remove(&mut self, raw_domain: &str) -> Result<bool, BlockerError> {
        let domain = normalize_domain(raw_domain)?;
        let before = self.rules.len();
        self.rules.retain(|rule| rule.domain != domain);
        Ok(self.rules.len() != before)
    }

    pub fn find_match(&self, raw_domain: &str) -> Result<Option<&Rule>, BlockerError> {
        let domain = normalize_domain(raw_domain)?;
        Ok(self.rules.iter().find(|rule| rule.matches(&domain)))
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_matches_root_and_subdomains() {
        let rule = Rule::new("example.com", None, None).unwrap();
        assert!(rule.matches("example.com"));
        assert!(rule.matches("ads.example.com"));
        assert!(rule.matches("a.b.example.com"));
        assert!(!rule.matches("fakeexample.com"));
    }

    #[test]
    fn wildcard_prefix_is_accepted() {
        let rule = Rule::new("*.example.com", None, None).unwrap();
        assert_eq!(rule.domain(), "example.com");
    }

    #[test]
    fn duplicate_rules_are_ignored() {
        let mut set = RuleSet::new();
        set.add(Rule::new("example.com", None, None).unwrap());
        set.add(Rule::new("EXAMPLE.COM", None, None).unwrap());
        assert_eq!(set.len(), 1);
    }
}
