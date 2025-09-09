use crate::issues::{Issue, Severity};
use crate::rules::RuleSet;

pub fn scan_file(file_path: &str, content: &str, ruleset: &RuleSet) -> Vec<Issue> {
    let mut issues = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    for rule in &ruleset.rules {
        // Match file pattern if specified
        if let Some(file_pattern) = &rule.file_pattern {
            if !wildmatch::WildMatch::new(file_pattern).matches(file_path) {
                continue;
            }
        }

        // Regex pattern matching
        if let Some(pattern) = &rule.pattern {
            for (i, line) in lines.iter().enumerate() {
                if pattern.is_match(line) {
                    issues.push(Issue::new(
                        rule.id.clone(),
                        rule.description.clone(),
                        file_path.to_string(),
                        i + 1,
                        line.to_string(),
                        rule.severity.clone(),
                        rule.confidence.clone(),
                        rule.remediation.clone(),
                    ));
                }
            }
        }
    }

    issues
}