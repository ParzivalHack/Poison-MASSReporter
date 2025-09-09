use crate::ast_parser::AstNode;
use crate::graph::representation::{ControlFlowGraph, BlockId};
use crate::issues::Issue;
use crate::rules::RuleSet;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Taint {
    source_rule_id: String,
}

type TaintState = HashMap<String, Taint>; // Variable name -> Taint info

pub fn analyze_function(cfg: &ControlFlowGraph, ruleset: &RuleSet, file_path: &str, content: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut block_taint_in: HashMap<BlockId, TaintState> = HashMap::new();
    let mut block_taint_out: HashMap<BlockId, TaintState> = HashMap::new();

    let mut worklist: Vec<BlockId> = cfg.blocks.keys().cloned().collect();
    worklist.sort_by(|a, b| b.cmp(a)); // Process in reverse order for efficiency

    // Initialize all taint states to empty
    for id in cfg.blocks.keys() {
        block_taint_in.insert(*id, TaintState::new());
        block_taint_out.insert(*id, TaintState::new());
    }

    let mut changed = true;
    while changed {
        changed = false;
        for block_id in &worklist {
            // Merge taint from predecessors
            let mut new_in_taint = TaintState::new();
            if let Some(block) = cfg.blocks.get(block_id) {
                for pred_id in &block.predecessors {
                    if let Some(pred_out) = block_taint_out.get(pred_id) {
                        for (var, taint) in pred_out {
                            new_in_taint.insert(var.clone(), taint.clone());
                        }
                    }
                }
            }

            if block_taint_in.get(block_id) != Some(&new_in_taint) {
                block_taint_in.insert(*block_id, new_in_taint.clone());
            }

            let mut current_taint = new_in_taint;
            let block = &cfg.blocks[block_id];

            for stmt in &block.statements {
                // Handle assignments to propagate taint
                if stmt.node_type == "Assign" {
                    let targets = stmt.children.get("targets").and_then(|t| t.get(0));
                    let value = stmt.children.get("value").and_then(|v| v.get(0));

                    if let (Some(target), Some(value_node)) = (targets, value) {
                        let target_name = get_name_from_node(target);
                        
                        // Check for new sources
                        if value_node.node_type == "Call" {
                            let func_name = get_full_call_name(value_node);
                            for source_rule in &ruleset.taint_sources {
                                if func_name == source_rule.function_call {
                                    if let Some(name) = &target_name {
                                        current_taint.insert(name.clone(), Taint { source_rule_id: source_rule.id.clone() });
                                    }
                                }
                            }
                        }

                        // NEW: Handle propagation through f-strings (JoinedStr)
                        if value_node.node_type == "JoinedStr" {
                             if let Some(values) = value_node.children.get("values") {
                                for formatted_val in values {
                                    if let Some(inner_val) = formatted_val.children.get("value").and_then(|v| v.get(0)) {
                                        if let Some(name) = get_name_from_node(inner_val) {
                                            if let (Some(taint), Some(target)) = (current_taint.get(&name), &target_name) {
                                                current_taint.insert(target.clone(), taint.clone());
                                                break; // Taint the whole f-string if one part is tainted
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Check for sinks
                if stmt.node_type == "Expr" {
                    if let Some(call_node) = stmt.children.get("value").and_then(|v| v.get(0)) {
                        if call_node.node_type == "Call" {
                            let func_name = get_full_call_name(call_node);
                            for sink_rule in &ruleset.taint_sinks {
                                if func_name == sink_rule.function_call {
                                    if let Some(arg) = call_node.children.get("args").and_then(|a| a.get(sink_rule.vulnerable_parameter_index)) {
                                        if let Some(arg_name) = get_name_from_node(arg) {
                                            if current_taint.contains_key(&arg_name) {
                                                report_issue(ruleset, &sink_rule.vulnerability_id, file_path, stmt, content, &mut issues);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            if block_taint_out.get(block_id) != Some(&current_taint) {
                block_taint_out.insert(*block_id, current_taint);
                changed = true;
            }
        }
    }
    
    issues
}

// Helper to get a variable name from an AST node
fn get_name_from_node(node: &AstNode) -> Option<String> {
    if node.node_type == "Name" {
        return node.fields.get("id").and_then(|v| v.as_ref()).and_then(|v| v.as_str().map(String::from));
    }
    None
}

// Helper to get a full call name like "module.function"
fn get_full_call_name(call_node: &AstNode) -> String {
    if let Some(func) = call_node.children.get("func").and_then(|v| v.get(0)) {
        match func.node_type.as_str() {
            "Name" => get_name_from_node(func).unwrap_or_default(),
            "Attribute" => {
                let value_name = func.children.get("value").and_then(|v| v.get(0))
                    .and_then(|n| get_name_from_node(n)).unwrap_or_default();
                let attr_name = func.fields.get("attr").and_then(|v| v.as_ref()).and_then(|v| v.as_str()).unwrap_or_default();
                format!("{}.{}", value_name, attr_name)
            }
            _ => String::new(),
        }
    } else {
        String::new()
    }
}

// Helper to create and push an issue
fn report_issue(ruleset: &RuleSet, vuln_id: &str, file_path: &str, stmt: &AstNode, content: &str, issues: &mut Vec<Issue>) {
    if let Some(vuln_rule) = ruleset.rules.iter().find(|r| r.id == *vuln_id) {
        let line_content = content.lines().nth(stmt.lineno.saturating_sub(1) as usize).unwrap_or("").to_string();
        issues.push(Issue::new(
            vuln_rule.id.clone(),
            vuln_rule.description.clone(),
            file_path.to_string(),
            stmt.lineno as usize,
            line_content,
            vuln_rule.severity.clone(),
            vuln_rule.confidence.clone(),
            vuln_rule.remediation.clone(),
        ));
    }
}