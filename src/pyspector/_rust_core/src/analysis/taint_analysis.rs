use crate::ast_parser::AstNode;
use crate::graph::call_graph_builder::CallGraph;
use crate::issues::Issue;
use crate::rules::RuleSet;
use std::collections::HashSet;

// Main entry point for inter-procedural taint analysis
pub fn analyze_program_for_taint(call_graph: &CallGraph, ruleset: &RuleSet) -> Vec<Issue> {
    println!("[*] Starting taint analysis with {} functions", call_graph.functions.len());
    println!("[+] Taint sources: {}, sinks: {}", ruleset.taint_sources.len(), ruleset.taint_sinks.len());
    
    let mut issues = Vec::new();
    let mut tainted_vars: HashSet<(String, String)> = HashSet::new(); // (func_id, var_name)

    // First pass: find all initial sources across all functions
    for (func_id, func_node) in &call_graph.functions {
        println!("[*] Analyzing function: {}", func_id);
        let mut assignments = Vec::new();
        find_assignments(func_node, &mut assignments);
        
        for assign_node in assignments {
            if let Some(value_node) = assign_node.children.get("value").and_then(|v| v.get(0)) {
                if value_node.node_type == "Call" {
                    let call_name = get_full_call_name(value_node);
                    println!("[+] Found call: {}", call_name);
                    
                    for source in &ruleset.taint_sources {
                        if call_name.contains(&source.function_call) || source.function_call.contains(&call_name) {
                            println!("[+] Found taint source: {} matches {}", call_name, source.function_call);
                            
                            if let Some(targets) = assign_node.children.get("targets") {
                                for target in targets {
                                    if let Some(name) = get_name_from_node(target) {
                                        println!("[+] Tainting variable: {} in {}", name, func_id);
                                        tainted_vars.insert((func_id.clone(), name));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    println!("[+] Found {} tainted variables", tainted_vars.len());

    // Second pass: find all sinks and check if arguments are tainted
    for (func_id, func_node) in &call_graph.functions {
        let file_path = func_id.split("::").next().unwrap_or("");
        
        // Fix: Create a default empty string that lives long enough
        let default_content = String::new();
        let content = call_graph.file_contents.get(file_path).unwrap_or(&default_content);
        
        let mut call_sites = Vec::new();
        find_call_sites(func_node, &mut call_sites);
        
        for call_node in call_sites {
            let callee_name = get_full_call_name(call_node);
            
            for sink in &ruleset.taint_sinks {
                if callee_name.contains(&sink.function_call) || sink.function_call.contains(&callee_name) {
                    println!("[+] Found potential sink: {} matches {}", callee_name, sink.function_call);
                    
                    if let Some(args) = call_node.children.get("args") {
                        if args.len() > sink.vulnerable_parameter_index {
                            let arg = &args[sink.vulnerable_parameter_index];
                            if let Some(arg_name) = get_name_from_node(arg) {
                                println!("[*] Checking if argument '{}' is tainted", arg_name);
                                
                                if tainted_vars.contains(&(func_id.clone(), arg_name.clone())) {
                                    println!("[!] VULNERABILITY FOUND! Tainted data flows to sink");
                                    report_issue(ruleset, &sink.vulnerability_id, file_path, call_node, content, &mut issues);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    issues
}

// Helper functions
fn find_assignments<'a>(node: &'a AstNode, assignments: &mut Vec<&'a AstNode>) {
    if node.node_type == "Assign" { 
        assignments.push(node); 
    }
    for child_list in node.children.values() { 
        for child in child_list { 
            find_assignments(child, assignments); 
        } 
    }
}

fn find_call_sites<'a>(node: &'a AstNode, sites: &mut Vec<&'a AstNode>) {
    if node.node_type == "Call" { 
        sites.push(node); 
    }
    for child_list in node.children.values() { 
        for child in child_list { 
            find_call_sites(child, sites); 
        } 
    }
}

fn get_name_from_node(node: &AstNode) -> Option<String> {
    // Handle both simple names (Name nodes) and more complex patterns
    match node.node_type.as_str() {
        "Name" => node.fields.get("id").and_then(|v| v.as_ref()).and_then(|v| v.as_str().map(String::from)),
        "Attribute" => {
            // For attribute access like obj.attr, just return the attribute name
            node.fields.get("attr").and_then(|v| v.as_ref()).and_then(|v| v.as_str().map(String::from))
        }
        _ => None
    }
}

fn get_full_call_name(call_node: &AstNode) -> String {
    if let Some(func) = call_node.children.get("func").and_then(|v| v.get(0)) {
        match func.node_type.as_str() {
            "Name" => return get_name_from_node(func).unwrap_or_default(),
            "Attribute" => {
                let mut parts = Vec::new();
                let mut current = func;
                
                while current.node_type == "Attribute" {
                    if let Some(attr) = current.fields.get("attr").and_then(|v| v.as_ref()).and_then(|v| v.as_str()) { 
                        parts.push(attr.to_string()); 
                    }
                    if let Some(next_node) = current.children.get("value").and_then(|v| v.get(0)) { 
                        current = next_node; 
                    } else { 
                        break; 
                    }
                }
                
                if let Some(base) = get_name_from_node(current) { 
                    parts.push(base); 
                }
                parts.reverse();
                return parts.join(".");
            }
            _ => {}
        }
    }
    String::new()
}

fn report_issue(ruleset: &RuleSet, vuln_id: &str, file_path: &str, stmt: &AstNode, content: &str, issues: &mut Vec<Issue>) {
    if let Some(vuln_rule) = ruleset.rules.iter().find(|r| r.id == vuln_id) {
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