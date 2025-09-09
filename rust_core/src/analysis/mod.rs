use crate::issues::Issue;
use crate::rules::RuleSet;
use crate::ast_parser::{PythonFile, AstNode};
use crate::graph::cfg_builder;
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

mod config_analysis;
mod ast_analysis;
mod taint_analysis;

pub struct AnalysisContext {
    pub root_path: String,
    pub exclusions: Vec<String>,
    pub ruleset: RuleSet,
    pub py_files: Vec<PythonFile>,
}

fn is_excluded(path: &Path, exclusions: &[String]) -> bool {
    let path_str = path.to_str().unwrap_or_default();
    let path_filename = path.file_name().and_then(|s| s.to_str()).unwrap_or_default();
    exclusions.iter().any(|ex| path_str.contains(ex) || wildmatch::WildMatch::new(ex).matches(path_filename))
}

fn find_functions<'a>(node: &'a AstNode, functions: &mut Vec<&'a AstNode>) {
    if node.node_type == "FunctionDef" || node.node_type == "AsyncFunctionDef" {
        functions.push(node);
    }
    for child_list in node.children.values() {
        for child in child_list {
            find_functions(child, functions);
        }
    }
}

pub fn run_analysis(context: AnalysisContext) -> Vec<Issue> {
    let root_path = Path::new(&context.root_path);
    let mut files_to_scan: Vec<String> = Vec::new();
    for entry in WalkDir::new(root_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() && !path.extension().map_or(false, |ext| ext == "py") && !is_excluded(path, &context.exclusions) {
            files_to_scan.push(path.to_str().unwrap().to_string());
        }
    }
    
    let mut issues: Vec<Issue> = files_to_scan
        .par_iter()
        .flat_map(|file_path| {
            if let Ok(content) = fs::read_to_string(file_path) {
                config_analysis::scan_file(file_path, &content, &context.ruleset)
            } else { Vec::new() }
        })
        .collect();

    let python_issues: Vec<Issue> = context.py_files
        .par_iter()
        .flat_map(|py_file| {
            let mut findings = Vec::new();
            if is_excluded(Path::new(&py_file.file_path), &context.exclusions) { return findings; }
            
            findings.extend(config_analysis::scan_file(&py_file.file_path, &py_file.content, &context.ruleset));
            
            if let Some(ast) = &py_file.ast {
                findings.extend(ast_analysis::scan_ast(ast, &py_file.file_path, &py_file.content, &context.ruleset));

                let mut functions = Vec::new();
                find_functions(ast, &mut functions);
                for func_node in functions {
                    let cfg = cfg_builder::build_cfg(func_node);
                    findings.extend(taint_analysis::analyze_function(&cfg, &context.ruleset, &py_file.file_path, &py_file.content));
                }
            }
            findings
        })
        .collect();
        
    issues.extend(python_issues);

    // --- FINAL DEDUPLICATION STEP ---
    let mut seen = HashSet::new();
    issues.retain(|issue| {
        let fingerprint = issue.get_fingerprint();
        seen.insert(fingerprint)
    });

    issues
}