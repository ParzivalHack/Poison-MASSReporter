use crate::ast_parser::PythonFile;
use crate::graph::call_graph_builder;
use crate::issues::Issue;
use crate::rules::RuleSet;
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

mod ast_analysis;
mod config_analysis;
mod taint_analysis;

pub struct AnalysisContext<'a> {
    pub root_path: String,
    pub exclusions: Vec<String>,
    pub ruleset: RuleSet,
    pub py_files: &'a [PythonFile],
}

pub fn run_analysis(context: AnalysisContext) -> Vec<Issue> {
    println!("[*] Starting analysis with {} rules", context.ruleset.rules.len());
    
    let root_path = Path::new(&context.root_path);
    let mut files_to_scan: Vec<String> = Vec::new();
    
    for entry in WalkDir::new(root_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        // FIXED: Changed logic to include .py files, not exclude them
        if path.is_file() && path.extension().map_or(false, |ext| ext == "py") && !is_excluded(path, &context.exclusions) {
            files_to_scan.push(path.to_str().unwrap().to_string());
        }
    }
    
    println!("[+] Found {} Python files to scan", files_to_scan.len());
    
    let mut issues: Vec<Issue> = files_to_scan
        .par_iter()
        .flat_map(|file_path| {
            println!("[*] Scanning file: {}", file_path);
            if let Ok(content) = fs::read_to_string(file_path) {
                config_analysis::scan_file(file_path, &content, &context.ruleset)
            } else { 
                println!("[!] Failed to read file: {}", file_path);
                Vec::new() 
            }
        })
        .collect();

    println!("[+] Found {} issues from config analysis", issues.len());

    let python_issues: Vec<Issue> = context.py_files
        .par_iter()
        .flat_map(|py_file| {
            println!("[*] Processing Python file: {}", py_file.file_path);
            let mut findings = Vec::new();
            if is_excluded(Path::new(&py_file.file_path), &context.exclusions) { 
                println!("[!] File excluded: {}", py_file.file_path);
                return findings; 
            }
            
            findings.extend(config_analysis::scan_file(&py_file.file_path, &py_file.content, &context.ruleset));
            println!("[+] Config analysis found {} issues in {}", findings.len(), py_file.file_path);
            
            if let Some(ast) = &py_file.ast {
                let ast_findings = ast_analysis::scan_ast(ast, &py_file.file_path, &py_file.content, &context.ruleset);
                println!("[+] AST analysis found {} issues in {}", ast_findings.len(), py_file.file_path);
                findings.extend(ast_findings);
            } else {
                println!("[!] No AST available for {}", py_file.file_path);
            }
            findings
        })
        .collect();
        
    println!("[+] {} issues from Python AST analysis", python_issues.len());
    issues.extend(python_issues);

    // Build the call graph and run taint analysis
    let call_graph = call_graph_builder::build_call_graph(context.py_files);
    let taint_issues = taint_analysis::analyze_program_for_taint(&call_graph, &context.ruleset);
    println!("[+] Found {} issues from taint analysis", taint_issues.len());
    issues.extend(taint_issues);
    
    // Remove duplicates
    let mut seen = HashSet::new();
    issues.retain(|issue| seen.insert(issue.get_fingerprint()));

    println!("[*] Total issues after deduplication: {}", issues.len());
    issues
}

fn is_excluded(path: &Path, exclusions: &[String]) -> bool {
    let path_str = path.to_str().unwrap_or_default();
    let path_filename = path.file_name().and_then(|s| s.to_str()).unwrap_or_default();
    exclusions.iter().any(|ex| path_str.contains(ex) || wildmatch::WildMatch::new(ex).matches(path_filename))
}