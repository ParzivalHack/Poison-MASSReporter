<img width="893" height="230" alt="image" src="https://github.com/user-attachments/assets/761a74bc-4d11-44b2-aa5c-64c4e999fcfa" />

# An High-Performance Python and Rust SAST Framework

[![latest release](https://img.shields.io/badge/latest%20release-v0.1.1--beta-blue)](https://github.com/ParzivalHack/PySpector/releases/tag/v0.1.1-beta)

PySpector is a static analysis security testing (SAST) Framework engineered for modern Python development workflows. It leverages a powerful Rust core to deliver high-speed, accurate vulnerability scanning, wrapped in a developer-friendly Python CLI. By compiling the analysis engine to a native binary, PySpector avoids the performance overhead of traditional Python-based tools, making it an ideal choice for integration into CI/CD pipelines and local development environments where speed is critical.

The tool is designed to be both comprehensive and intuitive, offering a multi-layered analysis approach that goes beyond simple pattern matching to understand the structure and data flow of your application.



## Getting Started

### Prerequisites

-   **Python**: Version 3.12 or lower (>3.9+).
-   **Rust**: The Rust compiler (`rustc`) and Cargo package manager are required. You can verify your installation by running `cargo --version`.

### Installation

1.  **Create a Virtual Environment**: It is highly recommended to install PySpector in a dedicated virtual environment.
    ```bash
    python3.12 -m venv venv
    source venv/bin/activate
    ```
In Windows, just download Python 3.12 (suggested) from the Microsoft Store and run:
```powershell
    python3.12 -m venv venv
    .\venv\Scripts\Activate.ps1
```

2.  **Install Build Dependencies**: PySpector uses `maturin` to build its Rust core.
    ```bash
    pip install maturin setuptools-rust
    ```
3.  **Install PySpector**: From the root of the project repository, install the package. This will compile the Rust core and install the Python wrapper.
    ```bash
    pip install .
    ```

## Key Features

* **Multi-Layered Analysis Engine:** PySpector employs a sophisticated, multi-layered approach to detect a broad spectrum of vulnerabilities:

* * **Regex-Based Pattern Matching:** Scans all files for specific patterns, ideal for identifying hardcoded secrets, insecure configurations in Dockerfiles, and weak settings in framework files.

* * **Abstract Syntax Tree (AST) Analysis:** For Python files, the tool parses the code into an AST to analyze its structure. This enables precise detection of vulnerabilities tied to code constructs, such as the use of eval(), insecure deserialization with pickle, or weak hashing algorithms.

* * **Inter-procedural Taint Analysis:** The engine builds a comprehensive call graph of the entire application to perform taint analysis. It tracks the flow of data from input sources (like web requests) to dangerous sinks (like command execution functions), allowing it to identify complex injection vulnerabilities with high accuracy.

* **Comprehensive and Customizable Ruleset:** PySpector comes with 238 built-in rules that cover common vulnerabilities, including those from the OWASP Top 10. The rules are defined in a simple TOML format, making them easy to understand and extend.

* **Versatile Reporting:** Generates clear and actionable reports in multiple formats, including a developer-friendly console output, JSON, HTML, and SARIF for seamless integration with other security tools and platforms.

* **Efficient Baselining:** The interactive triage mode simplifies the process of establishing a security baseline, allowing teams to focus on new and relevant findings in each scan.

## How It Works

PySpector's hybrid architecture is key to its performance and effectiveness.

* **Python CLI Orchestration:** The process begins with the Python-based CLI. It handles command-line arguments, loads the configuration and rules, and prepares the target files for analysis. For each Python file, it uses the native ast module to generate an Abstract Syntax Tree, which is then serialized to JSON.

* **Invocation of the Rust Core:** The serialized ASTs, along with the ruleset and configuration, are passed to the compiled Rust core. The handoff from Python to Rust is managed by the pyo3 library.

* **Parallel Analysis in Rust:** The Rust engine takes over and performs the heavy lifting. It leverages the rayon crate to execute file scans and analysis in parallel, maximizing the use of available CPU cores. It builds a complete call graph of the application to understand inter-file function calls, which is essential for the taint analysis module.

* **Results and Reporting:** Once the analysis is complete, the Rust core returns a structured list of findings to the Python CLI. The Python wrapper then handles the final steps of filtering the results based on the severity threshold and the baseline file, and generating the report in the user-specified format.

This architecture combines the best of both worlds: a flexible, user-friendly interface in Python and a high-performance, memory-safe analysis engine in Rust :)

## Usage

PySpector is operated through a straightforward command-line interface.

### Running a Scan

The primary command is `scan`, which can target a local file, a directory, or even a remote Git repository.

```bash
pyspector scan [PATH or --url REPO_URL] [OPTIONS]
```

### Examples:

* **Scan a single file**
```bash
pyspector scan project/main.py
```

* **Scan a local directory and save the report as HTML:**
```bash
pyspector scan /path/to/your/project -o report.html -f html
```

* **Scan a public GitHub repository:**
```bash
pyspector scan --url https://github.com/username/repo.git
```

### Scan for AI and LLM Vulnerabilities (NEW FEATURE🚀)

Use the `--ai` flag to enable a specialized ruleset for projects using Large Language Models.

```bash
pyspector scan /path/to/your/project --ai
```

## Triaging and Baselining Findings
<img width="871" height="950" alt="image" src="https://github.com/user-attachments/assets/5f31c2fc-9216-408e-975f-a1652c6bbdc7" />

PySpector includes an interactive triage mode to help manage and baseline findings. This allows you to review issues and mark them as "ignored" so they don't appear in future scans.

* **Generate a JSON report:**
```bash
pyspector scan /path/to/your/project -o report.json -f json
```

* **Start the triage TUI:**
```bash
pyspector triage report.json
```

Inside the TUI, you can navigate with the arrow keys, press i to toggle the "ignored" status of an issue, and s to save your changes to a .pyspector_baseline.json file. This baseline file will be automatically loaded on subsequent scans.

## Automation and Integration

PySpector includes Shell helper scripts to integrate security scanning directly into your development and operational workflows.

### Git Pre-Commit Hook

To ensure that no new high-severity issues are introduced into the codebase, you can set up a Git pre-commit hook. This hook will automatically scan staged Python files before each commit and block the commit if any HIGH or CRITICAL issues are found.

**To set up the hook, run the following script from the root of your Git repository:**
```bash
./scripts/setup_hooks.sh
```
This script creates an executable .git/hooks/pre-commit file that performs the check. You can bypass the hook for a specific commit by using the --no-verify flag with your git commit command.

## Scheduled Scans with Cron

For continuous monitoring, you can schedule regular scans of your projects using a cron job. PySpector provides an interactive script to help you generate the correct crontab entry.

**To generate your cron job command, run:**
```bash
./scripts/setup_cron.sh
```
The script will prompt you for the project path, desired scan frequency (daily, weekly, monthly), and a location to store the JSON reports. It will then output the command to add to your crontab, automating your security scanning and reporting process.

