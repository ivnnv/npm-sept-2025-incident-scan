use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use serde_json::Value;
use regex::Regex;
use rayon::prelude::*;
use colored::*;

// Compromised packages list (Sonatype 2025-003716/003727)
static COMPROMISED_PACKAGES: &[(&str, &str)] = &[
    // Main attack - Sonatype incident
    ("chalk", "5.6.1"),
    ("debug", "4.4.2"),
    ("duckdb", "1.3.3"),
    ("ansi-regex", "6.2.1"),
    ("ansi-styles", "6.2.2"),
    ("color", "5.0.1"),
    ("prebid", "10.9.2"),
    ("prebid.js", "10.9.2"),
    ("proto-tinker-wc", "0.1.87"),
    // Related reported packages
    ("backslash", "0.2.1"),
    ("chalk-template", "1.1.1"),
    ("color-convert", "3.1.1"),
    ("color-name", "2.0.1"),
    ("color-string", "2.1.1"),
    ("error-ex", "1.3.3"),
    ("has-ansi", "6.0.1"),
    ("is-arrayish", "0.3.3"),
    ("simple-swizzle", "0.2.3"),
    ("slice-ansi", "7.1.1"),
    ("strip-ansi", "7.1.1"),
    ("supports-color", "10.2.1"),
    ("supports-hyperlinks", "4.1.1"),
    ("wrap-ansi", "9.0.1"),
    ("@duckdb/node-api", "1.3.3"),
    ("@duckdb/duckdb-wasm", "1.29.2"),
    ("@duckdb/node-bindings", "1.3.3"),
    ("@coveops/abi", "2.0.1"),
];

// Expanded malware indicators
static MALWARE_INDICATORS: &[&str] = &[
    // Known malicious domains
    "checkethereumw",
    "websocket-api2.publicvm.com",
    "npmjs.help",
    "static-mw-host.b-cdn.net",
    "img-data-backup.b-cdn.net",
    // New 2024-2025 indicators
    "discord.com/api/webhooks",
    "api.telegram.org/bot",
    "wallet.dat",
    "seed.txt",
    "private.key",
    "mnemonic",
    "keystore",
    "metamask",
    "electrum",
    "exodus",
    // Malicious code patterns
    "fs.readFileSync.*wallet",
    "child_process.exec.*curl",
    "eval\\(atob\\(",
    "Buffer.from.*base64.*eval",
    "require\\('crypto'\\).*randomBytes",
    // Mining patterns
    "monero",
    "bitcoin",
    "stratum",
    "pool.minergate.com",
    "coinhive",
    // Data theft patterns
    "\\.ssh/id_rsa",
    "\\.aws/credentials",
    "cookies.sqlite",
    "Login Data",
    "browser.*password",
];

// Patterns to exclude from phantom wallet detection (PhantomJS is legitimate)
static PHANTOM_EXCLUSIONS: &[&str] = &[
    "phantomjs",
    "karma-phantomjs",
    "phantom-js",
    "phantomjs-launcher",
    "phantomjs-polyfill",
    "phantomjs-prebuilt",
];

#[derive(Debug, Clone)]
struct Project {
    name: String,
    path: PathBuf,
    company: String,
}

#[derive(Debug, Default)]
struct ScanResult {
    compromised_packages: Vec<String>,
    malware_indicators: Vec<MalwareIndicator>,
    files_with_issues: Vec<String>,
}

#[derive(Debug, Clone)]
struct MalwareIndicator {
    pattern: String,
    file: String,
    context: String, // Line or section where it was found
}

impl ScanResult {
    fn has_issues(&self) -> bool {
        !self.compromised_packages.is_empty() || !self.malware_indicators.is_empty()
    }

    fn total_issues(&self) -> usize {
        self.compromised_packages.len() + self.malware_indicators.len()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut clean_mode = false;
    let mut scan_dir = std::env::current_dir()?;
    let mut single_project: Option<PathBuf> = None;

    // Parse arguments
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--clean" | "-c" => clean_mode = true,
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--project" | "-p" => {
                if i + 1 < args.len() {
                    single_project = Some(PathBuf::from(&args[i + 1]));
                    i += 1; // Skip next arg since we consumed it
                } else {
                    eprintln!("{} --project requires a path", "❌".red());
                    std::process::exit(1);
                }
            }
            _ if !args[i].starts_with('-') => {
                scan_dir = PathBuf::from(&args[i]);
            }
            _ => {}
        }
        i += 1;
    }

    if !scan_dir.exists() {
        eprintln!("{} Directory {:?} does not exist", "❌".red(), scan_dir);
        std::process::exit(1);
    }

    println!("{}", "🔍 NPM Malware Scanner - Rust Edition".bold().blue());
    if clean_mode {
        println!("{}", "🧹 CLEANUP MODE ACTIVATED".bold().red());
    }
    println!("📦 Scanning for {} compromised packages", COMPROMISED_PACKAGES.len());
    println!("🔍 Scanning for {} malware indicators", MALWARE_INDICATORS.len());
    println!("📁 Scanning: {:?}", scan_dir);
    println!("{}", "=".repeat(60).bright_black());

    // Find projects or scan a specific one
    let projects = if let Some(single_path) = single_project {
        let full_path = if single_path.is_absolute() {
            single_path
        } else {
            scan_dir.join(&single_path)
        };

        if !full_path.exists() {
            eprintln!("{} Project {:?} does not exist", "❌".red(), full_path);
            std::process::exit(1);
        }

        if !full_path.join("package.json").exists() {
            eprintln!("{} Directory {:?} does not have package.json", "❌".red(), full_path);
            std::process::exit(1);
        }

        let project_name = full_path.file_name().unwrap().to_str().unwrap().to_string();
        let parent_name = full_path.parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        vec![Project {
            name: project_name,
            path: full_path,
            company: parent_name,
        }]
    } else {
        find_projects(&scan_dir)?
    };

    if projects.is_empty() {
        println!("{} No NPM projects found", "⚠️".yellow());
        return Ok(());
    }

    println!("🏢 Found {} companies with {} total projects",
             get_unique_companies(&projects).len(), projects.len());

    // Show structure
    show_project_structure(&projects);

    // Clean node_modules if activated
    if clean_mode {
        println!("\n{} Removing all node_modules...", "🧹".red());
        clean_node_modules(&projects);
        println!("{} Cleanup completed", "✅".green());
    }

    println!("\n{} Starting parallel scan...\n", "🚀".green());

    // Scan projects in parallel
    let results: Vec<(Project, ScanResult)> = projects
        .par_iter()
        .map(|project| {
            let result = scan_project(project);
            print_progress(project, &result);
            (project.clone(), result)
        })
        .collect();

    // Show final summary
    show_final_summary(&results);

    Ok(())
}

fn find_projects(base_dir: &Path) -> Result<Vec<Project>, Box<dyn std::error::Error>> {
    let mut projects = Vec::new();

    // Look for company directories (level 1)
    for company_entry in fs::read_dir(base_dir)? {
        let company_entry = company_entry?;
        let company_path = company_entry.path();

        if !company_path.is_dir() || company_path.file_name().unwrap().to_str().unwrap().starts_with('.')
            || company_path.file_name().unwrap().to_str().unwrap() == "node_modules" {
            continue;
        }

        let company_name = company_path.file_name().unwrap().to_str().unwrap().to_string();

        // Look for repos within each company (level 2)
        for repo_entry in fs::read_dir(&company_path)? {
            let repo_entry = repo_entry?;
            let repo_path = repo_entry.path();

            if !repo_path.is_dir() || repo_path.file_name().unwrap().to_str().unwrap().starts_with('.')
                || repo_path.file_name().unwrap().to_str().unwrap() == "node_modules" {
                continue;
            }

            // Check if it has package.json
            if repo_path.join("package.json").exists() {
                let repo_name = repo_path.file_name().unwrap().to_str().unwrap().to_string();
                projects.push(Project {
                    name: repo_name,
                    path: repo_path,
                    company: company_name.clone(),
                });
            }
        }
    }

    projects.sort_by(|a, b| {
        a.company.cmp(&b.company).then_with(|| a.name.cmp(&b.name))
    });

    Ok(projects)
}

fn get_unique_companies(projects: &[Project]) -> Vec<String> {
    let mut companies: Vec<String> = projects.iter()
        .map(|p| p.company.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    companies.sort();
    companies
}

fn show_project_structure(projects: &[Project]) {
    let _current_company = String::new();
    let mut company_count = HashMap::new();

    // Contar proyectos por compañía
    for project in projects {
        *company_count.entry(project.company.clone()).or_insert(0) += 1;
    }

    println!("\n📋 Structure found:");
    for (company, count) in &company_count {
        println!("  🏢 {} ({} projects)", company.bright_cyan(), count);
    }
}

fn scan_project(project: &Project) -> ScanResult {
    let mut result = ScanResult::default();

    // Scan package.json
    if let Ok(content) = fs::read_to_string(project.path.join("package.json")) {
        if let Ok(json) = serde_json::from_str::<Value>(&content) {
            check_dependencies(&json, &mut result, "package.json");
        }
    }

    // Scan package-lock.json
    if let Ok(content) = fs::read_to_string(project.path.join("package-lock.json")) {
        check_lockfile(&content, &mut result, "package-lock.json");
    }

    // Scan yarn.lock
    if let Ok(content) = fs::read_to_string(project.path.join("yarn.lock")) {
        check_lockfile(&content, &mut result, "yarn.lock");
    }

    // Scan pnpm-lock.yaml
    if let Ok(content) = fs::read_to_string(project.path.join("pnpm-lock.yaml")) {
        check_lockfile(&content, &mut result, "pnpm-lock.yaml");
    }

    // Scan JS/TS files for malware (only in root directory, not node_modules)
    scan_project_source_files(&project.path, &mut result);

    result
}

fn check_dependencies(json: &Value, result: &mut ScanResult, filename: &str) {
    let sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];

    for section in &sections {
        if let Some(deps) = json.get(section).and_then(|v| v.as_object()) {
            for (package_name, version_value) in deps {
                if let Some(version_str) = version_value.as_str() {
                    for &(compromised_pkg, compromised_version) in COMPROMISED_PACKAGES {
                        if package_name == compromised_pkg {
                            let clean_version = version_str.trim_start_matches(&['~', '^']);
                            if clean_version == compromised_version {
                                result.compromised_packages.push(format!(
                                    "{}@{} en {}", package_name, compromised_version, filename
                                ));
                                result.files_with_issues.push(filename.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
}

fn check_lockfile(content: &str, result: &mut ScanResult, filename: &str) {
    for &(package_name, version) in COMPROMISED_PACKAGES {
        let patterns = [
            format!("\"{}\".*\"{}\"", package_name, version),
            format!("{}@{}", package_name, version),
            format!("{} {}", package_name, version),
        ];

        for pattern in &patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(content) {
                    result.compromised_packages.push(format!(
                        "{}@{} en {}", package_name, version, filename
                    ));
                    result.files_with_issues.push(filename.to_string());
                    break;
                }
            }
        }
    }
}

fn scan_project_source_files(project_path: &Path, result: &mut ScanResult) {
    // Only scan specific critical files in the root directory
    let critical_files = [
        "index.js", "index.ts", "main.js", "main.ts",
        "server.js", "server.ts", "app.js", "app.ts",
        "webpack.config.js", "vite.config.js", "rollup.config.js",
        "postinstall.js", "preinstall.js", "install.js"
    ];

    for filename in &critical_files {
        let file_path = project_path.join(filename);
        if file_path.exists() {
            if let Ok(content) = fs::read_to_string(&file_path) {
                for indicator in MALWARE_INDICATORS {
                    if content.contains(indicator) {
                        let context = find_context_line(&content, indicator);
                        result.malware_indicators.push(MalwareIndicator {
                            pattern: indicator.to_string(),
                            file: filename.to_string(),
                            context,
                        });
                        result.files_with_issues.push(filename.to_string());
                        break; // Only mark once per file
                    }
                }
            }
        }
    }

    // Also review package.json scripts with more detail
    scan_package_json(project_path, result);
}

fn scan_package_json(project_path: &Path, result: &mut ScanResult) {
    let package_path = project_path.join("package.json");
    if let Ok(content) = fs::read_to_string(&package_path) {
        // Parse JSON to get more specific information
        if let Ok(json) = serde_json::from_str::<Value>(&content) {
            // Review scripts
            if let Some(scripts) = json.get("scripts").and_then(|v| v.as_object()) {
                for (script_name, script_value) in scripts {
                    if let Some(script_content) = script_value.as_str() {
                        for indicator in MALWARE_INDICATORS {
                            if script_content.contains(indicator) {
                                result.malware_indicators.push(MalwareIndicator {
                                    pattern: indicator.to_string(),
                                    file: "package.json".to_string(),
                                    context: format!("scripts.{}: \"{}\"", script_name, script_content),
                                });
                                result.files_with_issues.push("package.json".to_string());
                            }
                        }
                    }
                }
            }

            // Also review dependencies and devDependencies for suspicious names
            let sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
            for section in &sections {
                if let Some(deps) = json.get(section).and_then(|v| v.as_object()) {
                    for (package_name, version_value) in deps {
                        for indicator in MALWARE_INDICATORS {
                            if package_name.contains(indicator) {
                                // Special handling for phantom - exclude legitimate PhantomJS packages
                                if *indicator == "phantom" && is_legitimate_phantomjs(package_name) {
                                    continue;
                                }

                                result.malware_indicators.push(MalwareIndicator {
                                    pattern: indicator.to_string(),
                                    file: "package.json".to_string(),
                                    context: format!("{}.{}: {}", section, package_name, version_value),
                                });
                                result.files_with_issues.push("package.json".to_string());
                            }
                        }
                    }
                }
            }
        } else {
            // If JSON cannot be parsed, do simple text search
            for indicator in MALWARE_INDICATORS {
                if content.contains(indicator) {
                    let context = find_context_line(&content, indicator);
                    result.malware_indicators.push(MalwareIndicator {
                        pattern: indicator.to_string(),
                        file: "package.json".to_string(),
                        context,
                    });
                    result.files_with_issues.push("package.json".to_string());
                }
            }
        }
    }
}

fn find_context_line(content: &str, pattern: &str) -> String {
    for line in content.lines() {
        if line.contains(pattern) {
            return line.trim().to_string();
        }
    }
    format!("Found: {}", pattern)
}

fn is_legitimate_phantomjs(package_name: &str) -> bool {
    let lowercase_name = package_name.to_lowercase();
    PHANTOM_EXCLUSIONS.iter().any(|exclusion| lowercase_name.contains(exclusion))
}

fn print_progress(project: &Project, result: &ScanResult) {
    let status = if result.has_issues() {
        format!("⚠️  {} issues", result.total_issues()).red()
    } else {
        "✅ clean".green()
    };

    println!("📊 {:<20} | {:<30} | {}",
             project.company.bright_cyan(),
             project.name.bright_white(),
             status);

    // Show problem details
    if result.has_issues() {
        for issue in &result.compromised_packages {
            println!("    🚨 PACKAGE: {}", issue.yellow());
        }
        for indicator in &result.malware_indicators {
            println!("    💀 MALWARE: {} en {}", indicator.pattern.red().bold(), indicator.file.cyan());
            println!("       📍 {}", indicator.context.bright_black());
        }
    }
}

fn show_final_summary(results: &[(Project, ScanResult)]) {
    println!("\n{}", "=".repeat(60).bright_black());
    println!("{}", "📊 FINAL SUMMARY".bold().blue());
    println!("{}", "=".repeat(60).bright_black());

    let total_projects = results.len();
    let projects_with_issues = results.iter().filter(|(_, r)| r.has_issues()).count();
    let total_issues: usize = results.iter().map(|(_, r)| r.total_issues()).sum();

    println!("🗂️  Total projects scanned: {}", total_projects.to_string().bold());
    println!("⚠️  Projects with issues: {}", projects_with_issues.to_string().red().bold());
    println!("🔍 Total compromises found: {}", total_issues.to_string().red().bold());

    if total_issues == 0 {
        println!("\n{} EXCELLENT! No compromised packages found", "✅".green());
    } else {
        println!("\n{} ATTENTION! Found {} compromises in {} projects",
                 "🚨".red(), total_issues, projects_with_issues);

        println!("\n🔧 URGENT ACTIONS REQUIRED:");
        println!("   1. Review each project marked with ⚠️");
        println!("   2. For each affected project:");
        println!("      cd company/affected_project");
        println!("      rm -rf node_modules package-lock.json");
        println!("      npm install");
        println!("   3. Verify web applications in production");
        println!("   4. If you have crypto wallets: rotate keys and review transactions");

        // Summary by company
        let mut company_issues: HashMap<String, usize> = HashMap::new();
        for (project, result) in results {
            if result.has_issues() {
                *company_issues.entry(project.company.clone()).or_insert(0) += result.total_issues();
            }
        }

        if !company_issues.is_empty() {
            println!("\n📈 Issues by company:");
            for (company, issues) in company_issues {
                println!("  🏢 {}: {} issues", company.bright_cyan(), issues.to_string().red());
            }
        }
    }

    println!("\n⏰ Scan completed: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
}

fn print_help() {
    println!("{}", "🔍 NPM Malware Scanner - Rust Edition".bold().blue());
    println!("\n{}", "USAGE:".bold());
    println!("  npm-sept-2025-incident-scan [OPTIONS] [DIRECTORY]");
    println!("\n{}", "OPTIONS:".bold());
    println!("  -c, --clean      🧹 Remove all node_modules before scanning");
    println!("  -p, --project    🎯 Scan only a specific project");
    println!("  -h, --help       📖 Show this help");
    println!("\n{}", "EXAMPLES:".bold());
    println!("  # Scan current directory");
    println!("  ./npm-sept-2025-incident-scan");
    println!("\n  # Scan specific directory");
    println!("  ./npm-sept-2025-incident-scan /Users/user/Sites");
    println!("\n  # Scan only a specific project");
    println!("  ./npm-sept-2025-incident-scan --project company/project-name");
    println!("  ./npm-sept-2025-incident-scan -p /full/path/to/project");
    println!("\n  # Clean node_modules then scan");
    println!("  ./npm-sept-2025-incident-scan --clean /Users/user/Sites");
    println!("\n{}", "⚠️  WARNING: --clean will remove ALL node_modules".red().bold());
    println!("{}", "   You will need to run npm/pnpm/yarn install afterwards".red());
}

fn clean_node_modules(projects: &[Project]) {
    projects.par_iter().for_each(|project| {
        let node_modules_path = project.path.join("node_modules");
        if node_modules_path.exists() {
            if let Err(e) = fs::remove_dir_all(&node_modules_path) {
                println!("⚠️  Error removing {:?}: {}", node_modules_path, e);
            } else {
                println!("🗑️  {} node_modules removed", project.name.bright_white());
            }
        }
    });
}

