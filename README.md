# NPM Supply Chain September 2025 Incident Scanner Tool

A Rust-based tool for scanning npm projects and detecting potentially malicious packages in your dependency tree.

## Background

This tool was created in response to the major npm supply chain attack that occurred on September 8, 2025, which compromised 18+ popular packages with over 2.6 billion weekly downloads including `chalk`, `debug`, and `ansi-styles`.

The attack injected cryptocurrency wallet-stealing malware that would swap wallet addresses during transactions. While detected and resolved within 2.5 hours, it highlighted the critical need for automated supply chain security scanning tools.

**Key References:**
- [Sonatype Security Report](https://www.sonatype.com/blog/npm-chalk-and-debug-packages-hit-in-software-supply-chain-attack) - Detailed analysis of the supply chain attack
- [Wiz Security Analysis](https://www.wiz.io/blog/widespread-npm-supply-chain-attack-breaking-down-impact-scope-across-debug-chalk) - Technical breakdown with IOCs and detection methods
- [Chalk Issue #656](https://github.com/chalk/chalk/issues/656) - Official incident report from chalk maintainers
- [Debug Issue #1005](https://github.com/debug-js/debug/issues/1005) - Official incident report from debug maintainers

## Getting Started

### Prerequisites

- [Rust](https://rustup.rs/) (latest stable version)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/ivnnv/npm-sept-2025-incident-scan.git
cd npm-sept-2025-incident-scan

# Build the scanner
cargo build --release
```

### Usage

```bash
# Scan a project directory
./target/release/npm-sept-2025-incident-scan /path/to/your/project

# Scan with project name filter
./target/release/npm-sept-2025-incident-scan --project your-project-name /path/to/scan

# Clean mode - recursively removes all node_modules folders before scanning
./target/release/npm-sept-2025-incident-scan --clean /path/to/scan
```

## Example Output

```
🔍 NPM Malware Scanner - Rust Edition
📦 Scanning for 27 compromised packages
🔍 Scanning for 30 malware indicators
📁 Scanning: "/path/to/projects"
============================================================
🏢 Found 2 companies with 15 total projects

📋 Structure found:
  🏢 company-a (8 projects)
  🏢 company-b (7 projects)

🚀 Starting parallel scan...

📊 company-a           | frontend-app               | ✅ clean
📊 company-a           | backend-api                | ✅ clean
📊 company-b           | mobile-app                 | ✅ clean
📊 company-b           | web-dashboard              | ✅ clean
📊 company-a           | admin-panel                | ✅ clean
📊 company-b           | analytics-service          | ✅ clean

============================================================
📊 FINAL SUMMARY
============================================================
🗂️  Total projects scanned: 15
⚠️  Projects with issues: 0
🔍 Total compromises found: 0

✅ EXCELLENT! No compromised packages found

⏰ Scan completed: 2025-09-14 13:18:44
```

## Features

- Scans npm project dependencies for known malicious packages
- Fast Rust-based implementation with parallel processing
- Project-specific filtering capabilities
- Clean mode to remove node_modules before scanning
- Detailed reporting of potential security issues
- Multi-company project organization detection

## License

MIT
