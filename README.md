# 🛡️ solsec

```text
███████╗ ██████╗ ██╗      ███████╗███████╗ ██████╗ 
██╔════╝██╔═══██╗██║      ██╔════╝██╔════╝██╔════╝ 
███████╗██║   ██║██║      ███████╗█████╗  ██║      
╚════██║██║   ██║██║      ╚════██║██╔══╝  ██║      
███████║╚██████╔╝███████╗ ███████║███████╗╚██████╗ 
╚══════╝ ╚═════╝ ╚══════╝ ╚══════╝╚══════╝ ╚══════╝
```

**solsec** is a security-first Solidity static analysis tool designed for smart contract auditors and developers. It enhances the industry-standard [Slither](https://github.com/crytic/slither) engine with opinionated custom checks, a risk-scoring system, and beautiful, actionable reports.

---

## 🚀 Features

- **Hybrid Analysis**: Combines Slither's comprehensive detector suite with custom Go-based checks.
- **Custom Security Checks**: Specialized detectors for:
    - **Reentrancy**: State changes after external calls (even in patterns Slither might miss).
    - **Access Control**: Missing modifiers on sensitive functions (mint, burn, withdraw, etc.).
    - **Integer Safety**: Overflow risks in older Solidity versions and dangerous `unchecked` blocks in 0.8+.
- **Risk Scoring & Grading**: Automatically calculates a risk score (0-100) and assigns a letter grade (A-F) based on finding severity.
- **Rich Reporting**:
    - 📊 **HTML**: Beautiful standalone reports with remediation guidance.
    - 📄 **JSON**: Machine-readable output for integration.
    - 🤖 **SARIF**: Standard format for GitHub Code Scanning and IDE integrations.
- **CI/CD Ready**: Configurable exit codes based on severity (e.g., fail pipeline on "High" findings).

---

## 📦 Installation

### Prerequisites

1.  **Go**: 1.23+
2.  **Slither**: `pip3 install slither-analyzer`
3.  **Solc**: Ensure `solc` is in your PATH or manageable via `solc-select`.

### Build from Source

```bash
git clone https://github.com/Zubimendi/solsec.git
cd solsec
make build
# Binary will be in ./dist/solsec
```

### Install to $GOPATH

```bash
make install
```

---

## 🛠 Usage

### Basic Analysis

Run analysis on a single file or a directory of contracts:

```bash
solsec analyze ./contracts/Token.sol
```

### Advanced Options

```bash
# Export as JSON and fail on any "High" finding
solsec analyze ./contracts --format json --output report.json --fail-on high

# Run ONLY custom checks (skip Slither)
solsec analyze ./contracts --no-slither

# CI Mode (minimal output, meaningful exit codes)
solsec analyze ./contracts --ci
```

### Listing Custom Rules

View the built-in custom security checks:

```bash
solsec rules
```

---

## 📊 Scoring System

**solsec** uses a weighted scoring model to help you prioritize fixes:

| Grade | Score | Verdict |
| :--- | :--- | :--- |
| **A** | 0–9 | ✅ Low risk. Review findings. |
| **B** | 10–24 | ⚠️ Minor issues found. Address before mainnet. |
| **C** | 25–49 | 🟠 Moderate risk. Fix Medium+ findings. |
| **D** | 50–74 | 🔴 High risk. Do not deploy. |
| **F** | 75+ | 🚨 Critical risk. Security review required. |

---

## 🛠 Development

### Run Tests

```bash
make test
```

### Project Structure

- `cmd/`: CLI entry point and commands (Cobra).
- `internal/analyzer/`: Core analysis logic and custom Go checks.
- `internal/parser/`: Slither JSON parser and finding models.
- `internal/reporter/`: HTML, JSON, and SARIF report generators.
- `internal/scorer/`: Risk scoring and grading engine.

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
