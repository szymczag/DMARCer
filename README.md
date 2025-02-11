# DMARCer – Fast & Secure DMARC Analyzer in Rust 🚀

[![CI/CD](https://github.com/szymczag/dmarcer/actions/workflows/ci.yml/badge.svg)](https://github.com/szymczag/dmarcer/actions)

DMARCer is a high-performance, secure, and modular **DMARC report analyzer** written in Rust.  
It extracts, validates, and processes DMARC XML reports from ZIP archives with best security practices.

## 🚀 Features

- **Fast & Secure**: Leveraging Rust's performance and safety guarantees, DMARCer processes large DMARC reports quickly and reliably.
- **Robust ZIP & XML Processing**: The tool prevents common attacks including ZIP bombs, XML External Entity (XXE) attacks, and directory traversal exploits.
- **Clear, Actionable Output**: DMARCer presents detailed DMARC policy information and evaluation results for SPF and DKIM in table, -CSV-, or JSON format.
- **Configurable & Extensible**: Easily adjust security parameters (e.g., file size limits, decompression limits) via environment variables. Future enhancements may include integration with IMAP, webhooks, and ELK for centralized logging and monitoring.
- **Comprehensive Testing**: Includes a suite of automated tests covering security, configuration, and functionality. Integrated with GitHub Actions for continuous integration and delivery.

## 📦 Installation

Clone the repository and build in release mode:

```sh
git clone https://github.com/szymczag/dmarcer.git
cd dmarcer
cargo build --release
```

##⚙️ Usage
DMARCer is a command-line tool. The basic usage is as follows:
```sh
dmarcer <FILE> [OPTIONS]
```

### Options
- `--output <table|csv|json>`: Specifies the output format. The default is table.
- `--verbose`: Enables verbose logging for debugging purposes.

### Example Commands
- Display output in table format (default):
```sh
./target/release/dmarcer path/to/report.zip
```
- Display output in JSON format:
```sh
./target/release/dmarcer path/to/report.zip --output json
```
Enable verbose logging:
```sh
./target/release/dmarcer path/to/report.zip --verbose
```

## 🧪 Running Tests
To run the complete test suite locally, execute:
```sh
cargo test --release
```

## 🔗 Continuous Integration
DMARCer uses GitHub Actions for continuous integration. Every push and pull request triggers a CI pipeline that builds the project and runs the test suite automatically.

## 📜 License
DMARCer is licensed under the MIT License. See the LICENSE file for details.

## 👨 Contributing
Contributions are welcome! Please follow these steps to contribute:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes with clear, descriptive commit messages.
4. Push your changes to your fork.
5. Open a pull request detailing your changes.

For any questions or suggestions, please open an issue or contact the maintainer.

**Enjoy DMARCer and happy analyzing!**
