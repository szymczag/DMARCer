# DMARCer – Fast & Secure DMARC Analyzer in Rust 🚀

[![CI/CD](https://github.com/szymczag/dmarcer/actions/workflows/ci.yml/badge.svg)](https://github.com/szymczag/dmarcer/actions)

DMARCer is a high-performance, secure, and modular **DMARC report analyzer** written in Rust.  
It extracts, validates, and processes DMARC XML reports from ZIP archives with best security practices.

## 🚀 Features
✅ **Fast & Secure** – Written in Rust for high performance and safety  
✅ **ZIP & XML Processing** – Avoids ZIP bombs & XML parser exploits  
✅ **Configurable & Extensible** – Future support for IMAP, Webhooks, ELK  

## 📦 Installation
```sh
git clone https://github.com/szymczag/dmarcer.git
cd dmarcer
cargo build --release
