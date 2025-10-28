# 🧠 AstraPE: Reverse Engineering Assistant

AstraPE is a Python-based reverse engineering assistant designed to analyze and visualize Windows PE files (executables and DLLs).  
It’s inspired by CFF Explorer, IDA Pro, and PEStudio — built for learners, researchers, and malware analysts.

---

## ⚙️ Features (Week 1)
✅ Parse PE headers, sections, imports, and exports  
✅ Compute file hashes (MD5, SHA1, SHA256)  
✅ Display entropy per section  
✅ Simple colored console output  

---

## 🧰 Tech Stack
- **Language:** Python 3.11+
- **Libraries:** LIEF, Colorama
- **Platform:** Windows (PE focus)

---

## 🚀 Usage
```bash
python tests/sample_pe_analysis.py
