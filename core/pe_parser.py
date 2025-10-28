import lief
import hashlib
from colorama import Fore, Style
from pathlib import Path


class PEParser:
    def __init__(self, file_path: str):
        self.path = Path(file_path)
        if not self.path.exists():
            raise FileNotFoundError(f"{file_path} does not exist.")
        self.binary = lief.parse(file_path)
        if not self.binary:
            raise ValueError("Failed to parse PE file.")
    
    def file_hashes(self):
        """Return file hashes for integrity or malware triage."""
        data = self.path.read_bytes()
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def headers_info(self):
        hdr = self.binary.header
        return {
            "Machine": hdr.machine.name,
            "Sections": hdr.numberof_sections,
            "Timestamp": hdr.time_date_stamps,
            "Characteristics": [str(f) for f in hdr.characteristics_list],
        }

    def list_sections(self):
        return [{
            "Name": s.name,
            "Virtual Address": hex(s.virtual_address),
            "Virtual Size": s.virtual_size,
            "Raw Size": s.size,
            "Entropy": round(s.entropy, 2)
        } for s in self.binary.sections]

    def list_imports(self):
        imports = []
        for lib in self.binary.imports:
            functions = [f.name for f in lib.entries if f.name]
            imports.append({"Library": lib.name, "Functions": functions})
        return imports

    def list_exports(self):
        exports = self.binary.get_export()
        if not exports:
            return []
        return [f.name for f in exports.entries if f.name]

    def summary(self):
        print(Fore.CYAN + "\n=== FILE DETAILS ===" + Style.RESET_ALL)
        print(f"Path: {self.path}")
        for k, v in self.file_hashes().items():
            print(f"{k.upper()}: {v}")

        print(Fore.CYAN + "\n=== HEADERS ===" + Style.RESET_ALL)
        for k, v in self.headers_info().items():
            print(f"{k}: {v}")

        print(Fore.CYAN + "\n=== SECTIONS ===" + Style.RESET_ALL)
        for s in self.list_sections():
            print(f"{s['Name']:10} | RVA: {s['Virtual Address']} | Size: {s['Raw Size']} | Entropy: {s['Entropy']}")

        print(Fore.CYAN + "\n=== IMPORTS ===" + Style.RESET_ALL)
        for lib in self.list_imports():
            print(f"{lib['Library']}: {', '.join(lib['Functions'][:5])} ...")

        print(Fore.CYAN + "\n=== EXPORTS ===" + Style.RESET_ALL)
        exports = self.list_exports()
        print(", ".join(exports) if exports else "No exports found.")
