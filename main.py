import sys
from pathlib import Path
from core.pe_parser import PEParser
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}
    ╔══════════════════════════════════════╗
    ║        AstraPE - Reverse Assistant   ║
    ╚══════════════════════════════════════╝
{Style.RESET_ALL}
"""

def main():
    print(BANNER)
    print(Fore.YELLOW + "A Python-based Reverse Engineering Toolkit (Week 1: PE Parser)\n")

    # Accept file path from CLI args or prompt
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = input("Enter path to a PE file (.exe or .dll): ").strip('"')

    if not Path(file_path).exists():
        print(Fore.RED + f"[!] File not found: {file_path}")
        sys.exit(1)

    try:
        parser = PEParser(file_path)
        parser.summary()
    except Exception as e:
        print(Fore.RED + f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
