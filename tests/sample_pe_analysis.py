from core.pe_parser import PEParser
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if __name__ == "__main__":
    path = r"C:\Windows\System32\notepad.exe"  # sample path
    parser = PEParser(path)
    parser.summary()
