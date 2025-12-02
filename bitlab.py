import socket

class BitcoinPeer:
    def __init__(self):
        self.sock = None
        self.ip = None
        self.port = None

    def connect(self, ip: str, port: int = 8333):
        # na razie tylko log
        print(f"[+] Połączę się z {ip}:{port}")

HELP_TEXT = """
Dostępne komendy:

  help
  connect <ip> [port]
  quit / exit
"""

def main():
    peer = BitcoinPeer()
    print("=== BitLab – start ===")
    print("Wpisz 'help', żeby zobaczyć komendy.")
    while True:
        cmdline = input("\nbitlab> ").strip()
        if not cmdline:
            continue
        parts = cmdline.split()
        cmd = parts[0].lower()

        if cmd in ("quit", "exit"):
            break
        elif cmd == "help":
            print(HELP_TEXT)
        elif cmd == "connect":
            if len(parts) < 2:
                print("Użycie: connect <ip> [port]")
                continue
            ip = parts[1]
            port = int(parts[2]) if len(parts) > 2 else 8333
            peer.connect(ip, port)
        else:
            print("[-] Nieznana komenda.")

if __name__ == "__main__":
    main()