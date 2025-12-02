import socket
import struct
import time
import random
import hashlib
import select

# Magic bytes sieci głównej Bitcoina – początek każdej wiadomości P2P
MAINNET_MAGIC = b"\xf9\xbe\xb4\xd9"

# Wersja protokołu P2P, której używa nasz klient
PROTOCOL_VERSION = 70015

# Lista publicznych "DNS seedów" – domen, z których można pobrać adresy peerów
DNS_SEEDS = [
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr.org",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.org",
]

class BitcoinPeer:
    """
    Prosta klasa reprezentująca połączenie z jednym peerem Bitcoina.
    Obecnie zawiera tylko informacje o gnieździe i adresie oraz metodę connect().
    """
    def __init__(self):
        self.sock = None
        self.ip = None
        self.port = None

    def connect(self, ip: str, port: int = 8333):
        """
        Na razie tylko wypisuje, że „połączy się” z danym adresem.
        Docelowo w tej metodzie:
          - stworzymy gniazdo TCP,
          - połączymy się z (ip, port),
          - ustawimy gniazdo jako nieblokujące,
          - rozpoczniemy handshake (version/verack).
        """
        print(f"[+] Połączę się z {ip}:{port}")

def sha256d(data: bytes) -> bytes:
    """
    Liczy tzw. double SHA-256:
      sha256d(x) = SHA256(SHA256(x))
    To właśnie taki podwójny hash jest używany w Bitcoinie do:
      - liczenia hashy bloków,
      - checksumów wiadomości P2P.
    """
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def checksum(payload: bytes) -> bytes:
    """
    Zwraca 4-bajtowy checksum dla danego payloadu.
    W nagłówku wiadomości P2P przechowywane są pierwsze 4 bajty z sha256d(payload).
    Wykorzystujemy to do wykrywania uszkodzonych wiadomości.
    """
    return sha256d(payload)[:4]

def compact_size_encode(n: int) -> bytes:
    """
    (DO ZAAIMPLEMENTOWANIA)
    Zakoduje liczbę n w formacie 'compactSize' (varint) używanym w protokole Bitcoina.
    Zasada:
      - jeśli n < 0xfd  ->  1 bajt
      - jeśli <= 0xffff -> 0xfd + 2 bajty
      - jeśli <= 0xffffffff -> 0xfe + 4 bajty
      - inaczej -> 0xff + 8 bajtów
    Używane m.in. w wiadomościach inv, addr, getheaders itp.
    """
    pass

def compact_size_decode(buf: bytes, offset: int = 0):
    """
    (DO ZAAIMPLEMENTOWANIA)
    Odczyta liczbę w formacie 'compactSize' z bufora zaczynając od 'offset'.
    Zwróci:
      (wartość_liczby, nowy_offset_po_odczycie)
    Używane przy parsowaniu wiadomości (np. liczba adresów w 'addr').
    """
    pass

def ipv6_from_ipv4(ipv4_str: str) -> bytes:
    """
    (DO ZAAIMPLEMENTOWANIA)
    Zamienia adres IPv4 (np. '1.2.3.4') na 16-bajtową formę IPv6 typu IPv4-mapped:
      ::ffff:1.2.3.4
    W protokole Bitcoin pola adresowe mają zawsze 16 bajtów (IPv6),
    więc IPv4 opakowujemy w taki sposób.
    """
    pass

def var_str(b: bytes) -> bytes:
    """
    Koduje 'zmienną długość stringa':
      var_str = compact_size_encode(len(b)) + b
    Używane np. do user-agenta, tekstów w alert/reject itp.
    """
    return compact_size_encode(len(b)) + b

def build_message(command: str, payload: bytes) -> bytes:
    """
    Buduje pełną wiadomość P2P Bitcoina:
      - magic      (4B)  -> MAINNET_MAGIC
      - command    (12B) -> nazwa komendy, np. 'version', 'ping', 'getaddr'
      - length     (4B)  -> długość payloadu (little-endian)
      - checksum   (4B)  -> pierwsze 4 bajty z sha256d(payload)
      - payload    (N B) -> właściwa zawartość wiadomości
    Funkcja zwraca gotowe bajty do wysłania przez socket.
    """
    cmd = command.encode("ascii")
    cmd_padded = cmd + b"\x00" * (12 - len(cmd))
    length = struct.pack("<I", len(payload))
    csum = checksum(payload)
    return MAINNET_MAGIC + cmd_padded + length + csum + payload

def build_ping_payload() -> bytes:
    """
    Buduje payload dla wiadomości 'ping':
      - 8-bajtowy losowy nonce (little-endian)
    Peer, który otrzyma 'ping', powinien odesłać 'pong' z tym samym nonce.
    Służy to do sprawdzania, czy połączenie nadal żyje.
    """
    nonce = random.getrandbits(64)
    return struct.pack("<Q", nonce)

def build_getaddr_payload() -> bytes:
    """
    Zwraca payload dla wiadomości 'getaddr'.
    Dla getaddr payload jest pusty – sama komenda sygnalizuje:
      „podaj mi listę znanych peerów (addr)”.
    """
    return b""


HELP_TEXT = """
Dostępne komendy:

  help
  connect <ip> [port]
  quit / exit
"""

def main():
    """
    Główna funkcja programu:
      - tworzy obiekt BitcoinPeer,
      - uruchamia prostą pętlę REPL (czyta komendy z klawiatury),
      - obsługuje podstawowe polecenia:
    """
     
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