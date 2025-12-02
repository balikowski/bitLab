import socket
import struct
import time
import random
import hashlib
import select

# Magic bytes sieci głównej Bitcoina (początek każdej wiadomości P2P)
MAINNET_MAGIC = b"\xf9\xbe\xb4\xd9"

# Wersja protokołu P2P używana przez klienta
PROTOCOL_VERSION = 70015

# Publiczne DNS seedy – do późniejszego bootstrapa peerów
DNS_SEEDS = [
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr.org",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.org",
]


def build_version_payload(peer_ip: str, peer_port: int) -> bytes:
    """Buduje payload wiadomości 'version' dla podanego IP i portu peera."""
    version = struct.pack("<i", PROTOCOL_VERSION)
    services = struct.pack("<Q", 0)
    timestamp = struct.pack("<q", int(time.time()))
    addr_recv_services = struct.pack("<Q", 0)
    addr_recv_ip = ipv6_from_ipv4(peer_ip)
    addr_recv_port = struct.pack(">H", peer_port)
    addr_trans_services = struct.pack("<Q", 0)
    addr_trans_ip = ipv6_from_ipv4("127.0.0.1")
    addr_trans_port = struct.pack(">H", peer_port)
    nonce = struct.pack("<Q", random.getrandbits(64))
    ua = "/BitLabPy-Lite:0.1/".encode("ascii")
    ua_len = compact_size_encode(len(ua))
    start_height = struct.pack("<i", 0)
    relay = b"\x00"
    return b"".join([
        version, services, timestamp,
        addr_recv_services, addr_recv_ip, addr_recv_port,
        addr_trans_services, addr_trans_ip, addr_trans_port,
        nonce, ua_len, ua, start_height, relay
    ])

def parse_addr_payload(payload: bytes):
    """
    Dekoduje payload wiadomości 'addr',
    wyciągając listę znanych peerów (IP, port, timestamp, services) przesłaną przez zdalny węzeł.
    """

    peers = []
    if not payload:
        print("[i] addr: pusty payload – peer nie podał adresów.")
        return peers

    count, offset = compact_size_decode(payload, 0)
    for _ in range(count):
        if offset + 30 > len(payload):
            break
        timestamp, services = struct.unpack("<IQ", payload[offset:offset+12])
        offset += 12
        ip_raw = payload[offset:offset+16]
        offset += 16
        port, = struct.unpack(">H", payload[offset:offset+2])
        offset += 2

        if ip_raw[:12] == b"\x00" * 10 + b"\xff\xff":
            ipv4_bytes = ip_raw[12:]
            ip_str = ".".join(str(b) for b in ipv4_bytes)
        else:
            ip_str = ":".join(f"{ip_raw[i:i+2].hex()}" for i in range(0, 16, 2))

        peers.append((ip_str, port, timestamp, services))
    return peers


class BitcoinPeer:
    """Reprezentuje połączenie z jednym peerem Bitcoina."""

    def __init__(self):
        self.sock = None              # gniazdo TCP do peera
        self.reader = None            # NonBlockingReader dla tego gniazda
        self.ip = None                # IP peera
        self.port = None              # port peera
        self.last_addr_peers = []     # rezerwka na listę peerów z 'addr'

    def _ensure_connected(self):
        """Sprawdza, czy istnieje aktywne połączenie z peerem."""
        if not self.sock:
            raise RuntimeError("Brak połączenia z peerem.")

    def _send_msg(self, command: str, payload: bytes):
        """Buduje i wysyła pojedynczą wiadomość P2P."""
        self._ensure_connected()
        msg = build_message(command, payload)
        self.sock.sendall(msg)
        print(f"[<] Wysłano '{command}' ({len(payload)} B).")

    def send_getaddr(self):
        """
        Wysyła do peera wiadomość 'getaddr',
        a następnie czeka na odpowiedź typu 'addr' i zapisuje z niej otrzymaną listę adresów sieci Bitcoin.
        """
        self._ensure_connected()
        self._send_msg("getaddr", build_getaddr_payload())
        print("[+] Czekam na 'addr'...")
        try:
            _, pl = self._poll_until({"addr"}, timeout=30.0)
        except TimeoutError as e:
            print(f"[-] Timeout: {e}")
            return
        self.last_addr_peers = parse_addr_payload(pl)
        for i, (ip, port, ts, services) in enumerate(self.last_addr_peers[:50], start=1):
            tstr = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))
            print(f"  {i:3d}. {ip}:{port} (czas: {tstr}, services: {services})")

    def list_last_addr_peers(self):
        """
        Wypisuje listę peerów odebranych wcześniej w wiadomości 'addr',
        jeśli taka została zapamiętana po wywołaniu getaddr.
        """
        if not self.last_addr_peers:
            print("[-] Brak zapisanych peerów – użyj getaddr.")
            return
        print(f"[+] Peery z ostatniego 'addr' ({len(self.last_addr_peers)}):")
        for i, (ip, port, ts, services) in enumerate(self.last_addr_peers, start=1):
            tstr = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))
            print(f"  {i:3d}. {ip}:{port}  (czas: {tstr}, services: {services})")

    def connect_via_seeds(self, timeout: float = 5.0):
        """
        Próbuje kolejno połączyć się z peerami uzyskanymi z publicznych DNS seedów Bitcoina,
        losując adresy i wykonując handshake po pomyślnym zestawieniu połączenia.
        """
        last_error = None
        for host in DNS_SEEDS:
            print(f"[+] Próba seeda: {host}")
            try:
                infos = socket.getaddrinfo(host, 8333, socket.AF_INET, socket.SOCK_STREAM)
            except socket.gaierror as e:
                print(f"    [!] DNS error: {e}")
                last_error = e
                continue
            random.shuffle(infos)
            for family, socktype, proto, canonname, sockaddr in infos:
                ip, port = sockaddr
                print(f"    [+] Próba połączenia z {ip}:{port} ...")
                s = socket.socket(family, socktype, proto)
                s.settimeout(timeout)
                try:
                    s.connect((ip, port))
                    s.setblocking(False)
                    print(f"    [✓] Udało się połączyć z {ip}:{port}")
                    self.sock = s
                    self.reader = NonBlockingReader(s)
                    self.ip = ip
                    self.port = port
                    self.handshake()
                    return
                except (socket.timeout, OSError) as e:
                    print(f"    [x] Błąd połączenia: {e}")
                    s.close()
                    last_error = e
        raise ConnectionError(f"Nie udało się połączyć z żadnym seedem: {last_error}")

    def send_ping(self):
        """
        Wysyła wiadomość 'ping' do peera wraz z losowym 8-bajtowym nonce i oczekuje na odpowiedź 'pong',
        aby sprawdzić aktywność i opóźnienie połączenia.
        """
        self._ensure_connected()
        self._send_msg("ping", build_ping_payload())
        print("[+] Czekam na 'pong'...")
        try:
            self._poll_until({"pong"}, timeout=30.0)
            print("[+] Otrzymano 'pong'.")
        except TimeoutError as e:
            print(f"[-] Timeout: {e}")

    def _poll_until(self, want_cmds, timeout: float):
        """
        Czeka na jedną z komend z want_cmds.
        Po drodze odpowiada na 'ping' wiadomością 'pong'.
        """
        end = time.time() + timeout
        while time.time() < end:
            msgs = self.reader.poll_messages(end - time.time())
            for cmd, pl in msgs:
                print(f"[>] Otrzymano: {cmd}")
                if cmd == "ping":
                    self._send_msg("pong", pl)
                elif cmd in want_cmds:
                    return cmd, pl
        raise TimeoutError(f"Nie otrzymano {want_cmds} w czasie {timeout}s")

    def close(self):
        """Zamyka gniazdo i czyści stan połączenia."""
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self.reader = None
        self.ip = None
        self.port = None

    def connect(self, ip: str, port: int = 8333, timeout: float = 10.0):
        """Łączy z podanym peerem i wykonuje handshake."""
        self.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.setblocking(False)
        self.sock = s
        self.reader = NonBlockingReader(s)
        self.ip = ip
        self.port = port
        print(f"[+] Połączono z {ip}:{port}")
        self.handshake()

    def handshake(self):
        """Wysyła 'version' i kończy handshake po 'version'/'verack' od peera."""
        self._ensure_connected()
        print("[+] Wysyłam 'version'...")
        self._send_msg("version", build_version_payload(self.ip, self.port))

        got_version = False
        got_verack = False
        end = time.time() + 20.0

        while time.time() < end and not (got_version and got_verack):
            msgs = self.reader.poll_messages(end - time.time())
            for cmd, pl in msgs:
                print(f"[>] Otrzymano: {cmd}")
                if cmd == "version":
                    got_version = True
                    self._send_msg("verack", b"")
                elif cmd == "verack":
                    got_verack = True
                elif cmd == "ping":
                    self._send_msg("pong", pl)

        if not (got_version and got_verack):
            raise TimeoutError("Handshake nie został zakończony.")
        print("[+] Handshake zakończony.")


class NonBlockingReader:
    """Buforuje dane z gniazda i wycina kompletne wiadomości P2P."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = bytearray()

    def poll_messages(self, timeout: float):
        """
        Czyta dane z gniazda (select + recv) i zwraca listę (command, payload)
        dla wszystkich kompletnych wiadomości w buforze.
        """
        msgs = []
        r, _, _ = select.select([self.sock], [], [], timeout)
        if self.sock in r:
            data = self.sock.recv(4096)
            if not data:
                raise ConnectionError("Połączenie zamknięte przez peer")
            self.buf.extend(data)

        while True:
            if len(self.buf) < 24:
                break
            magic, cmd_raw, length, csum = struct.unpack("<4s12sI4s", self.buf[:24])
            if magic != MAINNET_MAGIC:
                raise ValueError("Złe magic bytes")

            total_len = 24 + length
            if len(self.buf) < total_len:
                break

            payload = bytes(self.buf[24:total_len])
            del self.buf[:total_len]

            cmd = cmd_raw.rstrip(b"\x00").decode("ascii", errors="ignore")
            if checksum(payload) != csum:
                print(f"[!] Niepoprawny checksum dla {cmd}")

            msgs.append((cmd, payload))

        return msgs


def sha256d(data: bytes) -> bytes:
    """Double SHA-256: SHA256(SHA256(data))."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def checksum(payload: bytes) -> bytes:
    """4-bajtowy checksum: pierwsze 4 bajty z sha256d(payload)."""
    return sha256d(payload)[:4]


def compact_size_encode(n: int) -> bytes:
    """
    Koduje liczbę w formacie compactSize (varint) używanym w Bitcoinie.
    """
    if n < 0xfd:
        return struct.pack("<B", n)
    elif n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)


def compact_size_decode(buf: bytes, offset: int = 0):
    """
    Dekoduje compactSize z bufora, zwraca (wartość, nowy_offset).
    """
    if offset >= len(buf):
        raise IndexError("compact_size_decode: offset poza buforem")

    first = buf[offset]
    if first < 0xfd:
        return first, offset + 1
    elif first == 0xfd:
        if offset + 3 > len(buf):
            raise IndexError("compact_size_decode: za mało danych dla 0xfd")
        return struct.unpack("<H", buf[offset + 1:offset + 3])[0], offset + 3
    elif first == 0xfe:
        if offset + 5 > len(buf):
            raise IndexError("compact_size_decode: za mało danych dla 0xfe")
        return struct.unpack("<I", buf[offset + 1:offset + 5])[0], offset + 5
    else:
        if offset + 9 > len(buf):
            raise IndexError("compact_size_decode: za mało danych dla 0xff")
        return struct.unpack("<Q", buf[offset + 1:offset + 9])[0], offset + 9


def ipv6_from_ipv4(ipv4_str: str) -> bytes:
    """Zamienia IPv4 (np. '1.2.3.4') na 16-bajtową formę IPv4-mapped IPv6."""
    parts = bytes(int(x) for x in ipv4_str.split("."))
    return b"\x00" * 10 + b"\xff\xff" + parts


def var_str(b: bytes) -> bytes:
    """Zwraca compactSize(len(b)) + dane; format zmiennego stringa w protokole."""
    return compact_size_encode(len(b)) + b


def build_message(command: str, payload: bytes) -> bytes:
    """
    Składa pełną wiadomość P2P:
    magic (4B) + command (12B) + length (4B) + checksum (4B) + payload.
    """
    cmd = command.encode("ascii")
    cmd_padded = cmd + b"\x00" * (12 - len(cmd))
    length = struct.pack("<I", len(payload))
    csum = checksum(payload)
    return MAINNET_MAGIC + cmd_padded + length + csum + payload


def build_ping_payload() -> bytes:
    """Payload 'ping' – 8-bajtowy losowy nonce."""
    nonce = random.getrandbits(64)
    return struct.pack("<Q", nonce)


def build_getaddr_payload() -> bytes:
    """Payload 'getaddr' – pusty (sama komenda wystarcza)."""
    return b""


HELP_TEXT = """
Dostępne komendy:
    help
    - pokaż tę pomoc
 
  connectseed
    - połącz się z losowym peerem z listy DNS seedów (8333)
 
  connect <ip> [port]
    - połącz się z konkretnym peerem, np. connect 1.2.3.4 8333
 
  getaddr
    - wyślij getaddr i wypisz listę peerów z odpowiedzi addr
 
  peers
    - wypisz peery z ostatniej wiadomości 'addr'
 
  ping
    - wyślij ping i poczekaj na pong
 
  quit / exit
    - zakończ program
"""


def main():
    """
    Tworzy obiekt BitcoinPeer i obsługuje proste CLI:
    help / connect / quit.
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
        elif cmd == "connectseed":
            peer.connect_via_seeds()
        elif cmd == "getaddr":
            peer.send_getaddr()
        elif cmd == "peers":
            peer.list_last_addr_peers()
        elif cmd == "ping":
            peer.send_ping()
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
