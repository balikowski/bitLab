import socket
import struct
import time
import random
import hashlib
import select
from typing import List, Tuple, Optional, Dict, Union, Any

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

def parse_addr_payload(payload: bytes) -> List[Tuple[str, int, int, int]]:
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
        self.last_inv_items = []      # ostatnie inv (lista (type, hash))
        self.last_block_txids = []

    def _ensure_connected(self):
        """Sprawdza, czy istnieje aktywne połączenie z peerem."""
        if not self.sock:
            print("[-] Brak połączenia z peerem. Użyj: connectseed albo connect <ip> [port].")
            return False
        return True


    def _send_msg(self, command: str, payload: bytes):
        """Buduje i wysyła pojedynczą wiadomość P2P."""
        if not self._ensure_connected():
            return
        msg = build_message(command, payload)
        self.sock.sendall(msg)
        print(f"[<] Wysłano '{command}' ({len(payload)} B).")

    def send_getaddr(self):
        """
        Wysyła do peera wiadomość 'getaddr',
        a następnie czeka na odpowiedź typu 'addr' i zapisuje z niej otrzymaną listę adresów sieci Bitcoin.
        """
        if not self._ensure_connected():
            return
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
        if not self._ensure_connected():
            return
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
        if not self._ensure_connected():
            return
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
    
    def send_getheaders(self, locator_hashes_hex, stop_hash_hex=None, timeout: float = 30.0):
        """
        Wysyła getheaders i czeka na headers.
        locator_hashes_hex: lista hashy (hex BE). W praktyce możesz podać 1 hash.
        """
        if not self._ensure_connected():
            return
        payload = build_getheaders_payload(locator_hashes_hex, stop_hash_hex)
        self._send_msg("getheaders", payload)

        print("[+] Czekam na 'headers'...")
        _, pl = self._poll_until({"headers"}, timeout=timeout)

        headers = parse_headers_payload(pl)
        print(f"[+] Otrzymano headers: {len(headers)}")

        for i, h in enumerate(headers[:20], 1):
            tstr = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(h["time"]))
            print(f"  {i:3d}. {h['hash']}  time={tstr}  prev={h['prev_block']}")

        return headers
    
    def send_getblocks(self, locator_hashes_hex, stop_hash_hex=None, timeout: float = 30.0):
        """
        Wysyła getblocks i czeka na inv.
        Zwraca listę (inv_type, hash_hex_be).
        """
        if not self._ensure_connected():
            return

        payload = build_getblocks_payload(locator_hashes_hex, stop_hash_hex)
        self._send_msg("getblocks", payload)

        print("[+] Czekam na 'inv'...")
        try:
            _, pl = self._poll_until({"inv"}, timeout=timeout)
        except TimeoutError as e:
            print(f"[-] Timeout: {e}")
            return

        items = parse_inv_payload(pl)
        self.last_inv_items = items
        print(f"[+] Otrzymano inv: {len(items)} pozycji")

        for i, (t, hx) in enumerate(items[:50], 1):
            typ = "TX" if t == INV_TYPE_TX else ("BLOCK" if t == INV_TYPE_BLOCK else str(t))
            print(f"  {i:3d}. {typ} {hx}")

        return items
    
    def request_block(self, block_hash_hex: str, timeout: float = 60.0):
        """
        getdata(BLOCK) -> czeka na 'block'
        Zwraca (info_dict, raw_payload).
        """
        if not self._ensure_connected():
            return

        payload = build_getdata_payload([(INV_TYPE_BLOCK, block_hash_hex)])
        self._send_msg("getdata", payload)

        print("[+] Czekam na 'block'...")
        try:
            _, pl = self._poll_until({"block"}, timeout=timeout)
        except TimeoutError as e:
            print(f"[-] Timeout: {e}")
            return

        info = parse_block_minimal(pl)
        try:
            total, txids = extract_txids_from_block_payload(pl, limit=50)
            self.last_block_txids = txids
            print(f"[+] TX w bloku: {total} (zapisano/wyświetlono pierwsze {len(txids)})")
            for i, txid in enumerate(txids[:20], 1):
                print(f"    tx{i:02d}: {txid}")
        except Exception as e:
            print(f"[!] Nie udało się wyciągnąć txid z bloku: {e}")

        tstr = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(info["time"]))
        print(f"[+] BLOCK {info['hash']}  tx_count={info['tx_count']}  time={tstr}  bytes={info['payload_bytes']}")
        return info, pl

    def request_tx(self, tx_hash_hex: str, timeout: float = 60.0):
        """
        getdata(TX) -> czeka na 'tx'
        Zwraca raw payload transakcji (bytes).
        """
        if not self._ensure_connected():
            return

        payload = build_getdata_payload([(INV_TYPE_TX, tx_hash_hex)])
        self._send_msg("getdata", payload)

        print("[+] Czekam na 'tx'...")
        try:
            _, pl = self._poll_until({"tx"}, timeout=timeout)
        except TimeoutError as e:
            print(f"[-] Timeout: {e}")
            return

        computed_txid = txid_from_tx_payload(pl)
        print(f"[+] TX otrzymana. txid(z payloadu)={computed_txid}  bytes={len(pl)}")
        return pl

    def wait_inv(self, timeout: float = 60.0):
        """Czeka na 'inv' od peera (np. nowe TX/bloki) i zapisuje do last_inv_items."""
        if not self._ensure_connected():
                return
        print("[+] Czekam na 'inv'...")
        try:
            _, pl = self._poll_until({"inv"}, timeout=timeout)
        except TimeoutError as e:
            print(f"[-] Timeout: {e}")
            return

        items = parse_inv_payload(pl)
        self.last_inv_items = items
        print(f"[+] Otrzymano inv: {len(items)} pozycji")
        for i, (t, hx) in enumerate(items[:50], 1):
            typ = "TX" if t == INV_TYPE_TX else ("BLOCK" if t == INV_TYPE_BLOCK else str(t))
            print(f"  {i:3d}. {typ} {hx}")
        return items

    def list_last_inv(self, only_type: int | None = None):
        """Wypisuje ostatnie inv; opcjonalnie filtruje po typie."""
        if not self.last_inv_items:
            print("[-] Brak zapisanych inv – użyj getblocks albo waitinv.")
            return
        items = self.last_inv_items
        if only_type is not None:
            items = [(t, h) for (t, h) in items if t == only_type]

        print(f"[+] Ostatnie inv ({len(items)}):")
        for i, (t, hx) in enumerate(items, 1):
            typ = "TX" if t == INV_TYPE_TX else ("BLOCK" if t == INV_TYPE_BLOCK else str(t))
            print(f"  {i:3d}. {typ} {hx}")
    
    def gettx_from_last_block(self, index_1based: int):
        """Pobiera tx z ostatnio pobranego bloku, wybierając txid po indeksie 1..N."""
        if not self.last_block_txids:
            print("[-] Brak txid z ostatniego bloku – użyj najpierw getblock <hash>.")
            return
        if index_1based < 1 or index_1based > len(self.last_block_txids):
            print(f"[-] Zły indeks. Dostępne: 1..{len(self.last_block_txids)}")
            return
        txid = self.last_block_txids[index_1based - 1]
        print(f"[+] Pobieram TX #{index_1based}: {txid}")
        return self.request_tx(txid)

    


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

# --- Inventory (inv/getdata) ---
# Standardowe typy obiektów dla inv/getdata
INV_TYPE_TX = 1
INV_TYPE_BLOCK = 2

def hex_to_hash_le(hex_str: str) -> bytes:
    """
    Hash podawany przez ludzi (hex) jest zwykle w big-endian.
    W protokole P2P Bitcoin hash idzie jako 32 bajty little-endian.
    """
    h = bytes.fromhex(hex_str.strip())
    if len(h) != 32:
        raise ValueError("Hash musi mieć 32 bajty (64 znaki hex).")
    return h[::-1]  # LE do payloadu

def hash_le_to_hex(hash_le: bytes) -> str:
    """32 bajty little-endian z payloadu -> hex big-endian do wyświetlenia."""
    if len(hash_le) != 32:
        raise ValueError("Hash w payloadzie musi mieć 32 bajty.")
    return hash_le[::-1].hex()

def build_inv_payload(items) -> bytes:
    """
    Buduje payload wiadomości 'inv'.

    items: lista elementów w formie:
      - (inv_type:int, hash_hex:str)   np. (2, "000000...") albo
      - (inv_type:int, hash_le:bytes)  (32 bajty)
    """
    out = bytearray()
    out += compact_size_encode(len(items))
    for inv_type, h in items:
        if isinstance(h, str):
            h_le = hex_to_hash_le(h)
        else:
            if len(h) != 32:
                raise ValueError("hash_le musi mieć 32 bajty.")
            h_le = h
        out += struct.pack("<I", inv_type) + h_le
    return bytes(out)

def parse_inv_payload(payload: bytes) -> List[Tuple[int, str]]:
    """
    Parsuje payload 'inv' i zwraca listę:
      [(inv_type, hash_hex_be), ...]
    """
    res = []
    if not payload:
        return res
    count, off = compact_size_decode(payload, 0)
    for _ in range(count):
        if off + 36 > len(payload):
            break
        inv_type = struct.unpack("<I", payload[off:off+4])[0]
        off += 4
        h_le = payload[off:off+32]
        off += 32
        res.append((inv_type, hash_le_to_hex(h_le)))
    return res

def build_getdata_payload(items) -> bytes:
    """Payload getdata ma identyczny format jak inv."""
    return build_inv_payload(items)

def build_getheaders_payload(locator_hashes_hex, stop_hash_hex=None) -> bytes:
    """
    Payload getheaders:
      version (4B LE) +
      hash_count (compactSize) +
      locator_hashes (32B each, LE) +
      stop_hash (32B, LE; 0..0 jeśli None)
    locator_hashes_hex: lista hashy w hex (BE, jak zwykle zapisujemy w tekstach)
    stop_hash_hex: opcjonalny hash stopu (BE). Jeśli None -> 32 bajty zer.
    """
    version = struct.pack("<i", PROTOCOL_VERSION)
    out = bytearray(version)

    out += compact_size_encode(len(locator_hashes_hex))
    for hx in locator_hashes_hex:
        out += hex_to_hash_le(hx)

    if stop_hash_hex:
        out += hex_to_hash_le(stop_hash_hex)
    else:
        out += b"\x00" * 32

    return bytes(out)

def build_getblocks_payload(locator_hashes_hex, stop_hash_hex=None) -> bytes:
    """
    Payload getblocks ma taki sam układ jak getheaders:
      version + varint(count) + locator_hashes + stop_hash
    """
    return build_getheaders_payload(locator_hashes_hex, stop_hash_hex)

def parse_headers_payload(payload: bytes):
    """
    Payload 'headers':
      count (compactSize)
      powtórzone count razy:
        - 80B nagłówka bloku
        - txn_count (compactSize)  (zwykle 0 w headers)

    Zwraca listę dictów z podstawowymi polami + hash nagłówka (block hash).
    """
    headers: List[Dict[str, Any]] = []
    if not payload:
        return headers

    count, off = compact_size_decode(payload, 0)

    for _ in range(count):
        if off + 80 > len(payload):
            break

        hdr = payload[off:off+80]
        off += 80

        # txn_count (ignorujemy wartość, ale musimy przesunąć offset)
        _, off = compact_size_decode(payload, off)

        ver, = struct.unpack("<I", hdr[0:4])
        prev_le = hdr[4:36]
        merkle_le = hdr[36:68]
        ts, bits, nonce = struct.unpack("<III", hdr[68:80])

        # Hash bloku = sha256d(header), do wyświetlania w BE
        block_hash_be = sha256d(hdr)[::-1].hex()

        headers.append({
            "hash": block_hash_be,
            "version": ver,
            "prev_block": hash_le_to_hex(prev_le),
            "merkle_root": hash_le_to_hex(merkle_le),
            "time": ts,
            "bits": bits,
            "nonce": nonce,
        })

    return headers

def parse_block_minimal(payload: bytes):
    """
    Minimalny parser bloku:
    - czyta nagłówek (80B)
    - czyta tx_count (compactSize)
    Nie parsuje samych transakcji (to dużo roboty).
    """
    if len(payload) < 80:
        raise ValueError("Za mały payload na block (min 80B).")

    hdr = payload[:80]
    tx_count, _ = compact_size_decode(payload, 80)

    ver, = struct.unpack("<I", hdr[0:4])
    prev_le = hdr[4:36]
    merkle_le = hdr[36:68]
    ts, bits, nonce = struct.unpack("<III", hdr[68:80])

    block_hash_be = sha256d(hdr)[::-1].hex()

    return {
        "hash": block_hash_be,
        "version": ver,
        "prev_block": hash_le_to_hex(prev_le),
        "merkle_root": hash_le_to_hex(merkle_le),
        "time": ts,
        "bits": bits,
        "nonce": nonce,
        "tx_count": tx_count,
        "payload_bytes": len(payload),
    }


def txid_from_tx_payload(tx_payload: bytes) -> str:
    """
    Oblicza poprawny TXID transakcji.
    Dla SegWit: TXID = sha256d(legacy_serialization).
    Dla Legacy: TXID = sha256d(full_payload).
    """
    try:
        _, legacy_bytes, _ = parse_one_tx(tx_payload, 0)
        return sha256d(legacy_bytes)[::-1].hex()
    except Exception:
        # Fallback na wypadek błędu parsowania (np. niekompletne dane)
        return sha256d(tx_payload)[::-1].hex()

def read_compact_size(buf: bytes, offset: int):
    """Alias: czytelniejsza nazwa."""
    return compact_size_decode(buf, offset)

def parse_one_tx(buf: bytes, offset: int):
    """
    Parsuje jedną transakcję od offsetu.
    Zwraca (full_tx_bytes, legacy_tx_bytes, new_offset).
    
    legacy_tx_bytes: serializacja bez markerów SegWit i bez danych Witness.
    Służy ona do obliczania poprawnego TXID.
    """
    start_offset = offset
    legacy_parts = []

    def need(n: int):
        if offset + n > len(buf):
            raise ValueError(f"Parsowanie TX: za mało danych (potrzeba {n} B).")

    # 1. Version (4B)
    need(4)
    legacy_parts.append(buf[offset:offset+4])
    offset += 4

    # 2. SegWit Check (Marker 0x00 + Flag 0x01)
    is_segwit = False
    if offset + 2 <= len(buf):
        if buf[offset] == 0x00 and buf[offset+1] == 0x01:
            is_segwit = True
            offset += 2  # Przesuwamy offset (czytamy marker), ale NIE dodajemy do legacy

    # 3. Inputs
    vin_start = offset
    vin_cnt, offset = read_compact_size(buf, offset)
    # Kopiujemy vin_cnt (varint) do legacy
    legacy_parts.append(buf[vin_start:offset])

    for _ in range(vin_cnt):
        # Stała część inputu: prev_hash(32) + vout(4) = 36 bajtów
        need(36)
        
        # Aby skopiować cały input do legacy, musimy znać jego długość
        # Obliczamy: 36 + varint(script_len) + script_len + sequence(4)
        
        # Tymczasowy kursor do odczytu długości skryptu
        tmp_off = offset + 36
        script_len, tmp_off = read_compact_size(buf, tmp_off)
        
        total_input_len = (tmp_off - offset) + script_len + 4
        need(total_input_len)
        
        # Cały input trafia do legacy (w SegWit scriptSig też jest w legacy)
        legacy_parts.append(buf[offset : offset + total_input_len])
        offset += total_input_len

    # 4. Outputs
    vout_start = offset
    vout_cnt, offset = read_compact_size(buf, offset)
    legacy_parts.append(buf[vout_start:offset])

    for _ in range(vout_cnt):
        # 8 bajtów (value) + varint(pk_len) + pk_len
        need(8)
        
        tmp_off = offset + 8
        pk_len, tmp_off = read_compact_size(buf, tmp_off)
        
        total_output_len = (tmp_off - offset) + pk_len
        need(total_output_len)
        
        legacy_parts.append(buf[offset : offset + total_output_len])
        offset += total_output_len

    # 5. Witness data (JEŚLI SegWit -> pomijamy w legacy)
    if is_segwit:
        for _ in range(vin_cnt):
            nstack, offset = read_compact_size(buf, offset)
            for _ in range(nstack):
                item_len, offset = read_compact_size(buf, offset)
                need(item_len)
                offset += item_len

    # 6. Locktime (4B)
    need(4)
    legacy_parts.append(buf[offset:offset+4])
    offset += 4

    # Wyniki
    full_tx_bytes = buf[start_offset:offset]
    legacy_tx_bytes = b"".join(legacy_parts)
    
    return full_tx_bytes, legacy_tx_bytes, offset

def extract_txids_from_block_payload(block_payload: bytes, limit: int = 50):
    """
    Wyciąga txid-y z payloadu 'block' (header + tx_count + tx...).
    Zwraca listę txid (hex BE). Limit kontroluje ile wypisujemy/zapisujemy.
    """
    if len(block_payload) < 80:
        raise ValueError("Za mały payload bloku.")

    tx_count, off = read_compact_size(block_payload, 80)

    txids = []
    for i in range(tx_count):
        # Pobieramy też legacy_bytes do poprawnego hashowania
        tx_bytes, legacy_bytes, off = parse_one_tx(block_payload, off)
        
        # TXID to hash z formatu legacy
        txid = sha256d(legacy_bytes)[::-1].hex()
        
        txids.append(txid)
        if len(txids) >= limit:
            break

    return tx_count, txids


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

  getheaders <locator_hash> [stop_hash]
    - wyślij getheaders i wypisz nagłówki (pokazuje do 20)
    - locator_hash: hash znanego bloku (64 znaki hex)
 
  getblocks <locator_hash> [stop_hash]
    - wyślij getblocks i wypisz inv (hashy bloków/tx)
    - locator_hash: hash znanego bloku (64 znaki hex)

  getblock <block_hash>
    - getdata(block) i pobierz 'block' (minimalnie parsuje nagłówek + tx_count)

  gettx <tx_hash>
    - getdata(tx) i pobierz 'tx' (surowy payload)
    waitinv
    - czeka na 'inv' od peera i zapisuje (czasem peer ogłasza TX/bloki)

  inv
    - wypisuje ostatnie inv

  invtx
    - wypisuje tylko TX z ostatniego inv

  gettxi <n>
    - pobiera TX po indeksie z listy txid uzyskanej z ostatniego getblock

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

        try:
            if cmd == "connectseed":
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
                try:
                    port = int(parts[2]) if len(parts) > 2 else 8333
                except ValueError:
                    print("[-] Port musi być liczbą.")
                    continue
                peer.connect(ip, port)
            elif cmd == "getheaders":
                if len(parts) < 2:
                    print("Użycie: getheaders <locator_hash> [stop_hash]")
                    continue
                locator = parts[1]
                stop = parts[2] if len(parts) > 2 else None
                peer.send_getheaders([locator], stop)

            elif cmd == "getblocks":
                if len(parts) < 2:
                    print("Użycie: getblocks <locator_hash> [stop_hash]")
                    continue
                locator = parts[1]
                stop = parts[2] if len(parts) > 2 else None
                peer.send_getblocks([locator], stop)

            elif cmd == "getblock":
                if len(parts) < 2:
                    print("Użycie: getblock <block_hash>")
                    continue
                if len(parts[1]) != 64:
                     print("[-] Hash bloku musi mieć 64 znaki hex.")
                     continue
                try:
                    peer.request_block(parts[1])
                except ValueError as e:
                    print(f"[-] Błąd: {e}")

            elif cmd == "gettx":
                if len(parts) < 2:
                    print("Użycie: gettx <tx_hash>")
                    continue
                if len(parts[1]) != 64:
                     print("[-] Hash TX musi mieć 64 znaki hex. Jeśli chciałeś gettxi, sprawdź komendę.")
                     continue
                try:
                    peer.request_tx(parts[1])
                except ValueError as e:
                    print(f"[-] Błąd: {e}")

            elif cmd == "waitinv":
                peer.wait_inv()

            elif cmd == "inv":
                peer.list_last_inv()

            elif cmd == "invtx":
                peer.list_last_inv(only_type=INV_TYPE_TX)

            elif cmd == "gettxi":
                if len(parts) < 2:
                    print("Użycie: gettxi <n>")
                    continue
                try:
                    idx = int(parts[1])
                    peer.gettx_from_last_block(idx)
                except ValueError:
                    print("[-] Indeks musi być liczbą całkowitą.")

            else:
                print("[-] Nieznana komenda.")

        except (ConnectionError, BrokenPipeError) as e:
            print(f"[-] Połączenie przerwane: {e}")
            peer.close()
        except KeyboardInterrupt:
            print("\n[-] Przerwano przez użytkownika (Ctrl+C).")
            break
        except Exception as e:
            print(f"[!] Nieoczekiwany błąd: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()

     
