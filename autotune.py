"""Hatta hangi desync stratejisinin calistigini uygulamanin kendisi olcer.

Neden var: tek bir sabit strateji her hatta calismiyor. Olculen iki ornek —
sabit hatta sahte paketin sunucuya ULASMAMASI dogru sira numarasi + bozuk
saglama ile saglanmali (DPI'in birlestirme tamponuna sahte SNI girsin diye),
iPhone USB tethering'de ise ayni bozuk saglama NAT tarafindan ONARILDIGI icin
sahte paket sunucuya gecerli olarak varir ve TUM HTTPS sitelerini bozar; orada
dogru olan bozuk sira numarasidir. Yani "her yerde dogru" tek bir varsayilan
yok. Kullaniciya mod sectirmek yerine (GoodbyeDPI'in -1..-9 yaklasimi) uygulama
acilista hatti kendi olcer, calisan kombinasyonu secer ve ag parmak izine gore
onbellege alir. Kullanici hicbir ayar yapmaz.

Olcum, motorun kullanacagi KODUN AYNISINI kullanir (strategies.tcp_fragment_and_send),
boylece "olcumde calisti ama uygulamada calismadi" farki olusamaz.
"""

import ctypes
import json
import os
import socket
import struct
import threading
import time

import pydivert

from config import STATE_DIR
from strategies import extract_sni, tcp_fragment_and_send

CACHE_FILE = os.path.join(STATE_DIR, "autotune.json")

# Denenme sirasi. Ustteki kombinasyon en genis dogrulanmis olan: sahte paket
# DOGRU sira numarasiyla gider (birlestiren DPI onu gercek ClientHello sanar),
# bozuk saglama ve dusuk TTL sunucuya ulasmasini engeller; gercek ClientHello
# TLS kayit basligindan ikiye bolunup ters sirada gonderilir.
CANDIDATES = (
    ("badsum", "record"),
    ("badsum", "sni"),
    ("badsum", "none"),
    ("both", "record+sni"),
    ("both", "record"),
    ("badseq", "record"),
    ("off", "record+sni"),
)

# Ilki engelli bulunana kadar sirayla denenir; engelli bulunan hedef, adaylarin
# uzerinde olculdugu hedef olur. Hicbiri engelli degilse hatta DPI engeli yok
# demektir ve olcut "normal siteleri bozmamak"a doner.
PROBE_TARGETS = ("discord.com", "gateway.discord.gg", "x.com", "www.instagram.com")

# Secilen stratejinin normal trafigi bozmadigini dogrulamak icin. Bir strateji
# engelli hedefi acsa bile bunlardan birini bozuyorsa reddedilir — "her siteyi
# bozan bypass" hatasi tam olarak boyle onlenir.
CONTROL_TARGETS = ("www.google.com", "www.cloudflare.com")

DOH_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")

# Cache omru. Ag parmak izi degismese bile ISP kurallari degisebilir; suresi
# dolunca sessizce yeniden olculur.
CACHE_TTL = 7 * 24 * 3600
# Hicbir strateji tutmadiginda kisa omurlu kayit: her acilista bastan olcup
# kullaniciyi bekletmemek icin, ama yarin tekrar denemek icin.
CACHE_TTL_FAILED = 3600

PROBE_TIMEOUT = 3.0          # tek bir TLS denemesi
RESOLVE_TIMEOUT = 3.0        # tek bir DoH sorgusu
TOTAL_BUDGET = 45.0          # tum tarama


# ------------------------------------------------------------------ ag kimligi
class _MIB_IPFORWARDROW(ctypes.Structure):
    _fields_ = [("dwForwardDest", ctypes.c_ulong),
                ("dwForwardMask", ctypes.c_ulong),
                ("dwForwardPolicy", ctypes.c_ulong),
                ("dwForwardNextHop", ctypes.c_ulong),
                ("dwForwardIfIndex", ctypes.c_ulong),
                ("dwForwardType", ctypes.c_ulong),
                ("dwForwardProto", ctypes.c_ulong),
                ("dwForwardAge", ctypes.c_ulong),
                ("dwForwardNextHopAS", ctypes.c_ulong),
                ("dwForwardMetric1", ctypes.c_ulong),
                ("dwForwardMetric2", ctypes.c_ulong),
                ("dwForwardMetric3", ctypes.c_ulong),
                ("dwForwardMetric4", ctypes.c_ulong),
                ("dwForwardMetric5", ctypes.c_ulong)]


def _default_route():
    """(gateway_ip, ifindex) — varsayilan rota. Basarisizsa (None, None)."""
    try:
        row = _MIB_IPFORWARDROW()
        dest = struct.unpack("<I", socket.inet_aton("8.8.8.8"))[0]
        if ctypes.windll.iphlpapi.GetBestRoute(dest, 0, ctypes.byref(row)) != 0:
            return None, None
        gw = socket.inet_ntoa(struct.pack("<I", row.dwForwardNextHop))
        return gw, int(row.dwForwardIfIndex)
    except Exception:
        return None, None


def _gateway_mac(gw_ip: str):
    """Ag gecidinin MAC adresi — 'ayni ag mi' sorusunun en saglam cevabi.

    IP ve arayuz adi ayni kalip ag degisebilir (ayni 192.168.1.0/24'u kullanan
    baska bir modem); MAC bunu ayirir.
    """
    try:
        buf = (ctypes.c_ubyte * 6)()
        blen = ctypes.c_ulong(6)
        dest = struct.unpack("<I", socket.inet_aton(gw_ip))[0]
        if ctypes.windll.iphlpapi.SendARP(dest, 0, ctypes.byref(buf),
                                          ctypes.byref(blen)) != 0:
            return None
        return "-".join("%02x" % b for b in buf[:blen.value])
    except Exception:
        return None


def network_signature() -> str:
    """Bagli olunan agin parmak izi. Degisirse strateji yeniden olculur."""
    gw, ifindex = _default_route()
    if not gw:
        return "unknown"
    return "%s|%s|%s" % (ifindex, gw, _gateway_mac(gw) or "?")


# ------------------------------------------------------------------ onbellek
def _load_cache() -> dict:
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_cache(cache: dict) -> None:
    try:
        tmp = CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
        os.replace(tmp, CACHE_FILE)
    except OSError:
        pass


def cached_for(signature: str):
    """Bu ag icin gecerli kayit: (decoy, split) ya da None."""
    entry = _load_cache().get(signature)
    if not isinstance(entry, dict):
        return None
    ttl = CACHE_TTL if entry.get("ok") else CACHE_TTL_FAILED
    if time.time() - entry.get("ts", 0) > ttl:
        return None
    decoy, split = entry.get("decoy"), entry.get("split")
    if isinstance(decoy, str) and isinstance(split, str):
        return decoy, split
    return None


def _remember(signature: str, decoy: str, split: str, ok: bool, target: str):
    cache = _load_cache()
    cache[signature] = {"decoy": decoy, "split": split, "ok": ok,
                        "target": target, "ts": int(time.time())}
    # Sinirsiz buyumesin — en eski kayitlar dusulur.
    if len(cache) > 20:
        for key in sorted(cache, key=lambda k: cache[k].get("ts", 0))[:-20]:
            cache.pop(key, None)
    _save_cache(cache)


# ------------------------------------------------------------------ DNS
def _wire_query(name: str) -> bytes:
    q = struct.pack("!HHHHHH", 0x2A2A, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack("!HH", 1, 1)


def _parse_first_a(data: bytes):
    try:
        ancount = struct.unpack_from("!H", data, 6)[0]
        off = 12
        while data[off]:
            off += data[off] + 1
        off += 5
        for _ in range(ancount):
            if data[off] & 0xC0 == 0xC0:
                off += 2
            else:
                while data[off]:
                    off += data[off] + 1
                off += 1
            rtype, _cls, _ttl, rdlen = struct.unpack_from("!HHIH", data, off)
            off += 10
            if rtype == 1 and rdlen == 4:
                return socket.inet_ntoa(data[off:off + 4])
            off += rdlen
    except (IndexError, struct.error):
        pass
    return None


def resolve(name: str, deadline: float = None):
    """A kaydini HTTPS uzerinden cozer.

    Sistem cozumleyicisi kullanilamaz: port 53'u kesen ISP'de her cozumleyici
    engel sayfasinin adresini dondurur, ona baglanip "acildi" demek olcumu
    tamamen gecersiz kilar. Cloudflare/Google/Quad9 sertifikalari cozumleyici
    IP'sini kapsadigi icin URL dogrudan IP olabilir ve DNS'e ihtiyac duymaz.
    """
    import urllib.request
    for server in DOH_RESOLVERS:
        if deadline and time.time() > deadline:
            return None
        req = urllib.request.Request(
            "https://%s/dns-query" % server, data=_wire_query(name),
            headers={"Content-Type": "application/dns-message",
                     "Accept": "application/dns-message"})
        try:
            with urllib.request.urlopen(req, timeout=RESOLVE_TIMEOUT) as r:
                ip = _parse_first_a(r.read())
            if ip:
                return ip
        except Exception:
            continue
    return None


def online() -> bool:
    """Cikis var mi? Acilista ag henuz hazir olmayabilir (onyukleme gorevi
    baglanti kurulmadan once calisir); o durumda olcume hic girismemek gerekir,
    yoksa her cozumleme zaman asimina ugrar ve motorun basalamasi geciker."""
    for server in DOH_RESOLVERS:
        s = None
        try:
            s = socket.create_connection((server, 443), 2.0)
            return True
        except Exception:
            continue
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
    return False


# ------------------------------------------------------------------ TLS olcumu
def _client_hello(host: str, size: int = 1700) -> bytes:
    """Tarayicilarinkine yakin boyutta, gercek bir ClientHello uretir.

    Python'un ssl modulunun urettigi hello kucuk kalir; DPI davranisi paket
    boyutuna ve SNI'nin kayit icindeki yerine gore degisebildigi icin olcumun
    gercek kullanimdan sapmamasi adina hello elle kurulur ve padding uzantisiyla
    tarayici boyuna cikarilir. Sunucunun anlasmayi kabul etmesi gerekmez: bir
    TLS cevabi (ServerHello ya da alert) donmesi hattin acik oldugunu kanitlar.
    """
    host_b = host.encode("ascii")
    sni = (struct.pack("!HH", 0x0000, len(host_b) + 5) +
           struct.pack("!H", len(host_b) + 3) + b"\x00" +
           struct.pack("!H", len(host_b)) + host_b)
    # supported_versions: TLS1.3 + TLS1.2
    versions = struct.pack("!HHB", 0x002B, 5, 4) + b"\x03\x04\x03\x03"
    # supported_groups: x25519, secp256r1
    groups = struct.pack("!HHH", 0x000A, 6, 4) + b"\x00\x1d\x00\x17"
    # ec_point_formats: uncompressed
    ecpf = struct.pack("!HHB", 0x000B, 2, 1) + b"\x00"
    # signature_algorithms
    sigalgs_list = b"\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01"
    sigalgs = (struct.pack("!HH", 0x000D, len(sigalgs_list) + 2) +
               struct.pack("!H", len(sigalgs_list)) + sigalgs_list)
    exts = sni + versions + groups + ecpf + sigalgs

    ciphers = (b"\x13\x01\x13\x02\x13\x03"      # TLS 1.3
               b"\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30"
               b"\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14"
               b"\x00\x9c\x00\x9d\x00\x2f\x00\x35")
    body = (b"\x03\x03" + os.urandom(32) +
            b"\x20" + os.urandom(32) +               # session_id (32)
            struct.pack("!H", len(ciphers)) + ciphers +
            b"\x01\x00")                              # compression: null

    # Padding uzantisi (RFC 7685) ile hedef boyuta tamamla.
    fixed = len(body) + 2 + len(exts) + 4 + 5      # +handshake basligi +kayit
    pad = max(0, size - fixed - 4)
    if pad:
        exts += struct.pack("!HH", 0x0015, pad) + b"\x00" * pad

    hs_body = body + struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + struct.pack("!I", len(hs_body))[1:] + hs_body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def tls_reachable(ip: str, host: str, timeout: float = PROBE_TIMEOUT) -> bool:
    """Bu SNI ile bu IP'ye TLS anlasmasi baslatilabiliyor mu?

    True: sunucudan TLS kaydi geldi (anlasma ya da alert) — engel yok.
    False: RST, zaman asimi ya da bos cevap — DPI kesti.
    """
    s = None
    try:
        s = socket.create_connection((ip, 443), timeout)
        s.settimeout(timeout)
        s.sendall(_client_hello(host))
        data = s.recv(16)
        return len(data) >= 3 and data[0] in (0x16, 0x15)
    except Exception:
        return False
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


# ------------------------------------------------------------------ olcum motoru
class _ProbeDiverter:
    """Tek bir hedef IP'ye giden ClientHello'lara aday stratejiyi uygular.

    Filtre yalnizca o IP'yi kapsar ve onceligi ana motorunkinden yuksektir, yani
    olcum sirasinda kullanicinin geri kalan trafigine dokunmaz.
    """

    def __init__(self, ip: str, decoy: str, split: str):
        self.ip = ip
        self.decoy = decoy
        self.split = split
        self.applied = 0
        self._w = None
        self._th = None

    def __enter__(self):
        flt = ("outbound and tcp and tcp.DstPort == 443 and "
               "tcp.PayloadLength > 5 and tcp.Payload[0] == 0x16 and "
               "tcp.Payload[5] == 0x01 and ip.DstAddr == %s" % self.ip)
        self._w = pydivert.WinDivert(flt, priority=1500)
        self._w.open()
        self._th = threading.Thread(target=self._loop, daemon=True)
        self._th.start()
        return self

    def __exit__(self, *exc):
        w, self._w = self._w, None
        if w is not None:
            try:
                if w.is_open:
                    w.close()
            except Exception:
                pass
        if self._th is not None:
            self._th.join(timeout=3)
        return False

    def _loop(self):
        w = self._w
        while True:
            try:
                pkt = w.recv()
            except Exception:
                return
            try:
                sni = extract_sni(bytes(pkt.payload) if pkt.payload else b"")
                if sni and tcp_fragment_and_send(w, pkt, sni, False,
                                                 self.decoy, self.split):
                    self.applied += 1
                    continue
                w.send(pkt)
            except Exception:
                try:
                    w.send(pkt)
                except Exception:
                    pass


def _works(ip: str, host: str, decoy: str, split: str) -> bool:
    """Aday strateji altinda hedef aciliyor mu?"""
    try:
        with _ProbeDiverter(ip, decoy, split):
            # Tek RST tesadufi olabilir; iki denemeden biri acilirsa gecerli say.
            return tls_reachable(ip, host) or tls_reachable(ip, host)
    except Exception:
        return False


# ------------------------------------------------------------------ ana akis
def choose(log=print, deadline: float = None):
    """Hatti olcup (decoy, split, durum, hedef) dondurur.

    durum:
      "offline"     — ag hazir degil, olcum yapilmadi (KAYDEDILMEZ)
      "engel-yok"   — hicbir hedef engelli degil; secim yalnizca "normal
                      siteleri bozmama" olcutune gore dogrulandi
      "olculdu"     — engelli hedef bulundu ve aday onu acti
      "asilamadi"   — engel var ama hicbir aday asamadi
    """
    deadline = deadline or (time.time() + TOTAL_BUDGET)
    default = CANDIDATES[0]

    # 0) Ag hazir degilse (onyuklemede motor baglantidan once basliyor) hic
    #    olcme: her sorgu zaman asimina ugrar, motor gec baslar ve sonuc da
    #    yanlis olur. "offline" kaydedilmez, ag gelince yeniden olculur.
    if not online():
        return default[0], default[1], "offline", None

    # 1) Engelli bir hedef bul. Motor kapali haldeyken acilmayan ilk hedef,
    #    adaylarin uzerinde olculecegi hedeftir.
    target = target_ip = None
    for host in PROBE_TARGETS:
        if time.time() > deadline:
            break
        ip = resolve(host, deadline)
        if not ip:
            continue
        if not tls_reachable(ip, host):
            target, target_ip = host, ip
            break

    if not target:
        # Hicbir hedef engelli degil: bu hatta DPI engeli gorunmuyor. Yine de
        # secilen strateji normal trafigi bozmamali; varsayilani dogrulayip gec.
        log("[*] Hatta engel saptanmadi — varsayilan strateji dogrulaniyor")
        decoy, split = default
        if _controls_ok(decoy, split, deadline):
            return decoy, split, "engel-yok", None
        for decoy, split in CANDIDATES[1:]:
            if time.time() > deadline:
                break
            if _controls_ok(decoy, split, deadline):
                return decoy, split, "engel-yok", None
        # Hicbiri normal siteleri bozmadan gecemedi — hicbir sey yapmayan
        # kombinasyon en guvenlisi: engel yoksa kaybedilen bir sey de yok.
        return "off", "none", "engel-yok", None

    log("[*] Engelli hedef: %s — strateji taraniyor" % target)

    # 2) Adaylari sirayla dene. Kazanan hem engelli hedefi acmali hem de normal
    #    siteleri bozmamali.
    for decoy, split in CANDIDATES:
        if time.time() > deadline:
            log("[!] Tarama suresi doldu")
            break
        if not _works(target_ip, target, decoy, split):
            continue
        if not _controls_ok(decoy, split, deadline):
            log("[!] %s/%s engeli asiyor ama normal siteleri bozuyor — elendi"
                % (decoy, split))
            continue
        return decoy, split, "olculdu", target

    return default[0], default[1], "asilamadi", target


def _controls_ok(decoy: str, split: str, deadline: float) -> bool:
    """Strateji normal (engelsiz) siteleri bozuyor mu?

    NAT/tethering yolunda bozuk saglamanin onarilmasi sahte paketi gecerli hale
    getirir ve TUM HTTPS'i bozar; bu kontrol tam olarak o durumu yakalar ve
    boyle bir stratejinin secilmesini engeller.
    """
    checked = 0
    for host in CONTROL_TARGETS:
        if time.time() > deadline:
            break
        ip = resolve(host, deadline)
        if not ip:
            continue
        checked += 1
        try:
            with _ProbeDiverter(ip, decoy, split):
                if not (tls_reachable(ip, host) or tls_reachable(ip, host)):
                    return False
        except Exception:
            return False
    return checked > 0


def resolve_strategy(settings: dict, log=print, force: bool = False):
    """Motorun kullanacagi (decoy, split). Gerekiyorsa olcer, gerekmiyorsa
    onbellekten doner.

    settings icinde elle secim varsa (strategy_mode != "auto") ona saygi
    gosterilir — gelistirici/destek senaryosu icin kapi acik kalir, ama
    varsayilan kurulumda kimse bunu ayarlamak zorunda degildir.
    """
    if settings.get("strategy_mode", "auto") != "auto":
        return (settings.get("decoy_mode", "badsum"),
                settings.get("split_mode", "record"), "elle")

    sig = network_signature()
    if not force:
        hit = cached_for(sig)
        if hit:
            return hit[0], hit[1], "onbellek"

    log("[*] Hat taraniyor (ilk kurulum / yeni ag)...")
    t0 = time.time()
    decoy, split, status, target = choose(log)

    if status == "offline":
        # Kaydetme: baglanti gelince yeniden olculmeli. Ag imzasi da degisecegi
        # icin motor bunu kendiliginden tetikler.
        log("[*] Ag henuz hazir degil — varsayilan strateji ile baslaniyor")
        return decoy, split, "offline"

    # Imzasi cikarilamayan ag (varsayilan rota yok) onbellege anahtar olamaz;
    # yanlis agin sonucunu baska aga uygulamaktansa her seferinde olcmek dogru.
    if sig != "unknown":
        _remember(sig, decoy, split, status != "asilamadi", target or "")

    log("[*] Strateji secildi: %s / %s (%.1fs, %s)"
        % (decoy, split, time.time() - t0, status))
    if status == "asilamadi":
        log("[!] Bu hatta hicbir strateji engeli asamadi — varsayilan kullaniliyor")
    return decoy, split, "olculdu"
