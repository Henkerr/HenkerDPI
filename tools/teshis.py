"""HenkerDPI teshis araci.

Kullanicinin kendi hattinda hangi DPI-asma stratejisinin calistigini olcer ve
masaustune okunabilir bir rapor birakir. Uzaktan tahmin yurutmek yerine veri
toplamak icin: kullanici raporu geri gonderir, dogru varsayilan ona gore secilir.

DNS'i denklemden cikarir — hedeflere 1.1.1.1'den cozulen IP ile baglanip SNI'yi
elle set eder, boylece DNS yonlendirmesi ile DPI engeli birbirine karismaz.

Tek basina calisir; kurulu HenkerDPI'ye dokunmaz, ayarlari degistirmez, sistem
DNS'ini elleme. Yonetici gerekir (WinDivert surucusu).
"""
import ctypes
import os
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pydivert  # noqa: E402
from strategies import extract_sni, _build_packet, _corrupt_tcp_checksum, FAKE_TTL  # noqa: E402

MAIN_FILTER = ("outbound and tcp and tcp.DstPort == 443 and tcp.PayloadLength > 5 and "
               "tcp.Payload[0] == 0x16 and tcp.Payload[5] == 0x01 and "
               "ip.DstAddr != 127.0.0.1")
RST_FILTER = "inbound and tcp and tcp.Rst and tcp.SrcPort == 443"

TARGETS = ["discord.com", "gateway.discord.gg", "cdn.discordapp.com"]
CONTROL = ["www.google.com", "www.cloudflare.com"]
SEQ_BACK = 0x10000
RESOLVER = "1.1.1.1"

# Turkiye'de engelli alan adlari icin donen bilinen yonlendirme adresleri.
BLOCK_IPS = {"195.175.254.2", "195.175.254.1"}

report = []


def out(s=""):
    print(s)
    report.append(s)


# ----------------------------------------------------------------- DNS
def _wire_query(name):
    q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack("!HH", 1, 1)


def dns_query_doh(name, server_ip=RESOLVER, timeout=6.0):
    """A-kaydini HTTPS uzerinden sorar — port 53'u kesen ISP'yi atlar.

    Bu sart: bu hatta duz 53 sorgusu her cozumleyici icin engel sayfasinin
    adresini donuyor. Onunla cozulen IP'ye baglanip "acildi" demek, Discord'u
    degil ISP'nin engel sunucusunu olcmek olur ve tum matrisi gecersiz kilar.
    Cloudflare/Google/Quad9 sertifikalari cozumleyici IP'sini kapsadigi icin
    URL dogrudan IP olabilir; dogrulama acik kalir.
    """
    req = urllib.request.Request(
        "https://%s/dns-query" % server_ip, data=_wire_query(name),
        headers={"Content-Type": "application/dns-message",
                 "Accept": "application/dns-message"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
    except Exception:
        return None
    return _parse_first_a(data)


def dns_query(name, server, timeout=4.0):
    """Minimal A-kaydi sorgusu — sistem cozumleyicisini bypass eder."""
    q = _wire_query(name)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(2048)
    finally:
        s.close()
    return _parse_first_a(data)


def _parse_first_a(data):
    """Ilk A kaydini dondurur (wire-format cevap, DoH ve UDP icin ortak)."""
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
            rtype, _, _, rdlen = struct.unpack_from("!HHIH", data, off)
            off += 10
            if rtype == 1 and rdlen == 4:
                return ".".join(str(b) for b in data[off:off + 4])
            off += rdlen
    except (IndexError, struct.error):
        return None
    return None


# ------------------------------------------------------------ stratejiler
def send_variant(w, packet, sni, v):
    payload = bytes(packet.payload)
    raw = bytes(packet.raw)
    l4 = (raw[0] & 0x0F) * 4
    tcp_hlen = ((raw[l4 + 12] >> 4) & 0xF) * 4
    headers = raw[:l4 + tcp_hlen]
    seq = struct.unpack_from("!I", raw, l4 + 4)[0]
    ack = struct.unpack_from("!I", raw, l4 + 8)[0]
    iface, direction = packet.interface, packet.direction

    sni_pos = payload.find(sni.encode())
    sni_mid = (sni_pos + len(sni) // 2) if sni_pos != -1 else len(payload) // 3
    sni_end = (sni_pos + len(sni)) if sni_pos != -1 else len(payload) // 2

    def resolve(c):
        if c == "snimid":
            return sni_mid
        if c == "snistart":
            return max(1, sni_pos)
        if c == "sniend":
            return sni_end
        return int(c)

    cuts = sorted({max(1, min(resolve(c), len(payload) - 1)) for c in v["splits"]})

    def send_fake():
        """Sahte ClientHello. Seq DOGRU ise DPI'in birlestirme tamponuna once o
        girer ve gercek baytlar 'tekrar' sayilir; sunucu ise bozuk saglama /
        dusuk TTL yuzunden onu atar. badseq bunu iptal eder: pencere disindaki
        segmenti birlestiren DPI zaten yok sayar."""
        fake_dom = ("www.w3.org" + "w" * len(sni))[:len(sni)]
        fp = (payload[:sni_pos] + fake_dom.encode() + payload[sni_pos + len(sni):]
              if sni_pos != -1 else payload)
        fseq = (seq - SEQ_BACK) & 0xFFFFFFFF if "badseq" in v["decoy"] else seq
        fake = _build_packet(headers, fp, l4, fseq, ack, iface, direction, ttl=v["ttl"])
        if "badsum" in v["decoy"]:
            fake = _corrupt_tcp_checksum(fake, l4)
            for _ in range(v["repeats"]):
                w.send(fake, recalculate_checksum=False)
        else:
            for _ in range(v["repeats"]):
                w.send(fake)

    if v["decoy"] and not v["fake_last"]:
        send_fake()

    bounds = [0] + cuts + [len(payload)]
    segs = []
    for i, (a, b) in enumerate(zip(bounds, bounds[1:])):
        if i == 0 and v["seqovl"]:
            # Ilk segmentin onune, pencerenin BASLANGICINDAN once oturan cop
            # bayt ekle. Sunucunun TCP yigini bu kismi kirpip gercek veriyi
            # alir; akisi birlestiren DPI ise copu de iceri katar ve elindeki
            # ClientHello bozulur. Yeniden birlestiren DPI'a karsi bolmenin
            # tek basina yetmedigi yerde calisan teknik budur.
            k = v["seqovl"]
            segs.append(_build_packet(headers, b"\x00" * k + payload[a:b], l4,
                                      (seq - k) & 0xFFFFFFFF, ack, iface, direction))
        else:
            segs.append(_build_packet(headers, payload[a:b], l4, seq + a, ack,
                                      iface, direction))
    if v["reverse"]:
        segs = segs[::-1]
    for s in segs:
        w.send(s)

    if v["decoy"] and v["fake_last"]:
        send_fake()
    return True


class Engine(threading.Thread):
    def __init__(self, v):
        super().__init__(daemon=True)
        self.v = v
        self.count = 0
        self.rst_dropped = 0
        # Sahte paket ya da ustuste binen segment de ClientHello'yu yakalamayi
        # gerektirir; kanci yalnizca bolme varsa acmak onlari olcum disi birakir.
        needs_divert = bool(v["splits"] or v["decoy"] or v["seqovl"])
        self.w = pydivert.WinDivert(MAIN_FILTER) if needs_divert else None
        if self.w:
            self.w.open()
        self.rst = None
        if v["rstdrop"]:
            self.rst = pydivert.WinDivert(RST_FILTER)
            self.rst.open()
            threading.Thread(target=self._rst_loop, daemon=True).start()

    def _rst_loop(self):
        while True:
            try:
                self.rst.recv()
                self.rst_dropped += 1
            except Exception:
                return

    def run(self):
        if not self.w:
            return
        while True:
            try:
                p = self.w.recv()
            except Exception:
                return
            try:
                pl = p.payload
                sni = extract_sni(pl) if pl and len(pl) > 5 and pl[0] == 0x16 else None
                if sni:
                    send_variant(self.w, p, sni, self.v)
                    self.count += 1
                    continue
                self.w.send(p)
            except Exception:
                try:
                    self.w.send(p)
                except Exception:
                    pass

    def shutdown(self):
        for h in (self.w, self.rst):
            if h:
                try:
                    h.close()
                except Exception:
                    pass
        self.join(timeout=4)


def V(splits=(), reverse=True, decoy=None, rstdrop=False, ttl=FAKE_TTL,
      repeats=1, fake_last=False, seqovl=0):
    return dict(splits=list(splits), reverse=reverse, decoy=decoy,
                rstdrop=rstdrop, ttl=ttl, repeats=repeats,
                fake_last=fake_last, seqovl=seqovl)


# (gorunen ad, strateji, settings.json karsiligi veya None)
# Karsiligi None olan varyantlar uygulamada henuz ayarla secilemez — kazanan
# onlardan biri cikarsa yapilacak sey raporu gonderip yeni surum beklemek.
VARIANTS = [
    ("motor kapali (referans)", None, None),
    # --- uygulamada bugun secilebilen ayarlar ------------------------
    ("record  (simdiki varsayilan)", V((1,), True, "badseq+badsum"),
     {"split_mode": "record"}),
    ("record+sni", V((1, "snimid"), True, "badseq+badsum"),
     {"split_mode": "record+sni"}),
    # --- sahte paketi DPI'in GORDUGU bicimde gonderen varyantlar -----
    # Dogru seq + bozuk saglama: birlestiren DPI'in tamponuna sahte SNI girer.
    ("bolme yok + yalniz badsum", V((), True, "badsum"), None),
    ("record + yalniz badsum", V((1,), True, "badsum"),
     {"split_mode": "record", "decoy_mode": "badsum"}),
    ("record + yalniz badsum + 6 tekrar", V((1,), True, "badsum", repeats=6), None),
    ("bolme yok + badsum + 6 tekrar", V((), True, "badsum", repeats=6), None),
    ("record + badsum + sahte sonda", V((1,), True, "badsum", fake_last=True), None),
    ("record + badsum TTL=2", V((1,), True, "badsum", ttl=2), None),
    ("record + badsum TTL=4", V((1,), True, "badsum", ttl=4), None),
    ("record + badsum TTL=8", V((1,), True, "badsum", ttl=8), None),
    # --- ustuste binen segment: birlestiren DPI'a karsi asil silah ---
    ("seqovl 8 + record", V((1,), False, None, seqovl=8), None),
    ("seqovl 24 + bolme yok", V((), False, None, seqovl=24), None),
    ("seqovl 8 + record + badsum", V((1,), False, "badsum", seqovl=8), None),
    ("seqovl 64 + record", V((1,), False, None, seqovl=64), None),
    # --- cok noktali dagitim ----------------------------------------
    ("multidisorder 1+snimid+sniend", V((1, "snimid", "sniend"), True,
                                        "badseq+badsum"), None),
    ("snistart kesme + badsum", V(("snistart",), True, "badsum"), None),
    ("yalniz RST dusurme", V((), True, None, True),
     {"rst_drop_enabled": True}),
]


def tls(ip, sni):
    t0 = time.time()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), 8) as s:
            with ctx.wrap_socket(s, server_hostname=sni):
                return True, "ACILDI  %4dms" % ((time.time() - t0) * 1000)
    except Exception as e:
        name = {"ConnectionResetError": "RST (engel)",
                "TimeoutError": "zaman asimi",
                "socket.timeout": "zaman asimi"}.get(type(e).__name__, type(e).__name__)
        return False, "kapali  %4dms  %s" % ((time.time() - t0) * 1000, name)


def main():
    out("HenkerDPI teshis raporu")
    out("=" * 60)
    out(time.strftime("%Y-%m-%d %H:%M:%S"))
    out()

    # --- ag durumu -------------------------------------------------
    out("AG DURUMU")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 53))
        out("  yerel IP            : %s" % s.getsockname()[0])
        s.close()
    except Exception as e:
        out("  yerel IP            : okunamadi (%s)" % e)

    ips = {}
    for host in TARGETS + CONTROL:
        try:
            sysip = socket.gethostbyname(host)
        except Exception:
            sysip = None
        try:
            plainip = dns_query(host, RESOLVER)
        except Exception:
            plainip = None
        dohip = dns_query_doh(host)
        # Engel sayfasinin adresine baglanip "acildi" demek olcumu bozar, o
        # yuzden bilinen engel adresleri elenir; DoH once gelir cunku duz 53'u
        # kesen ISP'de tek guvenilir kaynak odur.
        ips[host] = next((ip for ip in (dohip, plainip, sysip)
                          if ip and ip not in BLOCK_IPS), None)
        if host == "discord.com":
            out("  sistem DNS  discord : %s%s" % (sysip, "   <-- ENGEL SAYFASI"
                                                  if sysip in BLOCK_IPS else ""))
            out("  duz 53 @%-4s discord: %s%s" % (RESOLVER, plainip,
                                                  "   <-- DUZ DNS KACIRILIYOR"
                                                  if plainip is None or plainip in BLOCK_IPS
                                                  else ""))
            out("  DoH (HTTPS) discord : %s%s" % (dohip, "   <-- DoH CALISMIYOR"
                                                  if dohip is None else "   <-- OLCUMDE BU KULLANILIYOR"))
    missing = [h for h, ip in ips.items() if not ip]
    if missing:
        out("  cozulemedi          : %s" % ", ".join(missing))
    out()
    out("  Not: asagidaki testler DNS'i devre disi birakir; hedeflere IP ile")
    out("       baglanilip alan adi elle bildirilir. Yani sonuclar yalnizca")
    out("       DPI engelini olcer, DNS yonlendirmesini degil.")
    out()

    # --- stratejiler -----------------------------------------------
    out("STRATEJILER")
    out("%-38s %-13s %-13s %s" % ("", "discord", "gateway", "kontrol(google)"))
    winners = []
    for name, v, recipe in VARIANTS:
        eng = None
        if v is not None:
            try:
                eng = Engine(v)
                eng.start()
                time.sleep(0.7)
            except Exception as e:
                out("%-38s BASLATILAMADI: %s" % (name, e))
                continue
        res = {}
        for host in ("discord.com", "gateway.discord.gg", "www.google.com"):
            ip = ips.get(host)
            res[host] = (False, "IP yok") if not ip else tls(ip, host)
        if eng:
            eng.shutdown()
        ok_t = res["discord.com"][0] and res["gateway.discord.gg"][0]
        ok_c = res["www.google.com"][0]
        if v is not None and ok_t and ok_c:
            winners.append((name, recipe))
        out("%-38s %-13s %-13s %s%s" % (
            name,
            res["discord.com"][1].split()[0],
            res["gateway.discord.gg"][1].split()[0],
            res["www.google.com"][1].split()[0],
            "   <== CALISTI" if (v is not None and ok_t and ok_c) else ""))
        time.sleep(0.4)

    out()
    out("SONUC")
    if not winners:
        out("  Hicbir strateji tutmadi.")
        out("  Bu, engelin SNI'ye degil IP'ye/DNS'e dayandigina ya da araya bir")
        out("  proxy/guvenlik duvari girdigine isaret eder. Raporu gonder.")
    else:
        out("  Calisan strateji(ler): %s" % ", ".join(n for n, _ in winners))
        applicable = [(n, r) for n, r in winners if r]
        if not applicable:
            out("  Ancak bunlarin hicbiri uygulamada ayarla secilemiyor.")
            out("  Raporu gonder; bu strateji icin yeni bir surum cikarilmasi gerek.")
        else:
            name, recipe = applicable[0]
            out()
            out("  2.7.0 ve sonrasinda bunu ELLE YAPMANA GEREK YOK: uygulama")
            out("  ayni olcumu kendisi yapar ve calisan stratejiyi kendisi secer.")
            out("  Uygulama yanlis secmis gorunuyorsa once sunu dene: uygulamayi")
            out("  kapat, %LOCALAPPDATA%\\HenkerDPI\\autotune.json dosyasini sil,")
            out("  tekrar ac — hatti bastan olcer.")
            out()
            out("  Yine de elle sabitlemek istersen settings.json icinde:")
            out('     "strategy_mode": "manual"')
            for k, val in recipe.items():
                out('     "%s": %s' % (k, str(val).lower()
                                       if isinstance(val, bool) else '"%s"' % val))
            out("  Kaydet, uygulamayi tamamen kapat, yeniden ac. (\"%s\")" % name)
    out()
    out("Bu raporu oldugu gibi gonderebilirsin; kisisel veri icermez")
    out("(yerel IP disinda ag adresi, hesap veya gezinme gecmisi yok).")


def henkerdpi_running():
    """Calisan HenkerDPI'yi tek-ornek mutex'inden anla.

    Uygulamanin motoru acikken bu araci calistirmak sonuclari gecersiz kilar:
    iki WinDivert tuketicisi ayni ClientHello'lar icin yarisir ve hangi
    stratejinin olculdugu belirsizlesir.
    """
    for name in ("Global\\HenkerDPI_SingleInstance",
                 "Global\\HenkerDPI_V2_SingleInstance"):
        h = ctypes.windll.kernel32.OpenMutexW(0x00100000, False, name)  # SYNCHRONIZE
        if h:
            ctypes.windll.kernel32.CloseHandle(h)
            return True
    return False


if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Bu araci YONETICI olarak calistir.")
        input("Kapatmak icin Enter...")
        sys.exit(1)

    if henkerdpi_running():
        print("HenkerDPI su anda ACIK.")
        print()
        print("Bu arac olcum yapiyor; uygulama acikken onun motoru da ayni")
        print("paketlere karisir ve sonuclar anlamsiz cikar.")
        print()
        print("HenkerDPI'yi tamamen kapat (bildirim alanindaki simgeye sag tik ->")
        print("Cikis), sonra bu araci tekrar calistir.")
        input("\nKapatmak icin Enter...")
        sys.exit(1)
    try:
        main()
    except Exception as e:
        out("")
        out("BEKLENMEYEN HATA: %r" % (e,))

    desktop = os.path.join(os.environ.get("USERPROFILE", "."), "Desktop")
    if not os.path.isdir(desktop):
        desktop = os.environ.get("USERPROFILE", ".")
    path = os.path.join(desktop, "HenkerDPI-Teshis-Sonuc.txt")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\r\n".join(report))
        print("\nRapor kaydedildi: %s" % path)
    except Exception as e:
        print("\nRapor yazilamadi: %s" % e)
    input("\nKapatmak icin Enter...")
