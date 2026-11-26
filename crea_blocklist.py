#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crea_blocklist.py - genera una blocklist personale per Pi-hole, verificata via DNS.

Passi: 1) sorgenti (incorporate sotto)  2) download e verifica delle liste
3) normalizzazione  4) deduplica  5) allowlist  6) verifica DNS su resolver
pubblici (query UDP dirette, MAI tramite Pi-hole)  7) file finali + report.

Solo libreria standard Python (>= 3.8). Nessuna dipendenza da installare.

Uso tipico (su DietPi o qualunque Linux/macOS):
    python3 crea_blocklist.py                  # chiede conferma prima del DNS
    nohup python3 crea_blocklist.py --yes > log.txt 2>&1 &    # in background
Se si interrompe, rilancialo con --riusa-download: riprende il controllo DNS
da dove era arrivato (lo stato è salvato in lavoro/stato_dns.tsv).

Non modifica in alcun modo Pi-hole: scrive solo file nella cartella di output.
"""

import argparse
import asyncio
import datetime as _dt
import hashlib
import os
import random
import re
import socket
import struct
import sys
import time
import urllib.error
import urllib.request

# --------------------------------------------------------------------------
# 1) SORGENTI - ricavate dal tuo export Teleporter (gravity.db, 73 adlist tutte
#    abilitate), tolti i doppioni. Le escluse sono elencate più sotto.
# --------------------------------------------------------------------------
GH = "https://raw.githubusercontent.com/"
HM = GH + "hectorm/hmirror/master/data/"
SORGENTI = [
    GH + "andyts93/pihole-italian-list/master/adlist.txt",
    "https://adaway.org/hosts.txt",
    "https://v.firebog.net/hosts/AdguardDNS.txt",
    "https://v.firebog.net/hosts/Admiral.txt",
    GH + "anudeepND/blacklist/master/adservers.txt",
    "https://v.firebog.net/hosts/Easylist.txt",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    GH + "FadeMind/hosts.extras/master/UncheckyAds/hosts",
    "https://v.firebog.net/hosts/Easyprivacy.txt",
    "https://v.firebog.net/hosts/Prigent-Ads.txt",
    GH + "FadeMind/hosts.extras/master/add.2o7Net/hosts",
    GH + "crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
    "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
    GH + "FadeMind/hosts.extras/master/add.Spam/hosts",
    "https://big.oisd.nl",
    GH + "DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
    "https://v.firebog.net/hosts/static/w3kbl.txt",
    GH + "PolishFiltersTeam/KADhosts/master/KADomains.txt",
    GH + "Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt",
    "http://sysctl.org/cameleon/hosts",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
    "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt",
    "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt",
    "https://gist.githubusercontent.com/BBcan177/4a8bf37c131be4803cb2/raw/343ff780e15205b4dd0de37c86af34cfb26b2fbe/MS-2",
    "https://gist.githubusercontent.com/BBcan177/b6df57cef74e28d90acf1eec93d62d3b/raw/f0996cf5248657ada2adb396f3636be8716b99eb/MS-4",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    GH + "deathbybandaid/piholeparser/master/Subscribable-Lists/ParsedBlacklists/AakList.txt",
    GH + "deathbybandaid/piholeparser/master/Subscribable-Lists/ParsedBlacklists/Prebake-Obtrusive.txt",
    HM + "adblock-nocoin-list/list.txt",
    HM + "adguard-simplified/list.txt",
    HM + "disconnect.me-malvertising/list.txt",
    HM + "disconnect.me-malware/list.txt",
    HM + "eth-phishing-detect/list.txt",
    HM + "fademind-add.dead/list.txt",
    HM + "fademind-add.risk/list.txt",
    HM + "malwaredomainlist.com/list.txt",
    HM + "malwaredomains.com-immortaldomains/list.txt",
    HM + "malwaredomains.com-justdomains/list.txt",
    HM + "matomo.org-spammers/list.txt",
    HM + "mitchellkrogza-badd-boyz-hosts/list.txt",
    HM + "ransomwaretracker.abuse.ch/list.txt",
    HM + "someonewhocares.org/list.txt",
    HM + "spam404.com/list.txt",
    HM + "winhelp2002.mvps.org/list.txt",
    HM + "zerodot1-coinblockerlists-browser/list.txt",
    "https://www.stopforumspam.com/downloads/toxic_domains_whole.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
    GH + "Perflyst/PiHoleBlocklist/master/SmartTV.txt",
    # --- porno: le due più note e mantenute ---
    GH + "StevenBlack/hosts/master/alternates/porn/hosts",   # include StevenBlack base + Sinfonietta
    GH + "chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_all.list",
]

# Escluse perché doppioni (misurati il 2026-11-25) o superate:
#  StevenBlack/hosts (base)        -> contenuta al 100% in StevenBlack porn
#  hmirror/stevenblack             -> 94% in StevenBlack base
#  hmirror/adaway.org, anudeepnd-adservers, disconnect.me-ad/-tracking,
#  easylist, easyprivacy, fademind-add.2o7net, fademind-add.spam, kadhosts,
#  pgl.yoyo.org                    -> copie di liste originali già presenti
#  hagezi hosts/pro.txt (404), dnsmasq/, wildcard/, wildcard-onlydomains/, rpz/
#                                  -> stessa lista Pro di adblock/pro.txt
#  smokingwheels allhosts          -> aggregatore di altre liste
#  Sinfonietta pornography-hosts   -> contenuta al 100% in StevenBlack porn
#  mhxion/pornaway                 -> ferma al 2018
#  mhhakim list.txt / porn.txt     -> ferme a marzo 2023

# 5) ALLOWLIST esatta dal tuo export (domainlist type=0, abilitate)
ALLOWLIST = {
    "fpt.live.com",
    "static.cdninstagram.com",
    "scontent-mxp1-1.cdninstagram.com",
    "it.linkedin.com",
}

UA = "Mozilla/5.0 (X11; Linux x86_64) crea_blocklist/1.0"

# --------------------------------------------------------------------------
# 2) DOWNLOAD
# --------------------------------------------------------------------------
def scarica(url, dest, timeout=30, tentativi=2):
    """Restituisce (ok, motivo). Scrive il contenuto in dest."""
    ultimo = ""
    for t in range(1, tentativi + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                ctype = (r.headers.get("Content-Type") or "").lower()
                finale = r.geturl()
                dati = r.read()
            testa = dati[:2048].lstrip().lower()
            if "text/html" in ctype or testa.startswith(b"<!doctype html") or testa.startswith(b"<html"):
                rid = " (redirect a %s)" % finale if finale != url else ""
                return False, "pagina HTML%s" % rid
            with open(dest, "wb") as f:
                f.write(dati)
            if not dati.strip():
                return False, "vuota"
            return True, "OK"
        except urllib.error.HTTPError as e:
            return False, "HTTP %d" % e.code          # 4xx/5xx: niente retry
        except (socket.timeout, TimeoutError) as e:
            ultimo = "timeout"
        except urllib.error.URLError as e:
            r = e.reason
            if isinstance(r, (socket.timeout, TimeoutError)):
                ultimo = "timeout"
            else:
                ultimo = "errore di rete: %s" % r
                if t == tentativi:
                    break
        except Exception as e:                     # connessione chiusa, ecc.
            ultimo = "errore: %s" % e
        time.sleep(2)
    if ultimo == "timeout":
        return False, "timeout dopo %d tentativi" % tentativi
    return False, ultimo

# --------------------------------------------------------------------------
# 3) NORMALIZZAZIONE
# --------------------------------------------------------------------------
RE_IP = re.compile(r"^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:.]*)$", re.I)
RE_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
NON_DOMINI = {"localhost", "localhost.localdomain", "local", "broadcasthost",
              "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
              "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0"}


def valido_rfc1035(d):
    """Hostname secondo RFC 1035/1123: etichette 1-63 car. [a-z0-9-], senza
    trattino iniziale/finale, totale <= 253, almeno 2 etichette, TLD non numerico."""
    if not d or len(d) > 253:
        return False
    parti = d.split(".")
    if len(parti) < 2:
        return False
    if not all(RE_LABEL.match(p) for p in parti):
        return False
    if parti[-1].isdigit():
        return False
    return True


def a_punycode(d):
    if d.isascii():
        return d
    try:
        return d.encode("idna").decode("ascii").lower()
    except Exception:
        return None


def estrai(riga):
    """Restituisce la lista di domini candidati di una riga ([] se nessuno)
    oppure None se la riga è una regola non supportata (regex/wildcard/ecc.)."""
    s = riga.strip()
    if not s or s[0] in "#!;" or s.startswith("[") :
        return []
    # commenti in coda (hosts) - non toccare '#' dentro regole adblock tipo ##
    if "#" in s and not s.startswith("||"):
        s = s.split("#", 1)[0].strip()
        if not s:
            return []
    s = s.lower()
    if s.startswith("@@"):                     # eccezioni adblock
        return None
    if s.startswith("||"):                     # formato Adblock ||dominio^
        m = re.match(r"^\|\|([^\^/$*|]+)\^(\$important)?$", s)
        return [m.group(1)] if m else None
    if s.startswith("/") or any(c in s for c in "*^|$?()[]\\"):
        return None                            # regex / wildcard / filtri cosmetici
    parti = s.split()
    if RE_IP.match(parti[0]):                  # formato hosts: IP dominio [dominio...]
        return parti[1:]
    if len(parti) == 1:
        return parti
    return None


def normalizza(dom):
    d = dom.strip().rstrip(".")
    if not d or d in NON_DOMINI or RE_IP.match(d):
        return None
    d = a_punycode(d)
    if d is None or d in NON_DOMINI:
        return None
    return d if valido_rfc1035(d) else None


def analizza_file(percorso):
    """Restituisce (set_domini, righe_scartate)."""
    domini, scarti = set(), 0
    with open(percorso, "r", encoding="utf-8", errors="replace") as f:
        for riga in f:
            cand = estrai(riga)
            if cand is None:
                scarti += 1
                continue
            for c in cand:
                n = normalizza(c)
                if n:
                    domini.add(n)
                else:
                    scarti += 1
    return domini, scarti

# --------------------------------------------------------------------------
# 6) DNS - client UDP minimale, asincrono, con limite di velocità
# --------------------------------------------------------------------------
NOERROR, SERVFAIL, NXDOMAIN, REFUSED = 0, 2, 3, 5
T_A, T_AAAA, T_CNAME = 1, 28, 5


def costruisci_query(qid, nome, qtype):
    head = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1)        # RD, 1 domanda, 1 OPT
    q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in nome.split(".")) + b"\x00"
    opt = b"\x00" + struct.pack(">HHIH", 41, 1232, 0, 0)           # EDNS0, 1232 byte
    return head + q + struct.pack(">HH", qtype, 1) + opt


def _salta_nome(buf, i):
    while True:
        l = buf[i]
        if l == 0:
            return i + 1
        if l & 0xC0 == 0xC0:
            return i + 2
        i += 1 + l


def _leggi_nome(buf, i):
    parti, salti = [], 0
    while True:
        l = buf[i]
        if l == 0:
            break
        if l & 0xC0 == 0xC0:
            i = ((l & 0x3F) << 8) | buf[i + 1]
            salti += 1
            if salti > 20:
                raise ValueError("loop")
            continue
        parti.append(buf[i + 1:i + 1 + l].decode("ascii", "replace"))
        i += 1 + l
    return ".".join(parti).lower()


def analizza_risposta(buf):
    """-> (qid, nome_domanda, rcode, n_record_A/AAAA/CNAME, ip_A)"""
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", buf[:12])
    rcode = flags & 0x0F
    i = 12
    nome = _leggi_nome(buf, i) if qd else ""
    for _ in range(qd):
        i = _salta_nome(buf, i) + 4
    utili, ips = 0, []
    for _ in range(an):
        i = _salta_nome(buf, i)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", buf[i:i + 10])
        i += 10
        if rtype in (T_A, T_AAAA, T_CNAME):
            utili += 1
        if rtype == T_A and rdlen == 4:
            ips.append(socket.inet_ntoa(buf[i:i + 4]))
        i += rdlen
    return qid, nome, rcode, utili, ips


class LimitatoreVelocita:
    def __init__(self, qps):
        self.intervallo = 1.0 / qps
        self.prossimo = 0.0
        self.lock = asyncio.Lock()

    async def attendi(self):
        async with self.lock:
            ora = time.monotonic()
            if self.prossimo > ora:
                await asyncio.sleep(self.prossimo - ora)
                ora = self.prossimo
            self.prossimo = max(ora, self.prossimo) + self.intervallo


class ClientDNS(asyncio.DatagramProtocol):
    def __init__(self, server, limitatore, timeout):
        self.server = server
        self.lim = limitatore
        self.timeout = timeout
        self.in_volo = {}
        self.transport = None

    @classmethod
    async def crea(cls, server, limitatore, timeout):
        loop = asyncio.get_running_loop()
        fam = socket.AF_INET6 if ":" in server else socket.AF_INET
        _, proto = await loop.create_datagram_endpoint(
            lambda: cls(server, limitatore, timeout), remote_addr=(server, 53), family=fam)
        return proto

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            qid, nome, rcode, utili, ips = analizza_risposta(data)
        except Exception:
            return
        voce = self.in_volo.get(qid)
        if voce and voce[1] == nome and not voce[0].done():
            voce[0].set_result((rcode, utili, ips))

    def error_received(self, exc):
        pass

    async def chiedi(self, nome, qtype):
        """-> (rcode, n_record_utili, ip) oppure ('TIMEOUT', 0, [])"""
        await self.lim.attendi()
        loop = asyncio.get_running_loop()
        qid = random.randint(0, 65535)
        while qid in self.in_volo:
            qid = random.randint(0, 65535)
        fut = loop.create_future()
        self.in_volo[qid] = (fut, nome)
        try:
            self.transport.sendto(costruisci_query(qid, nome, qtype))
            return await asyncio.wait_for(fut, self.timeout)
        except asyncio.TimeoutError:
            return ("TIMEOUT", 0, [])
        finally:
            self.in_volo.pop(qid, None)


async def esito_su_resolver(client, dominio, tentativi=3):
    """'attivo' | 'nx' | 'nodata' | 'incerto' su un singolo resolver."""
    for _ in range(tentativi):
        rcode, utili, _ = await client.chiedi(dominio, T_A)
        if rcode == NOERROR:
            if utili:
                return "attivo"
            rcode6, utili6, _ = await client.chiedi(dominio, T_AAAA)
            if rcode6 == NOERROR and utili6:
                return "attivo"
            if rcode6 == NOERROR:
                return "nodata"
            continue                   # risposta AAAA anomala: riprova
        if rcode == NXDOMAIN:
            return "nx"
        # SERVFAIL, REFUSED, TIMEOUT, altro -> riprova
    return "incerto"


async def classifica(clients, dominio):
    """Primo resolver; se non è 'attivo' interroga il secondo.
    attivo su uno qualsiasi -> attivo; NXDOMAIN su entrambi -> morto;
    NOERROR senza record (e nessun NX) -> nodata; altrimenti incerto."""
    e1 = await esito_su_resolver(clients[0], dominio)
    if e1 == "attivo":
        return "attivo"
    e2 = await esito_su_resolver(clients[1], dominio)
    if e2 == "attivo":
        return "attivo"
    if e1 == "nx" and e2 == "nx":
        return "morto"
    if e1 == "nodata" and e2 == "nodata":
        return "nodata"
    return "incerto"


async def prova_resolver(clients):
    """Controllo preliminare: rileva DNS intercettato (router, Pi-hole, proxy)."""
    problemi = []
    for c in clients:
        e = await esito_su_resolver(c, "google.com")
        if e != "attivo":
            problemi.append("%s: google.com -> %s (atteso: attivo)" % (c.server, e))
        e = await esito_su_resolver(c, "nonesiste-%d-verifica.com" % random.randint(10**8, 10**9))
        if e != "nx":
            problemi.append("%s: dominio inesistente -> %s (atteso: NXDOMAIN)" % (c.server, e))
        _, _, ips = await c.chiedi("doubleclick.net", T_A)
        if ips and all(ip in ("0.0.0.0", "127.0.0.1") for ip in ips):
            problemi.append("%s: doubleclick.net -> %s: le query passano da un blocco DNS "
                            "(Pi-hole o router)" % (c.server, ips[0]))
    return problemi


async def verifica_dns(domini, resolver, qps, concorrenza, timeout, file_stato):
    gia = {}
    if os.path.exists(file_stato):
        with open(file_stato, encoding="utf-8") as f:
            for r in f:
                p = r.rstrip("\n").split("\t")
                if len(p) == 2:
                    gia[p[0]] = p[1]
    lim = LimitatoreVelocita(qps)
    clients = [await ClientDNS.crea(s, lim, timeout) for s in resolver]

    problemi = await prova_resolver(clients)
    if problemi:
        print("\nERRORE: i resolver non rispondono in modo affidabile da questa rete:")
        for p in problemi:
            print("  -", p)
        print("Il controllo DNS falserebbe i risultati: interrotto.")
        sys.exit(2)
    print("Controllo preliminare resolver: OK (%s)" % ", ".join(resolver))

    risultati = {d: gia[d] for d in domini if d in gia}
    da_fare = [d for d in domini if d not in gia]
    print("Domini già verificati in un'esecuzione precedente: %d; da verificare: %d"
          % (len(risultati), len(da_fare)))

    coda = asyncio.Queue(maxsize=concorrenza * 4)
    out = open(file_stato, "a", encoding="utf-8")
    cont = {"attivo": 0, "morto": 0, "incerto": 0, "nodata": 0}
    fatti, t0 = 0, time.monotonic()

    async def produttore():
        for d in da_fare:
            await coda.put(d)
        for _ in range(concorrenza):
            await coda.put(None)

    async def lavoratore():
        nonlocal fatti
        while True:
            d = await coda.get()
            if d is None:
                return
            esito = await classifica(clients, d)
            risultati[d] = esito
            cont[esito] += 1
            fatti += 1
            out.write("%s\t%s\n" % (d, esito))

    async def avanzamento():
        while True:
            await asyncio.sleep(30)
            out.flush()
            el = time.monotonic() - t0
            vel = fatti / el if el else 0
            rest = (len(da_fare) - fatti) / vel if vel else 0
            print("[%s] %d/%d  %.0f dom/s  ETA %s  attivi %d morti %d incerti %d senza-record %d"
                  % (time.strftime("%H:%M:%S"), fatti, len(da_fare), vel,
                     str(_dt.timedelta(seconds=int(rest))), cont["attivo"], cont["morto"],
                     cont["incerto"], cont["nodata"]), flush=True)

    mon = asyncio.ensure_future(avanzamento())
    await asyncio.gather(produttore(), *[lavoratore() for _ in range(concorrenza)])
    mon.cancel()
    out.close()
    for c in clients:
        c.transport.close()
    return risultati

# --------------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Genera blocklist-personale.txt verificata via DNS")
    ap.add_argument("--output", default=".", help="cartella di output (default: corrente)")
    ap.add_argument("--resolver", nargs=2, default=["1.1.1.1", "9.9.9.9"],
                    help="due resolver pubblici (default: 1.1.1.1 9.9.9.9)")
    ap.add_argument("--qps", type=float, default=200, help="query al secondo totali (default 200)")
    ap.add_argument("--concorrenza", type=int, default=400, help="domini in parallelo (default 400)")
    ap.add_argument("--timeout", type=float, default=2.5, help="timeout per query in s (default 2.5)")
    ap.add_argument("--riusa-download", action="store_true",
                    help="usa le liste già scaricate in lavoro/ (per riprendere un'esecuzione)")
    ap.add_argument("--yes", action="store_true", help="non chiedere conferma prima del controllo DNS")
    ap.add_argument("--solo-preparazione", action="store_true",
                    help="esegue i passi 1-5 e si ferma prima del DNS")
    a = ap.parse_args()

    os.makedirs(a.output, exist_ok=True)
    lavoro = os.path.join(a.output, "lavoro")
    os.makedirs(os.path.join(lavoro, "liste"), exist_ok=True)
    inizio = _dt.datetime.now().astimezone()

    # 2-3) download + normalizzazione
    print("== Download e normalizzazione di %d sorgenti" % len(SORGENTI))
    report, sorgenti_ok, tutti, grezzi = [], [], set(), 0
    for url in SORGENTI:
        dest = os.path.join(lavoro, "liste", hashlib.md5(url.encode()).hexdigest() + ".txt")
        stato_file = dest + ".stato"
        if a.riusa_download and os.path.exists(stato_file):
            ok, motivo = open(stato_file, encoding="utf-8").read().split("\t", 1)
            ok = ok == "1"
        else:
            ok, motivo = scarica(url, dest)
            with open(stato_file, "w", encoding="utf-8") as f:
                f.write("%d\t%s" % (ok, motivo))
        n, scarti = 0, 0
        if ok:
            dom, scarti = analizza_file(dest)
            n = len(dom)
            if n == 0:
                ok, motivo = False, "nessun dominio valido"
            else:
                tutti |= dom
                grezzi += n
                sorgenti_ok.append(url)
            del dom
        report.append((url, "OK" if ok else "scartata: " + motivo, n, scarti))
        print("  %-9s %8d  %s%s" % ("OK" if ok else "SCARTATA", n, url,
                                    "" if ok else "  (" + motivo + ")"), flush=True)

    # 4) deduplica
    dedup = len(tutti)

    # 5) allowlist
    in_allow = sorted(tutti & ALLOWLIST)
    tutti -= ALLOWLIST
    da_verificare = sorted(tutti)
    del tutti
    with open(os.path.join(lavoro, "domini_da_verificare.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(da_verificare) + "\n")

    print("\nDomini grezzi (somma per sorgente): %d" % grezzi)
    print("Dopo deduplica: %d" % dedup)
    print("Dopo allowlist: %d (tolti %d)" % (len(da_verificare), len(in_allow)))
    if a.solo_preparazione:
        return

    stima = len(da_verificare) / a.qps * 1.25
    print("\nStima controllo DNS a %.0f query/s: circa %s (dipende da quanti domini sono morti,"
          " che richiedono una seconda query)" % (a.qps, _dt.timedelta(seconds=int(stima))))
    if len(da_verificare) > 500000 and not a.yes:
        if input("Oltre 500.000 domini. Procedo con il controllo DNS? [s/N] ").strip().lower() not in ("s", "si", "sì", "y", "yes"):
            print("Interrotto. Rilancia con --riusa-download per non riscaricare le liste.")
            return

    # 6) DNS
    file_stato = os.path.join(lavoro, "stato_dns.tsv")
    t0 = time.monotonic()
    risultati = asyncio.run(verifica_dns(da_verificare, a.resolver, a.qps, a.concorrenza,
                                         a.timeout, file_stato))
    durata = time.monotonic() - t0
    fine = _dt.datetime.now().astimezone()

    attivi = [d for d in da_verificare if risultati.get(d) == "attivo"]
    c = {k: sum(1 for d in da_verificare if risultati.get(d) == k)
         for k in ("morto", "incerto", "nodata")}

    # 7) file finali
    data = fine.strftime("%Y-%m-%d %H:%M %Z")
    with open(os.path.join(a.output, "blocklist-personale.txt"), "w", encoding="utf-8") as f:
        f.write("# blocklist-personale.txt\n")
        f.write("# Generata: %s\n" % data)
        f.write("# Domini: %d (attivi via DNS su %s al momento del controllo)\n"
                % (len(attivi), " e ".join(a.resolver)))
        f.write("# Nota: fotografia di quell'istante; i domini possono morire o tornare attivi.\n")
        f.write("# Sorgenti usate (%d):\n" % len(sorgenti_ok))
        for u in sorgenti_ok:
            f.write("#   %s\n" % u)
        f.write("\n".join(attivi) + "\n")

    motivi = {"morto": "morto (NXDOMAIN su entrambi i resolver)",
              "incerto": "incerto (SERVFAIL/timeout o esiti discordanti dopo 3 tentativi)",
              "nodata": "nessun record (NOERROR senza A/AAAA/CNAME)"}
    with open(os.path.join(a.output, "scartati.txt"), "w", encoding="utf-8") as f:
        f.write("# scartati.txt - generato %s - formato: dominio<TAB>motivo\n" % data)
        for d in in_allow:
            f.write("%s\tin allowlist\n" % d)
        for d in da_verificare:
            e = risultati.get(d)
            if e in motivi:
                f.write("%s\t%s\n" % (d, motivi[e]))

    with open(os.path.join(a.output, "report.md"), "w", encoding="utf-8") as f:
        f.write("# Report blocklist personale\n\n")
        f.write("Generato: %s - controllo DNS durato %s su %s.\n\n"
                % (data, _dt.timedelta(seconds=int(durata)), " e ".join(a.resolver)))
        f.write("\"Funzionante\" = da sorgente raggiungibile e risolto via DNS al momento del "
                "controllo. È una fotografia di quell'istante.\n\n")
        f.write("| Sorgente (URL) | Stato | Domini estratti | Righe scartate |\n|---|---|---:|---:|\n")
        for url, st, n, sc in report:
            f.write("| %s | %s | %d | %d |\n" % (url, st, n, sc))
        f.write("\n## Totali\n\n| Fase | Domini |\n|---|---:|\n")
        f.write("| Grezzi (somma per sorgente) | %d |\n| Dopo deduplica | %d |\n"
                "| Dopo allowlist | %d |\n| **Attivi (finali)** | **%d** |\n| Morti | %d |\n"
                "| Incerti | %d |\n| Senza record (NOERROR vuoto) | %d |\n"
                % (grezzi, dedup, len(da_verificare), len(attivi), c["morto"], c["incerto"], c["nodata"]))
    print("\nFatto. Attivi: %d  morti: %d  incerti: %d  senza record: %d"
          % (len(attivi), c["morto"], c["incerto"], c["nodata"]))
    print("File: blocklist-personale.txt, scartati.txt, report.md in %s" % os.path.abspath(a.output))


if __name__ == "__main__":
    main()
