#!/usr/bin/env python3
"""
KeyHop / Jump VPN — fetch + build READY-to-use share links

Outputs (next to script):
  keyhop_uris_ready.txt   — working format (IP+sni+insecure for hy2, trojan ws, vless)
  keyhop_uris_all.txt     — raw decrypted (incl sn://)
  keyhop_uris_unique.txt  — unique raw
  keyhop_uris_clean.txt   — raw clean schemes only
  keyhop_uris.json        — per-server links
  keyhop_servers.json     — server metadata (premium flag etc.)

Keys from libhop-collections.so (XorString XOR 0x5A):
  r31 → /llc AES key
  r11 → pdvqs AES key
"""
from __future__ import annotations

import base64
import json
import re
import socket
import ssl
import struct
import sys
import urllib.parse
import urllib.request
import zlib
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlparse, parse_qs

# ── keys ───────────────────────────────────────────────────────────────
R31_KEY = base64.b64decode("M2EzOXM4N2cxcy01eWVsMmhyaTktMG80OWEzNm04YjI=")
R11_KEY = base64.b64decode("MmszMmUzN2kzOS01eWxmM2hjaTYtOW8yNmEzNmE4YjU=")
assert len(R31_KEY) == 32 and len(R11_KEY) == 32

HOPP_HOSTS = [
    "hopp-queen.roxa.org",
    "hello-tsmc-fromgrape.dynuddns.com",
    "grape-rich-lu.yyuyy.com",
]
FIRESTORE_BASE = (
    "https://firestore.googleapis.com/v1/projects/keyhop-x"
    "/databases/(default)/documents"
)
PDVQS_URL = f"{FIRESTORE_BASE}/pdvqs?pageSize=100"
PVCA_URL = f"{FIRESTORE_BASE}/pvca?pageSize=100"
UA = "okhttp/4.12.0"
OUT_DIR = Path(__file__).resolve().parent / "output"
OUT_DIR.mkdir(parents=True, exist_ok=True)

CLEAN_SCHEMES = (
    "hysteria2://", "hy2://", "trojan://", "vless://",
    "mieru://", "tuic://", "ss://", "ssr://", "vmess://",
)
VALID_SCHEMES = CLEAN_SCHEMES + ("sn://",)

# DNS cache
_dns: dict[str, str | None] = {}


def resolve_ip(host: str) -> str | None:
    if host in _dns:
        return _dns[host]
    # already IP?
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        _dns[host] = host
        return host
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        ip = sorted({x[4][0] for x in infos})[0]
        _dns[host] = ip
        return ip
    except Exception:
        _dns[host] = None
        return None


def http_get(url: str, timeout: int = 25) -> bytes:
    req = urllib.request.Request(
        url, headers={"User-Agent": UA, "Accept": "application/json"}
    )
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
        return resp.read()


def aes_cbc_decrypt(key: bytes, blob: bytes) -> bytes:
    if len(blob) < 32 or (len(blob) - 16) % 16 != 0:
        raise ValueError(f"bad blob length {len(blob)}")
    iv, ct = blob[:16], blob[16:]
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7

        c = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        plain = c.update(ct) + c.finalize()
        u = PKCS7(128).unpadder()
        return u.update(plain) + u.finalize()
    except ImportError:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad

        return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)


def try_aes_b64(key: bytes, b64: str) -> str | None:
    try:
        blob = base64.b64decode(b64)
        return aes_cbc_decrypt(key, blob).decode("utf-8")
    except Exception:
        return None


def fs_string(field: dict) -> str | None:
    return field.get("stringValue")


def fs_bool(field: dict) -> bool | None:
    return field.get("booleanValue")


def fs_all_strings(field: dict) -> list[str]:
    out: list[str] = []
    if "stringValue" in field:
        out.append(field["stringValue"])
    for v in field.get("arrayValue", {}).get("values", []) or []:
        if "stringValue" in v:
            out.append(v["stringValue"])
    return out


def is_share_uri(s: str) -> bool:
    s = s.strip()
    if not s or "\n" in s or "\r" in s:
        return False
    low = s.lower()
    if low.startswith(VALID_SCHEMES):
        return True
    if "://" in s and s.split("://", 1)[0].isalnum() and len(s) > 12:
        return True
    return False


# ── sn:// binary helpers ───────────────────────────────────────────────

def read_hb_string(data: bytes, i: int) -> tuple[str, int]:
    """High-bit-terminated string (last byte has bit7 set)."""
    chars: list[str] = []
    while i < len(data):
        b = data[i]
        i += 1
        if b & 0x80:
            chars.append(chr(b & 0x7F))
            break
        chars.append(chr(b))
    return "".join(chars), i


def sn_decompress(uri: str) -> tuple[str, bytes] | None:
    if not uri.startswith("sn://"):
        return None
    rest = uri[5:]
    if "?" not in rest:
        return None
    typ, payload = rest.split("?", 1)
    for pad in ("", "=", "==", "==="):
        try:
            raw = zlib.decompress(base64.urlsafe_b64decode(payload + pad))
            return typ, raw
        except Exception:
            continue
    return None


def extract_hb_strings(raw: bytes) -> list[str]:
    """Extract all high-bit-terminated strings from buffer."""
    out: list[str] = []
    i = 0
    while i < len(raw):
        # start of printable run
        if raw[i] < 0x80 and (chr(raw[i]).isalnum() or raw[i] in (ord("."), ord("-"), ord("/"), ord("_"), ord(":"), ord("#"))):
            s, i = read_hb_string(raw, i)
            if len(s) >= 3:
                out.append(s)
            continue
        i += 1
    return out


def parse_sn_trojan(raw: bytes) -> dict[str, Any] | None:
    """
    Layout (observed):
      u32 type?=2
      u32 addr_type?=4
      host (hb-string)
      port u32 LE
      path '/ws'
      'tls' + sni
      ECH block
      password
    """
    if len(raw) < 20:
        return None

    i = 8  # skip two leading u32
    if i < len(raw) and raw[i] >= 0x80:
        i += 1
    host, i = read_hb_string(raw, i)
    host = host.strip("\x00").strip()

    port = 750
    if i + 4 <= len(raw):
        p = struct.unpack_from("<I", raw, i)[0]
        if 1 <= p <= 65535:
            port = p
            i += 4
        else:
            for off in range(1, 6):
                if i + off + 4 <= len(raw):
                    p = struct.unpack_from("<I", raw, i + off)[0]
                    if 1 <= p <= 65535:
                        port = p
                        break

    hb = extract_hb_strings(raw)
    # also recover strings where last byte was high-bit (already handled by hb)
    path = "/ws"
    for s in hb:
        if s.startswith("/") and len(s) < 40:
            path = s
            break

    sni = host
    domains = [s for s in hb if "." in s and " " not in s and "BEGIN" not in s and not s.startswith("/")]
    if domains:
        # prefer exact host match or longest domain
        for d in domains:
            if d == host:
                sni = d
                break
        else:
            sni = max(domains, key=len)

    if not host or "." not in host:
        if domains:
            host = max(domains, key=len)
            sni = host

    # Password ends with a high-bit terminator byte: recover last char via & 0x7F
    # KeyHop passwords always contain '_' (e.g. Pak0wretg_M9CnEF_...)
    def _ok_pass(cand: str) -> bool:
        if "_" not in cand:
            return False
        if cand.startswith(("AQAB", "BEGIN", "AE7", "AFT", "AFn", "DQB", "DQB")):
            return False
        if len(cand) < 16 or len(cand) > 48:
            return False
        return True

    password = ""
    for m in re.finditer(rb"([A-Za-z0-9_]{15,47})([\x80-\xff])", raw):
        last = chr(m.group(2)[0] & 0x7F)
        if not (last.isalnum() or last == "_"):
            continue
        cand = m.group(1).decode("ascii") + last
        if not _ok_pass(cand):
            continue
        if len(cand) > len(password):
            password = cand
    # fallback: password glued after ECH text inside hb strings
    if not password:
        for s in hb:
            for m in re.finditer(r"([A-Za-z0-9_]{16,48})", s):
                cand = m.group(1)
                if not _ok_pass(cand):
                    continue
                if len(cand) > len(password):
                    password = cand

    # clean host of trailing junk (e.g. dynuddns.comn)
    host = re.split(r"[\x00-\x1f]", host, maxsplit=1)[0].strip()
    host = re.sub(r"[^A-Za-z0-9.\-]+$", "", host)
    host = re.sub(r"\.(com)n$", r".\1", host)
    host = re.sub(r"\.(org)g$", r".\1", host)
    host = re.sub(r"\.(net)t$", r".\1", host)
    sni = re.split(r"[\x00-\x1f]", sni or "", maxsplit=1)[0].strip()
    sni = re.sub(r"[^A-Za-z0-9.\-]+$", "", sni)
    sni = re.sub(r"\.(com)n$", r".\1", sni)
    sni = re.sub(r"\.(org)g$", r".\1", sni)
    sni = re.sub(r"\.(net)t$", r".\1", sni)
    if not sni or "." not in sni:
        sni = host

    if not host or not password:
        return None
    return {
        "host": host,
        "port": port,
        "password": password,
        "path": path,
        "sni": sni,
        "tls": any(s == "tls" for s in hb),
    }


def parse_sn_vmess_vless(raw: bytes) -> dict[str, Any] | None:
    """VLESS httpupgrade from sn://vmess payload."""
    i = 0
    # optional leading u32
    if len(raw) >= 4:
        i = 4
    host, i = read_hb_string(raw, i)
    host = host.strip()
    port = 443
    if i + 4 <= len(raw):
        p = struct.unpack_from("<I", raw, i)[0]
        if 1 <= p <= 65535:
            port = p

    strings = re.findall(rb"[\x20-\x7e]{3,}", raw)
    decoded = [s.decode("utf-8", errors="ignore") for s in strings]

    uuid = ""
    for s in decoded:
        m = re.search(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            s,
        )
        if m:
            uuid = m.group(0)
            break

    hb = extract_hb_strings(raw)
    path = "/api/v1"
    for s in hb:
        if s.startswith("/api"):
            path = s
            break
    # if truncated /api/v → /api/v1
    if path in ("/api/v", "/api/"):
        path = "/api/v1"

    network = "httpupgrade"
    for s in hb:
        low = s.lower()
        if "httpupgrade" in low:
            network = "httpupgrade"
            break
        if low == "ws":
            network = "ws"

    alpn = "http/1.1"
    fp = "chrome"
    for s in hb:
        if s in ("chrome", "firefox", "safari", "ios", "android", "random"):
            fp = s
        if s.startswith("http/"):
            alpn = s

    if not host or not uuid:
        return None
    return {
        "host": host,
        "port": port,
        "uuid": uuid,
        "path": path,
        "network": network,
        "sni": host,
        "alpn": alpn,
        "fp": fp,
    }


# ── normalize to READY URIs ────────────────────────────────────────────

def ready_hy2(uri: str) -> list[str]:
    """hy2/hysteria2 → IP + insecure=1 + sni (+ port range from mport)."""
    out: list[str] = []
    try:
        # support both schemes
        scheme, rest = uri.split("://", 1)
        if "@" not in rest:
            return out
        password, hostpart = rest.split("@", 1)
        # host:port/?query or host:port-port/?query
        path_q = ""
        if "/" in hostpart:
            hostport, path_q = hostpart.split("/", 1)
            path_q = "/" + path_q
        else:
            hostport = hostpart

        query = ""
        if "?" in path_q:
            path_only, query = path_q.split("?", 1)
        elif "?" in hostport:
            hostport, query = hostport.split("?", 1)
            path_only = ""
        else:
            path_only = path_q if path_q not in ("/", "") else ""

        params = {}
        if query:
            for part in query.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    params[k] = unquote(v)

        # port may be range already
        if ":" not in hostport:
            return out
        host, port = hostport.rsplit(":", 1)
        mport = params.pop("mport", None)
        if mport and "-" in mport and "-" not in port:
            port = mport  # 9443-9543

        sni = params.get("sni") or host
        ip = resolve_ip(host) or host

        q = f"insecure=1&sni={quote(sni)}"
        # keep other useful params except mport
        for k, v in params.items():
            if k in ("insecure", "sni", "mport"):
                continue
            q += f"&{k}={quote(v)}"

        out.append(f"hysteria2://{password}@{ip}:{port}/?{q}")
        # also hostname variant
        if ip != host:
            out.append(f"hysteria2://{password}@{host}:{port}/?{q}")
    except Exception:
        pass
    return out


def ready_trojan_direct(uri: str) -> list[str]:
    """Already trojan:// — ensure usable query params."""
    out: list[str] = []
    try:
        p = urlparse(uri)
        password = unquote(p.username or "")
        host = p.hostname or ""
        port = p.port or 443
        q = parse_qs(p.query)
        # flatten
        params = {k: v[0] for k, v in q.items()}

        if not password or not host:
            return [uri]

        # WS without TLS (common working form)
        if params.get("type") == "ws" or "path" in params:
            path = params.get("path", "/ws")
            sni = params.get("sni")
            base = f"trojan://{password}@{host}:{port}?path={quote(path)}&type=ws"
            if sni:
                base += f"&sni={quote(sni)}"
            out.append(base)
            # TLS variant if sni present or port looks like TLS
            if sni or port in (443, 4443, 8443):
                tls = (
                    f"trojan://{password}@{host}:{port}"
                    f"?allowInsecure=1&fp=chrome_auto&sni={quote(sni or host)}"
                    f"&type=ws&path={quote(path)}"
                )
                out.append(tls)
        else:
            out.append(uri)

        # IP variant for main one
        ip = resolve_ip(host)
        if ip and ip != host and out:
            out.append(out[0].replace(f"@{host}:", f"@{ip}:", 1))
    except Exception:
        out.append(uri)
    return out


def ready_from_sn_trojan(raw: bytes) -> list[str]:
    info = parse_sn_trojan(raw)
    if not info:
        return []
    host = info["host"]
    port = info["port"]
    password = info["password"]
    path = info["path"] or "/ws"
    sni = info["sni"] or host

    uris = []
    # working form: WS + allowInsecure (matches app / user configs)
    uris.append(
        f"trojan://{password}@{host}:{port}?allowInsecure=1&path={quote(path)}&type=ws"
    )
    # with sni
    uris.append(
        f"trojan://{password}@{host}:{port}?allowInsecure=1&path={quote(path)}&type=ws&sni={quote(sni)}"
    )
    ip = resolve_ip(host)
    if ip and ip != host:
        uris.append(
            f"trojan://{password}@{ip}:{port}?allowInsecure=1&path={quote(path)}&type=ws"
        )
    return uris


def ready_from_sn_vmess(raw: bytes) -> list[str]:
    info = parse_sn_vmess_vless(raw)
    if not info:
        return []
    q = (
        f"encryption=none&security=tls"
        f"&sni={quote(info['sni'])}"
        f"&fp={quote(info['fp'])}"
        f"&type={quote(info['network'])}"
        f"&host={quote(info['host'])}"
        f"&path={quote(info['path'])}"
        f"&alpn={quote(info['alpn'])}"
    )
    return [
        f"vless://{info['uuid']}@{info['host']}:{info['port']}?{q}"
        f"#{quote(info['host'])}"
    ]


def to_ready(uri: str) -> list[str]:
    """Convert one raw decrypted URI to zero or more READY links."""
    u = uri.strip()
    if u.startswith(("hy2://", "hysteria2://")):
        return ready_hy2(u)
    if u.startswith("trojan://"):
        return ready_trojan_direct(u)
    if u.startswith("vless://"):
        return [u]
    if u.startswith("mieru://"):
        return [u]
    if u.startswith("sn://"):
        parsed = sn_decompress(u)
        if not parsed:
            return [u]  # keep raw sn
        typ, raw = parsed
        if typ == "trojan":
            return ready_from_sn_trojan(raw) or [u]
        if typ in ("vmess", "vless"):
            return ready_from_sn_vmess(raw) or [u]
        return [u]
    return []


# ── fetch ──────────────────────────────────────────────────────────────

def fetch_llc() -> list[dict[str, Any]]:
    last_err: Exception | None = None
    raw: bytes | None = None
    for host in HOPP_HOSTS:
        url = f"https://{host}/llc"
        try:
            print(f"[llc] GET {url}")
            raw = http_get(url)
            break
        except Exception as e:
            print(f"[llc] fail {host}: {e}")
            last_err = e
    if raw is None:
        raise RuntimeError(f"/llc failed: {last_err}")

    outer = json.loads(raw)
    blob = base64.b64decode(base64.b64decode(outer["data"]))
    plain = aes_cbc_decrypt(R31_KEY, blob)
    doc = json.loads(plain.decode("utf-8"))

    servers: list[dict[str, Any]] = []
    for d in doc.get("documents", []):
        f = d.get("fields", {})
        v_b64 = fs_string(f.get("v", {}))
        protocols = ""
        if v_b64:
            try:
                protocols = base64.b64decode(v_b64).decode("utf-8")
            except Exception:
                protocols = v_b64 or ""
        servers.append(
            {
                "id": d.get("name", "").split("/")[-1],
                "country": fs_string(f.get("a", {})),
                "port_or_id": fs_string(f.get("b", {})),
                "credential_b64": fs_string(f.get("c", {})),
                "protocols": protocols,
                "premium": fs_bool(f.get("p", {})),
                "mode": fs_string(f.get("m", {})),
                "ab": fs_bool(f.get("ab", {})),
                "abi": fs_bool(f.get("abi", {})),
            }
        )
    print(f"[llc] {len(servers)} servers")
    return servers


def fetch_pvca_public() -> list[dict[str, Any]]:
    try:
        print(f"[pvca] GET {PVCA_URL}")
        doc = json.loads(http_get(PVCA_URL))
        return doc.get("documents", [])
    except Exception as e:
        print(f"[pvca] skip: {e}")
        return []


def fetch_pdvqs() -> list[dict]:
    print(f"[pdvqs] GET {PDVQS_URL}")
    doc = json.loads(http_get(PDVQS_URL))
    docs = doc.get("documents", [])
    while "nextPageToken" in doc:
        token = doc["nextPageToken"]
        url = f"{PDVQS_URL}&pageToken={urllib.parse.quote(token)}"
        doc = json.loads(http_get(url))
        docs.extend(doc.get("documents", []))
    print(f"[pdvqs] {len(docs)} documents")
    return docs


def decrypt_pdvqs(
    pdvqs_docs: list[dict],
    servers: list[dict[str, Any]],
) -> tuple[list[dict], list[str], list[str], list[str], list[str]]:
    by_id = {s["port_or_id"]: s for s in servers if s.get("port_or_id")}
    results: list[dict] = []
    all_occ: list[str] = []
    all_unique: list[str] = []
    clean_uris: list[str] = []
    ready_uris: list[str] = []
    seen_unique: set[str] = set()
    seen_clean: set[str] = set()
    seen_ready: set[str] = set()

    for doc in pdvqs_docs:
        doc_id = doc.get("name", "").split("/")[-1]
        fields = doc.get("fields", {})
        meta = by_id.get(doc_id, {})
        entry: dict[str, Any] = {
            "id": doc_id,
            "country": meta.get("country"),
            "premium": meta.get("premium"),
            "mode": meta.get("mode"),
            "protocols_meta": meta.get("protocols"),
            "links": {},
            "ready": [],
        }

        for fname, fval in fields.items():
            for ct in fs_all_strings(fval):
                plain = try_aes_b64(R11_KEY, ct)
                if not plain:
                    continue
                plain = plain.strip()
                if not is_share_uri(plain):
                    continue
                entry["links"].setdefault(fname, []).append(plain)
                all_occ.append(plain)
                if plain not in seen_unique:
                    seen_unique.add(plain)
                    all_unique.append(plain)
                if plain.startswith(CLEAN_SCHEMES) and plain not in seen_clean:
                    seen_clean.add(plain)
                    clean_uris.append(plain)

                for r in to_ready(plain):
                    if r not in seen_ready:
                        seen_ready.add(r)
                        ready_uris.append(r)
                        entry["ready"].append(r)

        if entry["links"]:
            results.append(entry)

    print(
        f"[decrypt] {len(all_occ)} raw occ, {len(all_unique)} unique, "
        f"{len(clean_uris)} clean, {len(ready_uris)} READY, "
        f"{len(results)} servers"
    )
    return results, all_occ, all_unique, clean_uris, ready_uris


def main() -> int:
    out = OUT_DIR
    print("=== KeyHop READY fetch ===")
    print(f"out dir: {out}\n")

    try:
        servers = fetch_llc()
    except Exception as e:
        print(f"[llc] ERROR {e} → fallback pvca")
        pvca = fetch_pvca_public()
        servers = []
        for d in pvca:
            f = d.get("fields", {})
            v_b64 = fs_string(f.get("v", {}))
            protocols = ""
            if v_b64:
                try:
                    protocols = base64.b64decode(v_b64).decode("utf-8")
                except Exception:
                    protocols = v_b64 or ""
            servers.append(
                {
                    "id": d.get("name", "").split("/")[-1],
                    "country": fs_string(f.get("a", {})),
                    "port_or_id": fs_string(f.get("b", {})),
                    "credential_b64": fs_string(f.get("c", {})),
                    "protocols": protocols,
                    "premium": fs_bool(f.get("p", {})),
                    "mode": fs_string(f.get("m", {})),
                    "ab": fs_bool(f.get("ab", {})),
                    "abi": fs_bool(f.get("abi", {})),
                }
            )
        print(f"[pvca] {len(servers)} servers")

    (out / "keyhop_servers.json").write_text(
        json.dumps(servers, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    try:
        pdvqs = fetch_pdvqs()
    except Exception as e:
        print(f"[pdvqs] ERROR {e}")
        return 1

    results, all_occ, all_unique, clean_uris, ready_uris = decrypt_pdvqs(
        pdvqs, servers
    )

    (out / "keyhop_uris.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (out / "keyhop_uris_all.txt").write_text(
        "\n".join(all_occ) + "\n", encoding="utf-8"
    )
    (out / "keyhop_uris_unique.txt").write_text(
        "\n".join(all_unique) + "\n", encoding="utf-8"
    )
    (out / "keyhop_uris_clean.txt").write_text(
        "\n".join(clean_uris) + "\n", encoding="utf-8"
    )
    (out / "keyhop_uris_ready.txt").write_text(
        "\n".join(ready_uris) + "\n", encoding="utf-8"
    )

    print(f"\nwrote keyhop_uris_ready.txt ({len(ready_uris)})")
    print(f"wrote keyhop_uris_all.txt ({len(all_occ)})")
    print(f"wrote keyhop_uris_unique.txt ({len(all_unique)})")
    print(f"wrote keyhop_uris_clean.txt ({len(clean_uris)})")

    print("\n--- READY (hy2 / vless / trojan sample) ---")
    for u in ready_uris:
        if u.startswith(("hysteria2://", "vless://", "trojan://")):
            print(u[:120])

    # premium summary
    prem = [s for s in servers if s.get("premium")]
    free = [s for s in servers if s.get("premium") is False]
    print(f"\nservers: {len(servers)}  premium={len(prem)}  free={len(free)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
