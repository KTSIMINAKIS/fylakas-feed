#!/usr/bin/env python3
"""
Builds the update that every phone downloads (no personal data goes up; phones only download).

  out/feed/manifest.json   versions + SHA-256 of every file   (signed -> manifest.sig)
  out/feed/rules.json      brands, patterns, official sites
  out/feed/popular.txt     famous real sites (never called fakes)
  out/feed/block.bin       known scam sites as 5-byte hashes (small, and the list itself is not readable)

Sources (free, reuse allowed; see SOURCES below): CERT Polska, NetAPI (CC BY 4.0), Phishing.Database (MIT, archive),
  and rules/manual-block.txt (approved user reports, police/news announcements, any country).

Usage: python3 tools/build_feed.py [--out out/feed] [--key private/feed-signing-key.pem] [--offline FILE]
Signing uses the openssl command (ECDSA P-256, SHA-256). Python standard library only.
"""
import argparse, hashlib, json, os, struct, subprocess, sys, time, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Free sources that allow reuse. "fresh": how to see when the source last changed; "required": alarm if it gets old.
SOURCES = [
    {"name": "CERT Polska warning list (hole.cert.pl; any use allowed)",
     "url": "https://hole.cert.pl/domains/v2/domains.txt", "fresh": "http", "required": True},
    {"name": "NetAPI compromised domains, CC BY 4.0 (https://netapi.com/compromised-urls/)",
     "url": "https://netapi.com/api2/?method=compromised&dataset_type=url", "fresh": "http", "required": True},
    {"name": "Phishing.Database (MIT; archive, stopped updating 2026-10-02)",
     "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
     "fresh": "github:Phishing-Database/Phishing.Database:phishing-domains-ACTIVE.txt", "required": False},
]
STALE_DAYS = 3
SECOND = {"com", "co", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "nic", "mil"}


def h5(host: str) -> bytes:
    return hashlib.sha256(host.encode("utf-8")).digest()[:5]


def clean(line: str):
    d = line.strip().lower()
    if not d or d.startswith("#") or " " in d or "/" in d:
        return None
    d = d.rstrip(".")
    if "." not in d or len(d) > 253:
        return None
    return d


def download(url):
    req = urllib.request.Request(url, headers={"User-Agent": "fylakas-feed-builder"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return r.read().decode("utf-8", "replace")


def _age_from(ts):
    return round((time.time() - ts) / 86400, 1)


def source_age_days(src):
    """Days since the source last changed. None if unknown."""
    how = src.get("fresh") or ""
    headers = {"User-Agent": "fylakas-feed-builder"}
    try:
        if how == "http":
            req = urllib.request.Request(src["url"], headers=headers, method="HEAD")
            with urllib.request.urlopen(req, timeout=60) as r:
                lm = r.headers.get("Last-Modified")
            if not lm:
                return None
            import email.utils
            return _age_from(email.utils.parsedate_to_datetime(lm).timestamp())
        if how.startswith("github:"):
            _, repo, path = how.split(":", 2)
            headers["Accept"] = "application/vnd.github+json"
            if os.environ.get("GITHUB_TOKEN"):
                headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
            url = "https://api.github.com/repos/%s/commits?per_page=1&path=%s" % (repo, path)
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as r:
                date = json.load(r)[0]["commit"]["committer"]["date"]
            import datetime
            return _age_from(datetime.datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp())
    except Exception as e:
        print("WARNING: cannot check age of", src["name"], e, file=sys.stderr)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "out", "feed"))
    ap.add_argument("--key", default=os.path.join(ROOT, "private", "feed-signing-key.pem"))
    ap.add_argument("--offline", action="append", default=[], help="use local file(s) instead of downloading")
    ap.add_argument("--prev", default="", help="URL of the currently published feed (…/feed/) to reuse its weekly base list")
    ap.add_argument("--base-days", type=float, default=7, help="make a new big base list after this many days")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    rules = json.load(open(os.path.join(ROOT, "rules", "rules.json"), encoding="utf-8"))
    version = int(time.strftime("%Y%m%d%H", time.gmtime()))
    rules["version"] = version
    rules["updated"] = time.strftime("%Y-%m-%d", time.gmtime())

    popular_txt = open(os.path.join(ROOT, "rules", "popular.txt"), encoding="utf-8").read()
    popular = {l.strip() for l in popular_txt.splitlines() if l.strip() and not l.startswith("#")}
    official = {d for b in rules["brands"] for d in b["dom"]}

    texts, used, freshness = [], [], []
    if a.offline:
        for f in a.offline:
            texts.append(open(f, encoding="utf-8", errors="replace").read()); used.append("local " + os.path.basename(f))
    else:
        for src in SOURCES:
            name = src["name"]
            age = source_age_days(src)
            stale = src["required"] and (age is None or age > STALE_DAYS)
            try:
                texts.append(download(src["url"])); used.append(name)
                freshness.append({"source": name, "ageDays": age, "stale": stale})
            except Exception as e:
                print("WARNING: could not download", name, e, file=sys.stderr)
                freshness.append({"source": name, "error": str(e), "stale": src["required"]})
    mb = os.path.join(ROOT, "rules", "manual-block.txt")
    if os.path.exists(mb):
        texts.append(open(mb, encoding="utf-8").read()); used.append("Manual list (approved reports)")

    hosts = set()
    for t in texts:
        for line in t.splitlines():
            d = clean(line)
            if not d:
                continue
            # never block a famous real site or a company's real site as a whole
            if d in popular or d in official or d.removeprefix("www.") in popular:
                continue
            hosts.add(d)
    if len(hosts) < 1000 and not a.offline:
        sys.exit("Too few sites (%d): a source is probably broken; not publishing." % len(hosts))

    current = {h5(d) for d in hosts}

    # Weekly big "base" list + small "delta" (only what is new since the base): phones download a few KB per update.
    base, base_version = None, None
    if a.prev:
        try:
            pm = json.loads(download(a.prev + "manifest.json"))
            bv = pm.get("baseVersion")
            made = pm.get("baseMade", 0)
            if bv and time.time() - made < a.base_days * 86400 and "base.bin" in pm.get("files", {}):
                req = urllib.request.Request(a.prev + "base.bin", headers={"User-Agent": "fylakas-feed-builder"})
                raw = urllib.request.urlopen(req, timeout=180).read()
                if hashlib.sha256(raw).hexdigest() == pm["files"]["base.bin"]["sha256"] and raw[:4] == b"FYLB":
                    n = struct.unpack(">I", raw[8:12])[0]
                    base = {raw[12 + i * 5: 17 + i * 5] for i in range(n)}
                    base_version, base_made = bv, made
        except Exception as e:
            print("NOTE: no previous base reused:", e, file=sys.stderr)
    if base is None or len(current - base) > len(current) // 3:
        base, base_version, base_made = current, version, int(time.time())
    delta = current - base

    def pack(hs, v):
        hs = sorted(hs)
        return b"FYLB" + struct.pack(">II", v % 2**32, len(hs)) + b"".join(hs)

    files = {
        "rules.json": json.dumps(rules, ensure_ascii=False, indent=1).encode("utf-8"),
        "popular.txt": popular_txt.encode("utf-8"),
        "base.bin": pack(base, base_version),
        "delta.bin": pack(delta, version),
    }
    manifest = {
        "format": 1,
        "version": version,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "blockCount": len(base | delta),
        "baseVersion": base_version,
        "baseMade": base_made,
        "sources": used,
        "freshness": freshness,
        "files": {},
    }
    for name, data in files.items():
        open(os.path.join(a.out, name), "wb").write(data)
        manifest["files"][name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    mpath = os.path.join(a.out, "manifest.json")
    open(mpath, "w", encoding="utf-8").write(json.dumps(manifest, ensure_ascii=False, indent=1))

    if os.path.exists(a.key):
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", a.key, "-out",
                        os.path.join(a.out, "manifest.sig"), mpath], check=True)
        print("signed")
    else:
        print("WARNING: no key, manifest not signed (phones will refuse it)", file=sys.stderr)
    print(json.dumps({k: manifest[k] for k in ("version", "blockCount", "sources", "freshness")}, ensure_ascii=False))
    stale = [f["source"] for f in freshness if f.get("stale")]
    open(os.path.join(os.path.dirname(a.out.rstrip("/")), "stale.txt"), "w").write("\n".join(stale))
    if stale:
        print("STALE SOURCES (older than %d days or failing): %s" % (STALE_DAYS, ", ".join(stale)), file=sys.stderr)
    for n, f in manifest["files"].items():
        print(" ", n, f["size"], "bytes")


if __name__ == "__main__":
    main()
