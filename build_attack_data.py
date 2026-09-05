#!/usr/bin/env python3
"""Regenerate attack-data.json from the official MITRE ATT&CK STIX bundles.

Usage:
    python build_attack_data.py                 # latest version of every matrix
    python build_attack_data.py --version 19.2  # pin a version
    python build_attack_data.py --cache-dir DIR # reuse downloaded bundles

Output format (attack-data.json):

    {
      "meta": { "attack_version": "19.2", ... },
      "techniques": {
        "T1055": [name, tactics, description, platforms, matrix, status, supersededBy]
      }
    }

`status` and `supersededBy` are omitted when a technique is active, so most rows
are 5 elements long. Consumers must read them as `row[5] || 0`.

    status: 0 = active, 1 = deprecated, 2 = revoked
"""

import argparse
import datetime
import json
import os
import re
import sys
import urllib.request

INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
BUNDLE_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
              "/{domain}-attack/{domain}-attack-{version}.json")
SOURCE_REPO = "https://github.com/mitre-attack/attack-stix-data"

# domain -> single-letter matrix code used in the bundled JSON
DOMAINS = {"enterprise": "E", "mobile": "M", "ics": "I"}

DESC_MAX = 200

STATUS_ACTIVE = 0
STATUS_DEPRECATED = 1
STATUS_REVOKED = 2


# ----------------------------------------------------------------- fetching

def fetch(url, cache_dir):
    """Download `url`, caching the body under `cache_dir`."""
    name = url.rsplit("/", 1)[-1]
    path = os.path.join(cache_dir, name)
    if os.path.exists(path) and os.path.getsize(path) > 0:
        print("  cached  " + name)
    else:
        print("  fetch   " + url)
        os.makedirs(cache_dir, exist_ok=True)
        with urllib.request.urlopen(url, timeout=300) as r, open(path, "wb") as f:
            f.write(r.read())
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def latest_versions(index):
    """Map domain name -> newest collection version string."""
    out = {}
    for collection in index.get("collections", []):
        # "Enterprise ATT&CK" -> "enterprise"
        name = collection.get("name", "").split()[0].lower()
        versions = collection.get("versions") or []
        if name in DOMAINS and versions:
            out[name] = versions[0]["version"]
    missing = set(DOMAINS) - set(out)
    if missing:
        sys.exit("index.json is missing collections for: " + ", ".join(sorted(missing)))
    return out


# ----------------------------------------------------------------- cleaning

CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")
CODE_RE = re.compile(r"<code>(.*?)</code>", re.S)
WS_RE = re.compile(r"\s+")


def clean_description(text):
    """Flatten ATT&CK's markdown description into a single short tooltip line."""
    if not text:
        return ""
    text = CITATION_RE.sub("", text)
    text = MD_LINK_RE.sub(r"\1", text)
    text = CODE_RE.sub(r"\1", text)
    text = text.replace("*", "").replace("`", "")
    text = WS_RE.sub(" ", text).strip()
    if len(text) <= DESC_MAX:
        return text
    # Prefer a sentence boundary, fall back to a word boundary.
    head = text[:DESC_MAX]
    stop = head.rfind(". ")
    if stop >= DESC_MAX // 2:
        return head[:stop + 1]
    space = head.rfind(" ")
    if space <= 0:
        return head + "..."
    return head[:space].rstrip(",;:") + "..."


def attack_id(obj):
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


# ----------------------------------------------------------------- building

def build(bundles):
    """Merge per-domain STIX bundles into the compact technique table."""
    techniques = {}
    stix_to_id = {}
    revoked_by = {}
    counts = {}

    for domain, bundle in bundles.items():
        code = DOMAINS[domain]
        objects = bundle["objects"]

        tactic_names = {
            o["x_mitre_shortname"]: o["name"]
            for o in objects
            if o["type"] == "x-mitre-tactic" and o.get("x_mitre_shortname")
        }

        domain_count = 0
        for obj in objects:
            if obj["type"] == "relationship":
                if obj.get("relationship_type") == "revoked-by":
                    revoked_by[obj["source_ref"]] = obj["target_ref"]
                continue
            if obj["type"] != "attack-pattern":
                continue

            tid = attack_id(obj)
            if not tid:
                continue
            stix_to_id[obj["id"]] = tid
            domain_count += 1

            existing = techniques.get(tid)
            if existing:
                # Same ID present in several matrices: keep the first row, add the code.
                if code not in existing["matrix"]:
                    existing["matrix"] += code
                continue

            if obj.get("revoked"):
                status = STATUS_REVOKED
            elif obj.get("x_mitre_deprecated"):
                status = STATUS_DEPRECATED
            else:
                status = STATUS_ACTIVE

            tactics = [
                tactic_names.get(p["phase_name"], p["phase_name"].replace("-", " ").title())
                for p in obj.get("kill_chain_phases") or []
                if p.get("kill_chain_name", "").endswith("attack")
            ]
            platforms = [p for p in obj.get("x_mitre_platforms") or [] if p and p != "None"]

            techniques[tid] = {
                "name": obj.get("name", ""),
                "tactics": ", ".join(dict.fromkeys(tactics)),
                "desc": clean_description(obj.get("description")),
                "platforms": ", ".join(platforms),
                "matrix": code,
                "status": status,
                "stix": obj["id"],
            }
        counts[domain] = domain_count

    # Resolve revoked -> replacement now that every ID is known.
    for entry in techniques.values():
        target = revoked_by.get(entry["stix"])
        entry["superseded"] = stix_to_id.get(target) if target else None

    rows = {}
    for tid in sorted(techniques, key=sort_key):
        e = techniques[tid]
        row = [e["name"], e["tactics"], e["desc"], e["platforms"], e["matrix"]]
        if e["status"] or e["superseded"]:
            row.append(e["status"])
            if e["superseded"]:
                row.append(e["superseded"])
        rows[tid] = row
    return rows, counts


def sort_key(tid):
    """Sort T1055 before T1055.001 and keep numeric order."""
    base, _, sub = tid.partition(".")
    return (base[:1], int(base[1:] or 0), int(sub or 0))


# ----------------------------------------------------------------- entrypoint

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", help="pin every matrix to this ATT&CK version (default: latest)")
    ap.add_argument("--cache-dir", default=os.path.join(here, ".attack-cache"),
                    help="where downloaded STIX bundles are kept")
    ap.add_argument("-o", "--output", default=os.path.join(here, "attack-data.json"))
    args = ap.parse_args()

    if args.version:
        versions = {d: args.version for d in DOMAINS}
    else:
        print("Resolving latest ATT&CK versions...")
        versions = latest_versions(fetch(INDEX_URL, args.cache_dir))
    print("  versions: " + ", ".join(d + "=" + v for d, v in sorted(versions.items())))

    bundles = {
        domain: fetch(BUNDLE_URL.format(domain=domain, version=versions[domain]), args.cache_dir)
        for domain in DOMAINS
    }

    rows, counts = build(bundles)
    active = sum(1 for r in rows.values() if len(r) == 5)

    payload = {
        "meta": {
            "attack_version": versions["enterprise"],
            "matrix_versions": versions,
            "generated": datetime.date.today().isoformat(),
            "source": SOURCE_REPO,
            "format": "[name, tactics, description, platforms, matrix, status?, supersededBy?]",
            "status_codes": {"0": "active", "1": "deprecated", "2": "revoked"},
            "counts": dict(counts, total=len(rows), active=active),
        },
        "techniques": rows,
    }

    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, ensure_ascii=False, separators=(",", ":"), sort_keys=False)
        f.write("\n")

    print("\nWrote " + args.output)
    print("  %d techniques (%d active), %.0f KB"
          % (len(rows), active, os.path.getsize(args.output) / 1024))
    for domain, n in sorted(counts.items()):
        print("  %s: %d" % (domain, n))


if __name__ == "__main__":
    main()
