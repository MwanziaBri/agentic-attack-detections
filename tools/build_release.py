#!/usr/bin/env python3
"""Build the files attached to each GitHub release, so the rules and indicators can be downloaded without cloning.

    python3 tools/build_release.py                    # version from the top entry in CHANGELOG.md, output in dist/
    python3 tools/build_release.py --version 2.8.0 --out dist

Writes:
    agentic-attack-detections.rules              every Suricata rule in one file (behaviors, then each framework)
    agentic-attack-detections-yara.zip           the YARA rules, one file per framework
    agentic-attack-detections-stix2.1.json       the STIX 2.1 bundle
    agentic-attack-detections-indicators.zip     iocs/indicators.csv and everything under feeds/
    agentic-attack-detections-waf.zip            everything under waf/
    agentic-attack-detections-sentinel.json      the Microsoft Sentinel ARM template with everything (deploy/sentinel/)
    agentic-attack-detections-sentinel.zip       every Microsoft Sentinel template: everything, and one per framework
    SHA256SUMS.txt                               SHA-256 of each file above

The names carry no version, so https://github.com/<owner>/<repo>/releases/latest/download/<name> always points at
the newest release. The version is written inside each file instead. The output is reproducible: the same commit
and version give the same bytes. Standard library only.
"""
import argparse
import hashlib
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = "https://github.com/ThreatDefence/agentic-attack-detections"
NAME = "agentic-attack-detections"


def changelog_version():
    m = re.search(r"^## (\d+\.\d+\.\d+)", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), re.M)
    if not m:
        raise SystemExit("no version heading in CHANGELOG.md")
    return m.group(1)


def suricata_rules(version):
    files = sorted((ROOT / "behaviors" / "suricata").glob("*.rules")) + sorted((ROOT / "frameworks").glob("*/suricata/*.rules"))
    out = [f"# Agentic attack detections {version}: every Suricata rule in one file.",
           f"# {REPO}",
           "# Built by tools/build_release.py from the files named below. Suricata 7 and 8.",
           "# Address rules (the -ip.rules sections) come from iocs/indicators.csv and are leads, not a block list.", ""]
    sids = {}
    for f in files:
        rel = f.relative_to(ROOT).as_posix()
        out += [f"# ---- {rel}", ""]
        text = f.read_text(encoding="utf-8").rstrip("\n")
        for line in text.splitlines():
            m = re.search(r"\bsid:(\d+);", line)
            if m and not line.lstrip().startswith("#"):
                if m.group(1) in sids:
                    raise SystemExit(f"duplicate sid {m.group(1)} in {rel} and {sids[m.group(1)]}")
                sids[m.group(1)] = rel
        out += [text, ""]
    return "\n".join(out), len(sids), len(files)


def write_zip(path, members, version):
    """members: (name in the archive, bytes). Fixed timestamps and order, so the archive is reproducible."""
    note = f"Agentic attack detections {version}\n{REPO}\n".encode()
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, data in [("VERSION.txt", note)] + sorted(members):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, data)
    return len(members)


def tree(folder):
    return [(p.relative_to(ROOT).as_posix(), p.read_bytes()) for p in sorted(folder.rglob("*")) if p.is_file() and p.name != ".DS_Store"]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", default=None, help="release version, default: the top entry in CHANGELOG.md")
    ap.add_argument("--out", default="dist", help="output folder, default: dist")
    args = ap.parse_args()
    version = (args.version or changelog_version()).lstrip("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit(f"version must look like 2.8.0, got {version!r}")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob(f"{NAME}*"):
        old.unlink()

    rules, n_rules, n_files = suricata_rules(version)
    (out / f"{NAME}.rules").write_text(rules, encoding="utf-8")
    print(f"{NAME}.rules: {n_rules} rules from {n_files} files")

    yara = [(p.name, p.read_bytes()) for p in sorted((ROOT / "frameworks").glob("*/yara/*.yar"))]
    print(f"{NAME}-yara.zip: {write_zip(out / f'{NAME}-yara.zip', yara, version)} files")

    (out / f"{NAME}-stix2.1.json").write_bytes((ROOT / "feeds" / "stix2.1-bundle.json").read_bytes())
    print(f"{NAME}-stix2.1.json: copied from feeds/stix2.1-bundle.json")

    indicators = [("iocs/indicators.csv", (ROOT / "iocs" / "indicators.csv").read_bytes())] + tree(ROOT / "feeds")
    print(f"{NAME}-indicators.zip: {write_zip(out / f'{NAME}-indicators.zip', indicators, version)} files")

    print(f"{NAME}-waf.zip: {write_zip(out / f'{NAME}-waf.zip', tree(ROOT / 'waf'), version)} files")

    sentinel = ROOT / "deploy" / "sentinel"
    (out / f"{NAME}-sentinel.json").write_bytes((sentinel / f"{NAME}.json").read_bytes())
    print(f"{NAME}-sentinel.json: copied from deploy/sentinel/{NAME}.json")
    print(f"{NAME}-sentinel.zip: {write_zip(out / f'{NAME}-sentinel.zip', tree(sentinel), version)} files")

    built = sorted(p for p in out.glob(f"{NAME}*") if p.is_file())
    sums = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in built)
    (out / "SHA256SUMS.txt").write_text(sums, encoding="utf-8")
    print(f"SHA256SUMS.txt: {len(built)} files")


if __name__ == "__main__":
    main()
