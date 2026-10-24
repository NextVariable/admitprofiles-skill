#!/usr/bin/env python3
"""Verify audit coverage and frozen evidence; never certify source semantics."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

VERDICTS = {
    "supported",
    "overstated",
    "unsupported",
    "changed",
    "inaccessible",
    "unknown_preserved",
}


def check(inventory, audits, root, redactions=None):
    errors = []
    expected = {u["unit_id"] for u in inventory["units"]}
    if len(expected) != len(inventory["units"]):
        errors.append("Inventory has duplicate unit IDs")
    seen = set()
    for audit in audits:
        for row in audit["units"]:
            ident = row.get("unit_id")
            if ident in seen:
                errors.append(f"Duplicate audit unit: {ident}")
            seen.add(ident)
            if row.get("verdict") not in VERDICTS:
                errors.append(f"Invalid verdict: {ident}")
            if (
                not isinstance(row.get("rationale"), str)
                or not row["rationale"].strip()
            ):
                errors.append(f"Missing rationale: {ident}")
            if row.get("checked_on") != inventory["date"]:
                errors.append(f"Audit date differs: {ident}")
            if row.get("verdict") != "unknown_preserved":
                if not row.get("checked_urls") or not row.get("evidence_locators"):
                    errors.append(f"Missing source check or locator: {ident}")
    for ident in sorted(expected - seen):
        errors.append(f"Missing audit unit: {ident}")
    for ident in sorted(seen - expected):
        errors.append(f"Unexpected audit unit: {ident}")
    approved = {}
    known = {entry["path"]: entry["sha256"] for entry in inventory["files"]}
    if redactions is not None:
        if redactions.get("schema_version") != 1:
            errors.append("Invalid privacy redaction manifest version")
        for row in redactions.get("files", []):
            name = row.get("path", "")
            if (
                name not in known
                or not name.startswith("research/")
                or ".." in Path(name).parts
                or name in approved
                or row.get("original_sha256") != known.get(name)
                or row.get("reason") != "public-example-privacy-minimization"
            ):
                errors.append(f"Invalid privacy redaction entry: {name}")
                continue
            approved[name] = row.get("public_sha256")
    for entry in inventory["files"]:
        path = root / entry["path"]
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            digest = None
        if entry["path"] in approved:
            if digest is None or digest != approved[entry["path"]]:
                errors.append(f"Privacy-edited file changed: {entry['path']}")
        elif digest != entry["sha256"]:
            errors.append(f"Historical file changed: {entry['path']}")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit_dir", type=Path)
    parser.add_argument("--records-root", type=Path, required=True)
    parser.add_argument(
        "--redactions",
        type=Path,
        help="Explicit manifest of privacy edits; original inventory stays unchanged",
    )
    args = parser.parse_args()
    inventory = json.loads((args.audit_dir / "inventory.json").read_text())
    audits = []
    for path in sorted(args.audit_dir.glob("*.json")):
        if path.name == "inventory.json":
            continue
        data = json.loads(path.read_text())
        if isinstance(data, dict) and "units" in data:
            audits.append(data)
    redactions = json.loads(args.redactions.read_text()) if args.redactions else None
    errors = check(inventory, audits, args.records_root, redactions)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    if redactions is not None:
        print(
            "Privacy-edited public files verified against separate hashes; "
            "these are not byte-identical frozen originals."
        )
    print(
        f"Audit covers {len(inventory['units'])} frozen units; source truth is not machine certified."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
