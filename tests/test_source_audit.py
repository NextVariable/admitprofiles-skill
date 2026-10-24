"""Coverage regressions prevent omission, duplicate approval, or history rewrite."""

import copy
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "source_audit", Path(__file__).with_name("check_source_audit.py")
)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class SourceAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "record.json").write_text("{}")
        self.inventory = {
            "date": "2026-10-05",
            "units": [{"unit_id": "record.json#/field"}],
            "files": [
                {"path": "record.json", "sha256": hashlib.sha256(b"{}").hexdigest()}
            ],
        }
        self.reviews = [
            {
                "units": [
                    {
                        "unit_id": "record.json#/field",
                        "verdict": "supported",
                        "rationale": "Source supports the field",
                        "checked_on": "2026-10-05",
                        "checked_urls": ["https://example.org/source"],
                        "evidence_locators": ["Education"],
                    }
                ]
            }
        ]

    def test_complete_frozen_audit(self):
        self.assertEqual(audit.check(self.inventory, self.reviews, self.root), [])

    def test_omission_is_rejected(self):
        reviews = copy.deepcopy(self.reviews)
        reviews[0]["units"].pop()
        self.assertTrue(
            any(
                "Missing audit unit" in e
                for e in audit.check(self.inventory, reviews, self.root)
            )
        )

    def test_duplicate_is_rejected(self):
        reviews = copy.deepcopy(self.reviews)
        reviews[0]["units"].append(reviews[0]["units"][0])
        self.assertTrue(
            any(
                "Duplicate audit unit" in e
                for e in audit.check(self.inventory, reviews, self.root)
            )
        )

    def test_history_digest_change_is_rejected(self):
        inventory = copy.deepcopy(self.inventory)
        inventory["files"][0]["sha256"] = "0" * 64
        self.assertTrue(
            any(
                "Historical file changed" in e
                for e in audit.check(inventory, self.reviews, self.root)
            )
        )

    def test_supported_claim_without_locator_is_rejected(self):
        reviews = copy.deepcopy(self.reviews)
        row = next(r for r in reviews[0]["units"] if r["verdict"] == "supported")
        row["evidence_locators"] = []
        self.assertTrue(
            any(
                "Missing source check" in e
                for e in audit.check(self.inventory, reviews, self.root)
            )
        )


class PrivacyRedactionTests(unittest.TestCase):
    def setUp(self):
        SourceAuditTests.setUp(self)
        (self.root / "research").mkdir()
        (self.root / "research/record.json").write_text("{}")
        self.inventory["files"][0]["path"] = "research/record.json"
        (self.root / "research/record.json").write_text('{"privacy": true}')
        self.manifest = {
            "schema_version": 1,
            "files": [
                {
                    "path": "research/record.json",
                    "original_sha256": hashlib.sha256(b"{}").hexdigest(),
                    "public_sha256": hashlib.sha256(b'{"privacy": true}').hexdigest(),
                    "reason": "public-example-privacy-minimization",
                }
            ],
        }

    def test_manifest_is_required_for_changed_examples(self):
        self.assertTrue(audit.check(self.inventory, self.reviews, self.root))

    def test_explicit_redaction_keeps_original_inventory(self):
        before = copy.deepcopy(self.inventory)
        self.assertEqual(
            audit.check(self.inventory, self.reviews, self.root, self.manifest), []
        )
        self.assertEqual(self.inventory, before)

    def test_edited_bytes_tampering_is_rejected(self):
        (self.root / "research/record.json").write_text("tampered")
        self.assertTrue(
            audit.check(self.inventory, self.reviews, self.root, self.manifest)
        )

    def test_wrong_original_hash_is_rejected(self):
        self.manifest["files"][0]["original_sha256"] = "0" * 64
        self.assertTrue(
            audit.check(self.inventory, self.reviews, self.root, self.manifest)
        )

    def test_unknown_or_duplicate_manifest_path_is_rejected(self):
        for path in ("../outside.json", "research/record.json"):
            manifest = copy.deepcopy(self.manifest)
            row = copy.deepcopy(manifest["files"][0])
            row["path"] = path
            manifest["files"].append(row)
            with self.subTest(path=path):
                self.assertTrue(
                    audit.check(self.inventory, self.reviews, self.root, manifest)
                )
