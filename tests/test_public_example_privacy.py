"""Public examples keep pseudonyms and explicitly mark withdrawn sources."""

import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PublicExamplePrivacyTests(unittest.TestCase):
    def test_case_labels_and_withdrawn_sources(self):
        for folder in (ROOT / "research", ROOT / "archive/research"):
            for path in folder.rglob("cases.json"):
                with self.subTest(path=str(path.relative_to(ROOT))):
                    data = json.loads(path.read_text())
                    self.assertIn("not a new verification", data["privacy_notice"])
                    for case in data["cases"]:
                        self.assertRegex(case["public_name_or_handle"], r"^AP-\d{3}$")
                    for source in data["sources"]:
                        self.assertNotRegex(
                            source["url"], r"(?i)linkedin\.com|/in/|student-spotlight"
                        )
                        if source["source_type"].startswith("personal_"):
                            self.assertTrue(
                                source["url"].startswith("https://redacted.invalid/")
                            )

    def test_linkedin_profiles_are_not_hidden_in_search_logs(self):
        for folder in (ROOT / "research", ROOT / "archive/research"):
            for path in folder.rglob("*.md"):
                self.assertIsNone(
                    re.search(
                        r"(?i)(?:https?://)?(?:[\w-]+\.)?linkedin\.com/(?:in|posts)/[A-Za-z0-9_-]+",
                        path.read_text(),
                    ),
                    str(path.relative_to(ROOT)),
                )

    def test_current_public_freeze_hashes(self):
        for path in (ROOT / "research").rglob("freeze.json"):
            data = json.loads(path.read_text())
            for name, expected in data["privacy_redaction"][
                "public_file_sha256"
            ].items():
                self.assertEqual(
                    hashlib.sha256((path.parent / name).read_bytes()).hexdigest(),
                    expected,
                )
