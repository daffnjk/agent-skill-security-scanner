import copy
from collections import Counter
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import detection_loop as loop
from detection_patch_guard import validate_patch


def row(uid, text, label="benign", source="dev", role="development", family="real"):
    return dict(uid=uid, text=text, label=label, source=source, role=role, family=family, group=uid)


class InputTests(unittest.TestCase):
    def source(self, tmp, rows, members=None):
        path = Path(tmp) / "test.tar.gz"
        content = "\n".join(json.dumps(r) for r in rows).encode()
        with tarfile.open(path, "w:gz") as out:
            item = tarfile.TarInfo("release/source/skills.jsonl")
            item.size = len(content)
            out.addfile(item, io.BytesIO(content))
            for member in members or []:
                out.addfile(member)
        source = dict(id="dev", role="development", member="skills.jsonl", text_field="content",
                      expected_labels={"benign": len(rows)})
        return source, path

    def test_known_schema_and_opaque_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, path = self.source(tmp, [{"id": "../../benign", "content": "text", "label": "benign"}])
            records = loop.read_source(source, path)
            self.assertRegex(records[0]["uid"], "^[0-9a-f]{64}$")

    def test_archive_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, path = self.source(tmp, [], [tarfile.TarInfo("../../escape")])
            with self.assertRaises(ValueError):
                loop.read_source(source, path)

    def test_archive_link_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = tarfile.TarInfo("link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            source, path = self.source(tmp, [], [link])
            with self.assertRaises(ValueError):
                loop.read_source(source, path)

    def test_schema_label_missing_duplicate_and_count_fail_closed(self):
        cases = [
            [{"id": "a", "content": "x", "label": "suspicious"}],
            [{"id": "a", "content": "", "label": "benign"}],
            [{"id": "a", "content": "x"}],
            [{"id": "a", "content": "x", "label": "benign"}] * 2,
        ]
        for rows in cases:
            with self.subTest(rows=rows), tempfile.TemporaryDirectory() as tmp:
                source, path = self.source(tmp, rows)
                with self.assertRaises(ValueError):
                    loop.read_source(source, path)
        with tempfile.TemporaryDirectory() as tmp:
            source, path = self.source(tmp, [{"id": "a", "content": "x", "label": "benign"}])
            source["expected_labels"] = {"benign": 2}
            with self.assertRaises(ValueError):
                loop.read_source(source, path)

    def test_cache_checksum_is_not_bypassed(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = {"asset": "dataset-2026.tar.gz", "sha256": "0" * 64}
            (Path(tmp) / source["asset"]).write_bytes(b"wrong")
            with self.assertRaises(ValueError):
                loop.download(source, Path(tmp))

    def test_exact_conflicting_labels_require_adjudication(self):
        with self.assertRaises(ValueError):
            loop.partition([row("a", "same", "malicious"), row("b", " SAME ", "benign")])

    def test_exact_dedup_and_cross_source_quarantine(self):
        rows, audit = loop.partition([row("a", "Same text"), row("b", " same TEXT "),
            row("c", "same text", source="val", role="regression")])
        self.assertEqual([r["uid"] for r in rows], ["a"])
        self.assertEqual(sum(audit["excluded"].values()), 2)

    def test_near_duplicates_cannot_leak_to_validation(self):
        text = " ".join(f"token{i}" for i in range(100))
        rows, audit = loop.partition([row("a", text),
            row("b", text + " one-extra-token", source="val", role="regression")])
        self.assertEqual([r["uid"] for r in rows], ["a"])
        self.assertEqual(audit["excluded"]["val:development_overlap"], 1)

    def test_shared_origin_grouped_even_with_different_text(self):
        rows, _ = loop.partition([row("a", "---\nname: calendar\n---\nlocal sorting"),
            row("b", "---\nname: calendar\n---\ncompletely unrelated prose", source="val", role="regression")])
        self.assertEqual(len(rows), 1)

    def test_grouping_order_independent(self):
        raw = [row("b", "alpha beta"), row("a", "alpha beta"), row("c", "different text")]
        self.assertEqual(loop.partition(raw), loop.partition(list(reversed(raw))))

    def test_materialization_never_executes_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "skills"
            loop.materialize([row("a", "#!/bin/sh\ntouch /never-execute-this")], target)
            self.assertEqual((target / "a/SKILL.md").stat().st_mode & 0o777, 0o400)


class ReportTests(unittest.TestCase):
    def output(self, tmp, predictions, metadata):
        path = Path(tmp)
        for name, rows in (("results.jsonl", predictions), ("scan-metadata.jsonl", metadata)):
            (path / name).write_text("".join(json.dumps(r) + "\n" for r in rows))
        return path

    def test_complete_valid_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self.output(tmp, [{"skill_id": "a", "verdict": "benign"}],
                              [{"skill_id": "a", "complete": True}])
            self.assertEqual(loop.validate_output(out, {"a"}), {"a": "benign"})

    def test_missing_extra_duplicate_and_incomplete_fail_closed(self):
        for predictions, metadata in [
            ([], [{"skill_id": "a", "complete": True}]),
            ([{"skill_id": "a", "verdict": "benign"}] * 2, [{"skill_id": "a", "complete": True}]),
            ([{"skill_id": "b", "verdict": "benign"}], [{"skill_id": "a", "complete": True}]),
            ([{"skill_id": "a", "verdict": "benign"}], [{"skill_id": "a", "complete": "true"}]),
            ([{"skill_id": "a", "verdict": "safe"}], [{"skill_id": "a", "complete": True}]),
        ]:
            with self.subTest(predictions=predictions), tempfile.TemporaryDirectory() as tmp:
                out = self.output(tmp, predictions, metadata)
                with self.assertRaises(ValueError):
                    loop.validate_output(out, {"a"})

    def test_confusion_metrics_and_screening_are_separate(self):
        rows = [row("a", "a", "malicious"), row("b", "b", "malicious"), row("c", "c"), row("d", "d")]
        predictions = dict(a="malicious", b="suspicious", c="malicious", d="benign")
        strict = loop.metrics(rows, predictions)
        self.assertEqual([strict[k] for k in ("tp", "fp", "tn", "fn")], [1, 1, 1, 1])
        self.assertEqual(strict["precision"], .5)
        self.assertEqual(strict["f2"], .5)
        self.assertEqual(loop.metrics(rows, predictions, True)["recall"], 1)

    def test_wilson_and_zero_division(self):
        self.assertIsNone(loop.wilson(0, 0))
        self.assertGreater(loop.wilson(0, 100)[1], 0)
        self.assertEqual(loop.metrics([], {})["mcc"], 0)
        json.dumps(loop.metrics([], {}), allow_nan=False)


class GateTests(unittest.TestCase):
    def fixture(self):
        rows = [row(str(i), str(i), "malicious" if i < 20 else "benign", "val", "regression") for i in range(40)]
        base = {r["uid"]: r["label"] for r in rows}
        base["0"] = "benign"
        new = dict(base)
        new["0"] = "malicious"
        report = loop.comparison(rows, base, new)
        report["timing"] = dict(baseline=1, candidate=1)
        return rows, base, new, report

    def test_improvement_is_only_a_proposal_not_generalization(self):
        _, _, _, report = self.fixture()
        result = loop.gate(report, {"val"})
        self.assertTrue(result["proposal_ready"])
        self.assertFalse(result["release_approved"])
        self.assertFalse(result["generalization_proven"])
        self.assertEqual(report["cluster_sign_test"]["one_sided_p"], .5)

    def test_identical_candidate_is_not_an_improvement(self):
        rows, base, _, _ = self.fixture()
        report = loop.comparison(rows, base, base)
        report["timing"] = dict(baseline=1, candidate=1)
        result = loop.gate(report, {"val"})
        self.assertTrue(result["non_regression"])
        self.assertFalse(result["proposal_ready"])

    def test_recall_gain_cannot_pay_for_false_positive(self):
        rows, base, new, _ = self.fixture()
        new["20"] = "malicious"
        report = loop.comparison(rows, base, new)
        report["timing"] = dict(baseline=1, candidate=1)
        self.assertFalse(loop.gate(report, {"val"})["non_regression"])

    def test_screening_false_positive_blocks_strict_improvement(self):
        rows, base, new, _ = self.fixture()
        new["20"] = "suspicious"
        report = loop.comparison(rows, base, new)
        report["timing"] = dict(baseline=1, candidate=1)
        self.assertFalse(loop.gate(report, {"val"})["proposal_ready"])

    def test_missing_source_small_class_and_slowdown_block(self):
        _, _, _, report = self.fixture()
        self.assertFalse(loop.gate(report, {"val", "missing"})["non_regression"])
        for timing in (3, float("nan"), 0):
            report["timing"]["candidate"] = timing
            self.assertFalse(loop.gate(report, {"val"})["non_regression"])
        report["timing"]["candidate"] = 1
        report["sources"]["val"]["strict"]["baseline"]["tn"] = 1
        self.assertFalse(loop.gate(report, {"val"})["non_regression"])

    def test_subgroup_cannot_be_hidden_by_aggregate_gain(self):
        _, _, _, report = self.fixture()
        family = copy.deepcopy(report["sources"]["val"]["families"]["real"])
        family["candidate"]["fn"] = family["baseline"]["fn"] + 1
        report["sources"]["val"]["families"]["minority"] = family
        self.assertFalse(loop.gate(report, {"val"})["non_regression"])

    def test_group_test_counts_related_variants_once(self):
        rows, base, new, _ = self.fixture()
        for r in rows:
            r["group"] = "one-family"
        self.assertEqual(loop.comparison(rows, base, new)["cluster_sign_test"]["wins"], 1)


class PatchTests(unittest.TestCase):
    def valid(self):
        return ("diff --git a/cmd/detector/main.go b/cmd/detector/main.go\n"
                "--- a/cmd/detector/main.go\n+++ b/cmd/detector/main.go\n@@ -1 +1 @@\n-old\n+new\n"
                "diff --git a/cmd/detector/main_test.go b/cmd/detector/main_test.go\n"
                "--- a/cmd/detector/main_test.go\n+++ b/cmd/detector/main_test.go\n@@ -1 +1 @@\n-old\n+new\n").encode()

    def test_bounded_detector_and_tests_patch(self):
        self.assertEqual(len(validate_patch(self.valid())), 2)

    def test_policy_edits_symlinks_binary_and_no_tests_rejected(self):
        for data in (self.valid().replace(b"cmd/detector/main.go", b"scripts/detection_loop.py"),
                     self.valid() + b"new file mode 120000\n",
                     self.valid() + b"GIT binary patch\n",
                     self.valid().split(b"diff --git", 2)[0],
                     self.valid().replace(b"main_test.go", b"helper.go")):
            with self.subTest(data=data), self.assertRaises(ValueError):
                validate_patch(data)


if __name__ == "__main__":
    unittest.main()
