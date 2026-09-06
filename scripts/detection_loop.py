#!/usr/bin/env python3
"""Frozen, source-separated static benchmark. Samples are data, never programs.

Only stdlib is required. Evaluation uses separately built static scanner images in
networkless containers; prepare-dev downloads *only* the development source.
Public v41 sources are regression evidence, never an unseen final test set.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import statistics
import subprocess
import tarfile
import tempfile
import time
import unicodedata
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "benchmarks/continuous/sources.json"
MAX_ASSET = 32 * 1024 * 1024
MAX_TEXT = 1024 * 1024
VERDICTS = {"benign", "suspicious", "malicious"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False) + "\n")


def download(source: dict, cache: Path) -> Path:
    """Do not fetch URLs found in samples, or accept unverified cached assets."""
    name = source["asset"]
    if not re.fullmatch(r"[a-z0-9_-]+\.tar\.gz", name):
        raise ValueError("invalid asset name")
    if not re.fullmatch(r"[0-9a-f]{64}", source["sha256"]):
        raise ValueError("a real SHA-256 is mandatory")
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / name
    if target.exists():
        if target.is_symlink() or target.stat().st_size > MAX_ASSET:
            raise ValueError("unsafe cached asset")
    else:
        tag = name.removesuffix(".tar.gz")
        url = ("https://github.com/daffnjk/agent-skill-security-datasets/"
               f"releases/download/{tag}/{name}")
        request = urllib.request.Request(url, headers={"User-Agent": "skillscan-evaluation/1"})
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read(MAX_ASSET + 1)
        if len(data) > MAX_ASSET or digest(data) != source["sha256"]:
            raise ValueError("asset size or checksum mismatch")
        with tempfile.NamedTemporaryFile(dir=cache, delete=False) as temporary:
            temporary.write(data)
            temporary_path = Path(temporary.name)
        temporary_path.replace(target)
    if digest(target.read_bytes()) != source["sha256"]:
        raise ValueError("cached asset checksum mismatch")
    return target


def read_source(source: dict, archive: Path) -> list[dict]:
    """Read the one declared JSONL member without extracting an archive."""
    found = []
    total_size = 0
    with tarfile.open(archive, "r:gz") as handle:
        for index, member in enumerate(handle):
            path = PurePosixPath(member.name)
            total_size += member.size
            if (index >= 100 or total_size > MAX_ASSET or member.size < 0
                    or path.is_absolute() or ".." in path.parts or "\\" in member.name
                    or not (member.isfile() or member.isdir())):
                raise ValueError("unsafe archive member or expansion budget exceeded")
            if member.isfile() and path.name == source["member"]:
                stream = handle.extractfile(member)
                if stream is None:
                    raise ValueError("unreadable JSONL member")
                found.append(stream.read(MAX_ASSET + 1))
    if len(found) != 1:
        raise ValueError(f"{source['id']}: expected exactly one declared JSONL member")
    records, seen = [], set()
    for line in found[0].decode("utf-8").splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        if not isinstance(raw, dict):
            raise ValueError("non-object sample")
        sid, text, label = raw.get("id"), raw.get(source["text_field"]), raw.get("label")
        if (not isinstance(sid, str) or not sid or sid in seen
                or not isinstance(text, str) or not text.strip()
                or len(text.encode()) > MAX_TEXT or "\0" in text
                or not isinstance(label, str) or label not in {"malicious", "benign"}):
            raise ValueError(f"{source['id']}: invalid, duplicate, or unlabelled sample")
        seen.add(sid)
        family = raw.get("source_family", "unspecified")
        if not isinstance(family, str) or not re.fullmatch(r"[\w-]{1,64}", family):
            family = "unspecified"
        # Directory names expose neither labels, source names nor upstream IDs.
        uid = digest((source["id"] + "\0" + sid).encode())
        records.append(dict(uid=uid, source=source["id"], role=source["role"],
                            text=text, label=label, family=family))
    if Counter(r["label"] for r in records) != Counter(source["expected_labels"]):
        raise ValueError(f"{source['id']}: frozen label counts changed; do not skip rows")
    return records


def normalize(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def origin_name(text: str) -> str:
    """Conservative origin grouping, separate from what the detector sees."""
    front = re.match(r"\A---\s*\n(.*?)\n---", text, re.S)
    name = re.search(r"(?m)^name:\s*([^\n]+)$", front[1]) if front else None
    return normalize(name[1].strip("\"' ")) if name else ""


def partition(records: list[dict], threshold: float = 0.85) -> tuple[list[dict], dict]:
    """Cluster BEFORE separation; quarantine validation relatives of dev cases.

    Exact duplicates are counted once per source. Near duplicates remain in the
    same cluster for uncertainty estimates. Conflicting exact labels fail closed.
    Do not interpret this conservative text/name grouping as perfect provenance.
    """
    if not 0.5 <= threshold <= 1 or not records:
        raise ValueError("invalid grouping policy or empty corpus")
    records = sorted((dict(r) for r in records), key=lambda r: r["uid"])
    exact_labels, representatives, retained = {}, set(), []
    excluded = Counter()
    for row in records:
        row["normalized"] = normalize(row["text"])
        key = digest(row["normalized"].encode())
        if key in exact_labels and exact_labels[key] != row["label"]:
            raise ValueError("conflicting labels on duplicate text; adjudication required")
        exact_labels[key] = row["label"]
        source_key = (row["source"], key)
        if source_key in representatives:
            excluded[f"{row['source']}:exact_duplicate"] += 1
            continue
        representatives.add(source_key)
        retained.append(row)
    parent = list(range(len(retained)))

    def root(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        parent[root(j)] = root(i)

    fingerprints, origins = [], []
    for row in retained:
        words = row["normalized"].split()
        fingerprints.append(set(zip(*(words[k:] for k in range(5))))
                            if len(words) >= 5 else {row["normalized"]})
        origins.append(origin_name(row["text"]))
    for i, left in enumerate(fingerprints):
        for j in range(i):
            right = fingerprints[j]
            same_origin = origins[i] and origins[i] == origins[j]
            if same_origin or (min(len(left), len(right)) >= threshold * max(len(left), len(right))
                               and len(left & right) / len(left | right) >= threshold):
                union(i, j)
    groups = defaultdict(list)
    for i, row in enumerate(retained):
        groups[root(i)].append(row)
    eligible = []
    for group in groups.values():
        gid = min(r["uid"] for r in group)
        touches_dev = any(r["role"] == "development" for r in group)
        for row in group:
            row.pop("normalized")
            row["group"] = gid
            if touches_dev and row["role"] != "development":
                excluded[f"{row['source']}:development_overlap"] += 1
            else:
                eligible.append(row)
    audit = {"input": dict(Counter(r["source"] for r in records)),
             "eligible": dict(Counter(r["source"] for r in eligible)),
             "excluded": dict(excluded), "groups": len({r["group"] for r in eligible}),
             "method": "NFKC+whitespace exact / 5-word Jaccard / declared frontmatter name"}
    return eligible, audit


def materialize(records: list[dict], root: Path) -> None:
    root.mkdir(parents=True, exist_ok=False)
    for row in records:
        directory = root / row["uid"]
        directory.mkdir()
        (directory / "SKILL.md").write_text(row["text"], encoding="utf-8")
        (directory / "SKILL.md").chmod(0o400)


def read_jsonl(path: Path, limit: int) -> dict[str, dict]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ASSET:
        raise ValueError("missing, unsafe, or oversized scanner report")
    rows = {}
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("invalid scanner row")
            sid = row.get("skill_id")
            if not isinstance(sid, str) or sid in rows or len(rows) >= limit:
                raise ValueError("duplicate, extra, or invalid scanner identity")
            rows[sid] = row
    return rows


def validate_output(output: Path, expected: set[str]) -> dict[str, str]:
    predictions = read_jsonl(output / "results.jsonl", len(expected))
    metadata = read_jsonl(output / "scan-metadata.jsonl", len(expected))
    if set(predictions) != expected or set(metadata) != expected:
        raise ValueError("scanner output coverage mismatch")
    if any(r.get("complete") is not True for r in metadata.values()):
        raise ValueError("incomplete scan: missingness must not improve metrics")
    if any(r.get("verdict") not in VERDICTS for r in predictions.values()):
        raise ValueError("invalid scanner verdict")
    return {sid: row["verdict"] for sid, row in predictions.items()}


def scan(image: str, skills: Path, expected: set[str]) -> tuple[dict[str, str], float]:
    name = "skillscan-eval-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="skillscan-output-") as tmp:
        output = Path(tmp)
        command = ["docker", "run", "--rm", "--name", name, "--network", "none",
                   "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                   "--cpus", "2", "--memory", "1g", "--pids-limit", "128",
                   "--user", f"{os.getuid()}:{os.getgid()}",
                   "--mount", f"type=bind,src={skills.resolve()},dst=/skills,readonly",
                   "--mount", f"type=bind,src={output},dst=/out", image, "/skills", "/out"]
        start = time.monotonic()
        try:
            result = subprocess.run(command, timeout=180, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, check=False)
            elapsed = time.monotonic() - start
            if result.returncode:
                raise ValueError(f"scanner failed (exit {result.returncode}); no partial acceptance")
            return validate_output(output, expected), elapsed
        finally:
            subprocess.run(["docker", "rm", "-f", name], timeout=30, check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wilson(success: int, total: int) -> list[float] | None:
    if not total:
        return None
    z = 1.959963984540054
    p = success / total
    scale = 1 + z * z / total
    center = (p + z * z / (2 * total)) / scale
    radius = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / scale
    return [max(0.0, center - radius), min(1.0, center + radius)]


def metrics(rows: list[dict], predictions: dict[str, str], screening=False) -> dict:
    tp = fp = tn = fn = 0
    for row in rows:
        positive = (predictions[row["uid"]] != "benign" if screening else
                    predictions[row["uid"]] == "malicious")
        actual = row["label"] == "malicious"
        tp += actual and positive
        fn += actual and not positive
        fp += not actual and positive
        tn += not actual and not positive
    div = lambda a, b: a / b if b else 0.0
    recall, specificity = div(tp, tp + fn), div(tn, tn + fp)
    return dict(n=len(rows), tp=tp, fp=fp, tn=tn, fn=fn,
                precision=div(tp, tp + fp), recall=recall,
                f1=div(2 * tp, 2 * tp + fp + fn), f2=div(5 * tp, 5 * tp + fp + 4 * fn),
                fpr=div(fp, fp + tn), specificity=specificity,
                accuracy=div(tp + tn, len(rows)), balanced_accuracy=(recall + specificity) / 2,
                mcc=div(tp * tn - fp * fn, math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))),
                recall_ci95=wilson(tp, tp + fn), fpr_ci95=wilson(fp, fp + tn))


def comparison(rows: list[dict], old: dict, new: dict) -> dict:
    comparisons = {}
    for source in sorted({r["source"] for r in rows}):
        subset = [r for r in rows if r["source"] == source]
        comparisons[source] = {"role": subset[0]["role"], "strict": {}, "screening": {}}
        for mode in ("strict", "screening"):
            comparisons[source][mode] = {
                "baseline": metrics(subset, old, mode == "screening"),
                "candidate": metrics(subset, new, mode == "screening")}
        comparisons[source]["families"] = {
            family: {"baseline": metrics([r for r in subset if r["family"] == family], old),
                     "candidate": metrics([r for r in subset if r["family"] == family], new)}
            for family in sorted({r["family"] for r in subset})}
    # Effective clusters, not individual related variants, for an exploratory sign test.
    deltas = defaultdict(int)
    for row in rows:
        if row["role"] != "development":
            actual = row["label"] == "malicious"
            deltas[row["group"]] += (int((new[row["uid"]] == "malicious") == actual)
                                     - int((old[row["uid"]] == "malicious") == actual))
    wins, losses = sum(d > 0 for d in deltas.values()), sum(d < 0 for d in deltas.values())
    n = wins + losses
    p = sum(math.comb(n, k) for k in range(wins, n + 1)) / 2 ** n if n else 1.0
    return {"sources": comparisons, "cluster_sign_test": {"wins": wins, "losses": losses,
            "one_sided_p": p, "exploratory_only": True}}


def gate(report: dict, expected_sources: set[str]) -> dict:
    reasons, improved = [], False
    if set(report["sources"]) != expected_sources:
        reasons.append("required source absent after decontamination")
    for source, item in report["sources"].items():
        base, candidate = item["strict"]["baseline"], item["strict"]["candidate"]
        if min(base["tp"] + base["fn"], base["tn"] + base["fp"]) < 10:
            reasons.append(f"{source}: fewer than 10 eligible examples in a class")
        for mode in ("strict", "screening"):
            old, new = item[mode]["baseline"], item[mode]["candidate"]
            if new["n"] != old["n"] or new["fp"] > old["fp"] or new["fn"] > old["fn"]:
                reasons.append(f"{source}/{mode}: false positives or false negatives increased")
        for family, result in item["families"].items():
            if any(result["candidate"][k] > result["baseline"][k] for k in ("fp", "fn")):
                reasons.append(f"{source}/{family}: subgroup regression")
        if item["role"] != "development":
            improved |= candidate["fp"] < base["fp"] or candidate["fn"] < base["fn"]
    timing = report["timing"]
    if (not all(math.isfinite(timing[k]) and timing[k] > 0 for k in ("baseline", "candidate"))
            or timing["candidate"] > timing["baseline"] * 1.20 + 0.15):
        reasons.append("median batch runtime exceeds 20% + 150ms allowance")
    return {"non_regression": not reasons, "proposal_ready": not reasons and improved,
            "reasons": reasons, "generalization_proven": False, "release_approved": False,
            "note": "Public reused regression cohorts cannot establish unseen-data generalization."}


def summary(report: dict) -> str:
    lines = ["# Continuous detection evaluation", "",
             "Public, previously evaluated corpora: regression evidence, NOT a sealed test.", "",
             f"Baseline: `{report['baseline_ref']}`; candidate: `{report['candidate_ref']}`.", "",
             "| Source | Version | N | TP/FP/TN/FN | Precision | Recall | F1 | F2 | FPR |",
             "|---|---|---:|---|---:|---:|---:|---:|---:|"]
    for source, item in report["sources"].items():
        for version, m in item["strict"].items():
            lines.append(f"| {source} | {version} | {m['n']} | "
                         + "/".join(str(m[k]) for k in ("tp", "fp", "tn", "fn")) + " | "
                         + " | ".join(f"{m[k]:.2%}" for k in ("precision", "recall", "f1", "f2", "fpr")) + " |")
    lines += ["", f"Gate: `{json.dumps(report['gate'], ensure_ascii=True)}`", "",
              f"Data audit: `{json.dumps(report['data_audit'], sort_keys=True)}`", "",
              "The JSON artifact also includes screening metrics, accuracy, balanced accuracy, MCC,",
              "specificity, marginal Wilson intervals, cluster sign-test diagnostics and timing.",
              "Wilson intervals assume independent observations and can be optimistic for related samples.",
              "Runtime is the median whole-batch wall time (including container startup), not per-Skill p95.",
              "No PR-AUC/ROC-AUC is claimed: the stable CLI supplies verdicts, not calibrated scores.",
              "No raw sample, malicious instruction, or per-case regression prediction is published.", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("evaluate", "prepare-dev"))
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline-image")
    parser.add_argument("--candidate-image")
    parser.add_argument("--baseline-ref", default="unspecified")
    parser.add_argument("--candidate-ref", default="unspecified")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    try:
        config_bytes = args.config.read_bytes()
        config = json.loads(config_bytes)
        sources = config["sources"]
        if args.command == "prepare-dev":
            sources = [s for s in sources if s["role"] == "development"]
        raw = [row for source in sources for row in read_source(source, download(source, args.cache))]
        rows, audit = partition(raw, config["near_duplicate_jaccard"])
        if args.command == "prepare-dev":
            materialize(rows, args.output / "skills")
            write_json(args.output / "labels.json", [{k: v for k, v in r.items() if k != "text"} for r in rows])
            write_json(args.output / "audit.json", audit)
            return 0
        if not args.baseline_image or not args.candidate_image:
            raise ValueError("both scanner images are required")
        predictions, timings = {}, defaultdict(list)
        with tempfile.TemporaryDirectory(prefix="skillscan-input-") as tmp:
            skills = Path(tmp) / "skills"
            materialize(rows, skills)
            expected = {r["uid"] for r in rows}
            # Warm both images; alternate order to reduce cache/order bias.
            for version, image in (("baseline", args.baseline_image), ("candidate", args.candidate_image)):
                predictions[version], _ = scan(image, skills, expected)
            for repeat in range(3):
                order = ["baseline", "candidate"] if repeat % 2 == 0 else ["candidate", "baseline"]
                for version in order:
                    image = args.baseline_image if version == "baseline" else args.candidate_image
                    result, elapsed = scan(image, skills, expected)
                    if result != predictions[version]:
                        raise ValueError("nondeterministic scanner predictions")
                    timings[version].append(elapsed)
        report = comparison(rows, predictions["baseline"], predictions["candidate"])
        report.update(schema_version=1, evaluated_at=datetime.now(timezone.utc).isoformat(), config_sha256=digest(config_bytes), data_audit=audit,
                      baseline_ref=args.baseline_ref, candidate_ref=args.candidate_ref,
                      data_sources=sources, timing={k: statistics.median(v) for k, v in timings.items()},
                      timing_repeats=dict(timings))
        report["gate"] = gate(report, {s["id"] for s in sources})
        write_json(args.output / "report.json", report)
        (args.output / "summary.md").write_text(summary(report))
        return 0 if report["gate"]["non_regression"] else 1
    except (ValueError, KeyError, TypeError, OSError, tarfile.TarError,
            subprocess.SubprocessError) as error:
        # Exception text is deliberately not echoed: it may contain sample data.
        failure = {"status": "failed_closed", "error_type": type(error).__name__}
        if type(error) is ValueError:
            failure["reason"] = str(error)  # Only harness-authored messages, never decoder payloads.
        write_json(args.output / "failure.json", failure)
        (args.output / "summary.md").write_text("# Evaluation failed closed\n\n"
            "An input, integrity, scanner, or resource check failed. No candidate is approved.\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
