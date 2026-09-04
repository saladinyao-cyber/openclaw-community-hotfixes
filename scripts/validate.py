#!/usr/bin/env python3
"""Fail-closed validation for the OpenClaw community hotfix repository."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile

ALLOWED_FILES = {
    ".github/workflows/validate-and-release.yml",
    "README.md",
    "manifest.json",
    "patches/0001-memory-core-avoid-full-retry-storm.patch",
    "patches/0002-memory-keep-searches-read-only.patch",
    "patches/0003-ai-preserve-codex-stateless-aliases.patch",
    "scripts/validate.py",
    "tests/test_validate.py",
}
PATCH_FILES = [
    "patches/0001-memory-core-avoid-full-retry-storm.patch",
    "patches/0002-memory-keep-searches-read-only.patch",
    "patches/0003-ai-preserve-codex-stateless-aliases.patch",
]
MAX_FILE_BYTES = 1_000_000
SENSITIVE_PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "bearer credential": re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    "assigned credential": re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\b\s*[:=]\s*['\"]?[A-Za-z0-9._~+/=-]{12,}"
    ),
    "private home path": re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+/"),
    "OpenClaw private state path": re.compile(r"(?:^|[/'\"])\.openclaw(?:/|[/'\"])", re.MULTILINE),
}
PATCH_FROM_RE = re.compile(rb"\AFrom ([0-9a-f]{40}) Mon Sep 17 00:00:00 2001\n")
PATCH_PATH_RE = re.compile(r"^diff --git a/(.+) b/(.+)$", re.MULTILINE)


class ValidationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ValidationError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def repository_files(root: Path) -> set[str]:
    found: set[str] = set()
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not (Path(current) == root and d == ".git"))
        for name in sorted(files):
            path = Path(current) / name
            rel = path.relative_to(root).as_posix()
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                fail(f"symlink forbidden: {rel}")
            if not stat.S_ISREG(mode):
                fail(f"non-regular file forbidden: {rel}")
            found.add(rel)
    return found


def read_text_checked(root: Path, rel: str) -> tuple[bytes, str]:
    path = root / rel
    data = path.read_bytes()
    if len(data) > MAX_FILE_BYTES:
        fail(f"file exceeds {MAX_FILE_BYTES} bytes: {rel}")
    if b"\0" in data:
        fail(f"NUL byte forbidden: {rel}")
    try:
        return data, data.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"non-UTF-8 file forbidden: {rel}: {exc}")


def validate_sensitive(rel: str, text: str) -> None:
    for label, pattern in SENSITIVE_PATTERNS.items():
        match = pattern.search(text)
        if match:
            line = text.count("\n", 0, match.start()) + 1
            fail(f"sensitive signature ({label}) in {rel}:{line}")


def validate_manifest(root: Path) -> dict:
    try:
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"invalid manifest: {exc}")
    if set(manifest) != {"schema_version", "upstream", "application_base", "application_order", "patches"}:
        fail("manifest top-level keys drifted")
    if manifest["schema_version"] != 1:
        fail("unsupported manifest schema")
    if manifest["upstream"] != "https://github.com/openclaw/openclaw.git":
        fail("unexpected upstream")
    if not re.fullmatch(r"[0-9a-f]{40}", manifest["application_base"]):
        fail("application_base must be a full commit hash")
    if manifest["application_order"] != PATCH_FILES:
        fail("application_order must match the fixed patch allowlist")
    patches = manifest["patches"]
    if not isinstance(patches, list) or len(patches) != len(PATCH_FILES):
        fail("manifest must contain exactly three patch records")
    commits: list[str] = []
    for expected_order, (expected_file, record) in enumerate(zip(PATCH_FILES, patches), start=1):
        required = {"order", "file", "commit", "original_parent", "subject", "depends_on", "sha256", "touched_paths"}
        if not isinstance(record, dict) or set(record) != required:
            fail(f"patch record {expected_order} keys drifted")
        if record["order"] != expected_order or record["file"] != expected_file:
            fail(f"patch record {expected_order} order/file mismatch")
        for key in ("commit", "original_parent", "sha256"):
            width = 64 if key == "sha256" else 40
            if not isinstance(record[key], str) or not re.fullmatch(rf"[0-9a-f]{{{width}}}", record[key]):
                fail(f"invalid {key} in patch record {expected_order}")
        if not isinstance(record["subject"], str) or not record["subject"].strip():
            fail(f"missing subject in patch record {expected_order}")
        if not isinstance(record["depends_on"], list) or any(dep not in commits for dep in record["depends_on"]):
            fail(f"dependency must reference an earlier manifest commit in record {expected_order}")
        touched = record["touched_paths"]
        if not isinstance(touched, list) or not touched or touched != sorted(set(touched)):
            fail(f"touched_paths must be non-empty, unique, and sorted in record {expected_order}")
        for item in touched:
            pure = PurePosixPath(item)
            if pure.is_absolute() or ".." in pure.parts or item.startswith("."):
                fail(f"unsafe touched path in record {expected_order}: {item}")
        commits.append(record["commit"])
    return manifest


def validate_patches(root: Path, manifest: dict) -> None:
    for record in manifest["patches"]:
        rel = record["file"]
        data, text = read_text_checked(root, rel)
        if sha256(data) != record["sha256"]:
            fail(f"SHA-256 mismatch: {rel}")
        match = PATCH_FROM_RE.match(data)
        if not match or match.group(1).decode() != record["commit"]:
            fail(f"canonical From header mismatch: {rel}")
        subject_match = re.search(r"^Subject: (.+(?:\n[ \t].+)*)$", text, re.MULTILINE)
        if not subject_match:
            fail(f"subject header missing: {rel}")
        unfolded_subject = re.sub(r"\n[ \t]+", " ", subject_match.group(1))
        if unfolded_subject != f"[PATCH] {record['subject']}":
            fail(f"subject mismatch: {rel}")
        changed: set[str] = set()
        for left, right in PATCH_PATH_RE.findall(text):
            if left != right:
                fail(f"rename/copy patch paths are not allowed: {rel}: {left} -> {right}")
            pure = PurePosixPath(left)
            if pure.is_absolute() or ".." in pure.parts:
                fail(f"unsafe patch path: {rel}: {left}")
            changed.add(left)
        if sorted(changed) != record["touched_paths"]:
            fail(f"touched path mismatch: {rel}")
        if "GIT binary patch" in text or "Binary files " in text:
            fail(f"binary patch forbidden: {rel}")


def run_git(repo: Path, *args: str, input_data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        fail(f"git {' '.join(args)} failed: {detail}")
    return result


def validate_upstream(root: Path, upstream: Path, manifest: dict) -> None:
    if run_git(upstream, "rev-parse", "--is-inside-work-tree").stdout.strip() != b"true":
        fail(f"not a Git worktree: {upstream}")
    for record in manifest["patches"]:
        commit = record["commit"]
        run_git(upstream, "cat-file", "-e", f"{commit}^{{commit}}")
        parent = run_git(upstream, "rev-parse", f"{commit}^").stdout.decode().strip()
        if parent != record["original_parent"]:
            fail(f"original parent mismatch for {commit}")
        generated = run_git(upstream, "format-patch", "-1", "--stdout", commit).stdout
        stored = (root / record["file"]).read_bytes()
        if generated != stored:
            fail(f"format-patch provenance mismatch for {commit}")
    with tempfile.TemporaryDirectory(prefix="openclaw-hotfix-verify-") as temp:
        worktree = Path(temp) / "worktree"
        run_git(upstream, "worktree", "add", "--detach", str(worktree), manifest["application_base"])
        try:
            for record in manifest["patches"]:
                patch = (root / record["file"]).read_bytes()
                run_git(worktree, "apply", "--check", "-", input_data=patch)
                run_git(worktree, "apply", "-", input_data=patch)
        finally:
            run_git(upstream, "worktree", "remove", "--force", str(worktree))


def validate(root: Path, upstream: Path | None = None) -> None:
    root = root.resolve()
    actual = repository_files(root)
    unknown = sorted(actual - ALLOWED_FILES)
    missing = sorted(ALLOWED_FILES - actual)
    if unknown or missing:
        fail(f"repository allowlist mismatch; unknown={unknown}, missing={missing}")
    decoded: dict[str, str] = {}
    for rel in sorted(actual):
        _, text = read_text_checked(root, rel)
        decoded[rel] = text
    for rel, text in decoded.items():
        validate_sensitive(rel, text)
    manifest = validate_manifest(root)
    validate_patches(root, manifest)
    if upstream is not None:
        validate_upstream(root, upstream.resolve(), manifest)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--upstream", type=Path)
    args = parser.parse_args()
    try:
        validate(args.root, args.upstream)
    except ValidationError as exc:
        print(f"FAIL: {exc}")
        return 1
    print("PASS: repository allowlist, sensitive scan, manifest, and patches")
    if args.upstream:
        print("PASS: canonical provenance and ordered upstream application")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
