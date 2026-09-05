# OpenClaw Community Hotfixes

A minimal, public-ready patch set for selected OpenClaw fixes. This repository contains only canonical `git-format-patch` files, their manifest, validation tests, and release automation.

## Patch set

Apply the patches in manifest order from base commit `bd2a91dac35a4975eb8b544f95cefa32bf4229a1`:

1. `3c91576a14` — avoid a full memory reindex retry storm on a revision race.
2. `1093a13d6d` — keep memory searches read-only and reusable. This depends on patch 1.
3. `f4a81adcdd` — preserve Codex stateless policy through provider aliases. Its changed files are independent of patches 1–2, but the published sequence remains the fully verified order above.

Canonical patch author metadata is retained by `git format-patch`.

## Validate

```bash
python3 scripts/validate.py
python3 -m unittest discover -s tests -v
```

To additionally prove byte-for-byte provenance and ordered application against a local OpenClaw checkout:

```bash
python3 scripts/validate.py --upstream /path/to/openclaw
```

The validator is fail-closed: it rejects every path not in its exact repository allowlist, symlinks, oversized or non-UTF-8 files, manifest drift, patch hash/header/path drift, and common credential or private-path signatures.

## Apply

```bash
git checkout bd2a91dac35a4975eb8b544f95cefa32bf4229a1
git am /path/to/openclaw-community-hotfixes/patches/*.patch
```

Use a disposable branch and run OpenClaw's own relevant test suites before deployment.

## CI and releases

Every push and pull request runs validation and negative tests. A `v*` tag additionally creates a GitHub Release containing a `git archive` tarball and `SHA256SUMS`. Tagging therefore performs publication and should be restricted by repository permissions.

No remote repository is configured or created by this local setup.
