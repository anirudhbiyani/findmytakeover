# Publishing

Releases are **tag-free**. The package version lives in `pyproject.toml`, and
`.github/workflows/publish.yml` decides what to publish from the event:

| Event | Version built | Published to |
| --- | --- | --- |
| Push to `main` | `pyproject.toml` version (e.g. `1.0.0`) | **PyPI** (GA) |
| Pull request (same repo, opened/updated) | `<version>.dev<run_number>` | **TestPyPI** (pre-release) |

Fork PRs are skipped — they can't obtain an OIDC token. GA publishes use
`skip-existing`, so merging to `main` without changing the version is a no-op
rather than a failure.

## Cutting a GA release

No tags, no manual upload:

1. Bump `version` in `pyproject.toml` (e.g. `1.0.0` → `1.0.1`).
2. Merge to `main`.

The push to `main` builds that version and publishes it to PyPI. To release
again, bump the version again and merge again.

## Dev builds

Every push to an open PR (from a branch in this repo) publishes
`<version>.dev<run_number>` to TestPyPI automatically — nothing to do. Install
one for testing (deps come from real PyPI, since TestPyPI doesn't mirror them):

```bash
pip install --pre \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  findmytakeover
```

## One-time setup (required before the first publish)

Uses [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC)
— no API tokens or secrets stored in the repo.

1. **GitHub environments** — create both (repo → Settings → Environments):
   - `pypi`
   - `testpypi`

2. **PyPI trusted publisher** — on <https://pypi.org> → Account → Publishing →
   *Add a pending publisher*:
   - PyPI project name: `findmytakeover`
   - Owner: `anirudhbiyani`
   - Repository name: `findmytakeover`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`

3. **TestPyPI trusted publisher** — repeat on <https://test.pypi.org> with the
   same values but **Environment name: `testpypi`**.

"Pending publisher" is the right choice while the projects don't exist yet; the
project is created automatically on first successful publish.
