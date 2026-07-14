# Release process

Only a release maintainer may perform these steps. Releases are built from a
clean, annotated, cryptographically signed tag. The GitHub workflow verifies the
tag through GitHub's tag-verification API before it builds or publishes anything.

## Prepare

1. Choose a semantic version `vMAJOR.MINOR.PATCH` and create
   `docs/releases/<version>.md` from the previous notes.
2. Move completed `Unreleased` entries in `CHANGELOG.md` under the version and
   date. Update the README beta/version banner if necessary.
3. Review `docs/SUPPORT.md`, `docs/KNOWN_LIMITATIONS.md`, and
   `docs/MIGRATIONS.md`. State every schema change and required re-ingestion or
   detection rebuild in the versioned notes.
4. Import `demo/synthetic-case/synthetic-defender.jsonl` and complete its smoke
   procedure.
5. From a clean checkout, run backend tests, Ruff, frontend build, dependency
   audits, CodeQL/CI, and the local release build.

```powershell
python .github/scripts/sync_labels.py --check
cd backend
python -m unittest discover -s tests -v
ruff check app tests
cd ..\frontend
npm ci
npm run build
cd ..
$env:SOURCE_DATE_EPOCH = git show -s --format=%ct HEAD
python scripts/build_release.py --version v0.1.1 --output dist
```

Build twice into separate output directories and compare the ZIP and SBOM
SHA-256 values. A difference blocks release.

## Sign and push the tag

Use a GitHub-verified GPG or SSH signing key. Confirm `git tag -v` succeeds in
your configured environment before pushing.

```powershell
$version = "v0.1.1"
git status --short                 # must print nothing
git tag -s $version -m "Investigator $version"
git tag -v $version
git push origin $version
```

Never move, replace, or force-push a published tag. If a tag or release is
incorrect, document the problem, withdraw the GitHub release if necessary, and
publish a new patch version.

Pushing a matching tag starts `.github/workflows/release.yml`. The workflow:

1. requires an annotated tag whose GitHub `verification.verified` value is true;
2. requires `docs/releases/<tag>.md`;
3. installs locked dependencies and runs backend tests and the frontend build on
   Windows;
4. builds the archive twice and proves byte-for-byte reproducibility;
5. generates a CycloneDX SBOM and `SHA256SUMS.txt`; and
6. publishes a GitHub release using the versioned notes.

## Verify published assets

Download every asset into an empty directory and run:

```powershell
Get-Content SHA256SUMS.txt | ForEach-Object {
    $expected, $name = $_ -split "  ", 2
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $name).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "Checksum mismatch: $name" }
}
git fetch --tags origin
git tag -v v0.1.1
```

Also verify that the GitHub release shows a verified tag, the SBOM parses as
JSON and lists Python and npm components, the ZIP starts on Windows 11 with Node
absent, and the synthetic case imports nine events.

Record any release deviation in the notes. Do not manually replace one asset
without issuing a new version because checksums, SBOM, notes, tag, and archive
form one immutable release set.
