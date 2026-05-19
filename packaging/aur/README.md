# Arch Linux AUR packaging

This directory holds the upstream-mirrored PKGBUILDs for Pentest Swarm AI's
Arch User Repository submissions. The actual AUR git repo is the canonical
location once submitted; this in-tree copy is so changes can be reviewed via
GitHub PRs before being pushed to AUR.

## Packages

- **`pentestswarm-bin/`** — Binary release. Fetches the pre-built Linux
  binaries from the upstream GitHub release. Fast install, no Go toolchain
  required. Recommended for most users. Lives at:
  https://aur.archlinux.org/packages/pentestswarm-bin

- *Future: `pentestswarm/`* — Source-build variant. Builds from upstream
  Go source via `go build`. Useful for users who want to verify against
  source or run on architectures we don't ship binaries for. Not yet shipped.

## How to install (end users)

With an AUR helper (recommended):

```bash
yay -S pentestswarm-bin
# or
paru -S pentestswarm-bin
```

Manually with `makepkg`:

```bash
git clone https://aur.archlinux.org/pentestswarm-bin.git
cd pentestswarm-bin
makepkg -si
```

## How to submit / update (maintainer)

**One-time setup** (per maintainer):

1. Register an account at https://aur.archlinux.org
2. Add your SSH public key in your AUR account settings
3. Verify SSH access: `ssh aur@aur.archlinux.org help`

**First-time submission of a new package:**

```bash
# Clone the AUR repo (will be empty for a new package)
git clone ssh://aur@aur.archlinux.org/pentestswarm-bin.git /tmp/aur-pentestswarm-bin
cd /tmp/aur-pentestswarm-bin

# Copy the PKGBUILD + .SRCINFO from the upstream repo
cp /path/to/Pentest-Swarm-AI/packaging/aur/pentestswarm-bin/PKGBUILD .
cp /path/to/Pentest-Swarm-AI/packaging/aur/pentestswarm-bin/.SRCINFO .

# Test the build locally (requires Arch / makepkg)
makepkg -si --noconfirm

# Commit + push to AUR
git add PKGBUILD .SRCINFO
git commit -m "Initial submission: pentestswarm-bin v0.1.0"
git push origin master
```

**Updating on a new upstream release:**

```bash
cd /tmp/aur-pentestswarm-bin

# Update PKGBUILD (bump pkgver, reset pkgrel to 1, refresh sha256sums)
# — easiest to copy the new version from upstream's packaging/aur/ dir
cp /path/to/Pentest-Swarm-AI/packaging/aur/pentestswarm-bin/PKGBUILD .

# Regenerate .SRCINFO from PKGBUILD
makepkg --printsrcinfo > .SRCINFO

# Test the build
makepkg -si --noconfirm

# Ship it
git add PKGBUILD .SRCINFO
git commit -m "Update to v$(grep pkgver PKGBUILD | head -1 | cut -d= -f2)"
git push origin master
```

**Future automation** (tracked as a follow-up): a GitHub Action in this repo
that runs on every release tag, regenerates the PKGBUILD with the new
`pkgver` and `sha256sums`, and pushes to AUR via a deploy key. Same pattern
as the `homebrew-tap`'s `update-formula.yml`. Once in place, AUR updates
become hands-off.

## Verifying sha256sums

Each upstream release publishes a `checksums.txt` alongside the binaries:

```bash
curl -sSL https://github.com/Armur-Ai/Pentest-Swarm-AI/releases/download/v0.1.0/checksums.txt
```

The values in PKGBUILD's `sha256sums_x86_64` and `sha256sums_aarch64` must
match the corresponding lines in `checksums.txt`. A mismatch means either
the release was tampered with or the PKGBUILD is stale — either way, stop
and investigate before submitting.

## Why `pentestswarm-bin` instead of `pentestswarm`?

Arch packaging convention: `-bin` suffix signals "pre-built binary, not
compiled from source." The source-build variant (`pentestswarm`, plain)
would compile from Go source via `go build` and is a separate package
shipped later. Until then, the `-bin` variant uses `provides=('pentestswarm')`
and `conflicts=('pentestswarm')` so the eventual source package can replace
it cleanly.
