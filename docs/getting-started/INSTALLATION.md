---
title: "Installation"
description: "Install QPKI - Download binaries, Homebrew, or build from source"
---

## Requirements

- **Go 1.25** or later (only for building from source)
- No CGO required for standard usage
- CGO required only for HSM/PKCS#11 support (optional)
- No external dependencies (OpenSSL not required)

## Download pre-built binaries (recommended)

Download the latest release for your platform from [GitHub Releases](https://github.com/qentriq/qpki/releases/latest).

**Linux / macOS:**
```bash
# Download (replace VERSION, OS, and ARCH as needed)
curl -LO https://github.com/qentriq/qpki/releases/latest/download/qpki_VERSION_OS_ARCH.tar.gz

# Extract
tar -xzf qpki_*.tar.gz

# Install
sudo mv qpki /usr/local/bin/

# Verify
qpki --version
```

**Available platforms:**

| OS | Architecture | File |
|----|--------------|------|
| Linux | amd64 | `qpki_VERSION_linux_amd64.tar.gz` |
| Linux | arm64 | `qpki_VERSION_linux_arm64.tar.gz` |
| macOS | Intel | `qpki_VERSION_darwin_amd64.tar.gz` |
| macOS | Apple Silicon | `qpki_VERSION_darwin_arm64.tar.gz` |
| macOS | Universal | `qpki_VERSION_darwin_all.tar.gz` |
| Windows | amd64 | `qpki_VERSION_windows_amd64.zip` |

**Linux packages:**
```bash
# Debian/Ubuntu
sudo dpkg -i qpki_VERSION_linux_amd64.deb

# RHEL/Fedora
sudo rpm -i qpki_VERSION_linux_amd64.rpm
```

## Install via Homebrew (macOS)

```bash
brew tap qentriq/qpki
brew install qpki
```

## Build from source

Requires Go 1.25 or later.

```bash
# Clone and build
git clone https://github.com/qentriq/qpki.git
cd qpki
go build -o qpki ./cmd/qpki

# Or install directly to GOPATH/bin
go install github.com/qentriq/qpki/cmd/qpki@latest
```

## Verify installation

```bash
qpki version
qpki --help
```

## Verify release signatures

All releases are signed with GPG. To verify:

```bash
# Import public key
gpg --keyserver keyserver.ubuntu.com --recv-keys 39CD0BF9647E3F56

# Download checksums and signature
curl -LO https://github.com/qentriq/qpki/releases/download/vX.Y.Z/checksums.txt
curl -LO https://github.com/qentriq/qpki/releases/download/vX.Y.Z/checksums.txt.sig

# Verify signature
gpg --verify checksums.txt.sig checksums.txt
```

## Next steps

Once installed, continue with the [Quick Start](/qpki/getting-started/quick-start/) guide to create your first certificate authority.
