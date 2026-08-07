# Installation & Development Setup

This guide covers everything needed to build, test, and develop `cloudformation-validate` from source, plus how to
download and verify signed release artifacts.

Pinned tool versions live in [`.github/workflows/configs.yml`](.github/workflows/configs.yml) and
[`src/rust-toolchain.toml`](src/rust-toolchain.toml). The versions below match CI - staying on them avoids
environment drift.

## Required tools

| Tool                            | Version | Required for                                              | Notes                                                                                                           |
|---------------------------------|---------|-----------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| Rust (`cargo`, `rustc`)         | 1.96.0  | everything                                                | Pinned by `src/rust-toolchain.toml`; rustup installs it for you                                                 |
| `rustfmt`                       | bundled | `cargo fmt` lint                                          | Declared as a component in the toolchain file                                                                   |
| `wasm32-unknown-unknown` target | bundled | WASM binding                                              | Added automatically by the toolchain file                                                                       |
| `wasm-pack`                     | 0.15.0  | WASM binding build/test                                   | `cargo install`                                                                                                 |
| `cargo-about`                   | 0.9.1   | third-party license generation (Build Artifacts workflow) | `cargo install`                                                                                                 |
| `cargo-audit`                   | 0.22.2  | dependency vulnerability audit                            | `cargo install`                                                                                                 |
| Node.js + npm                   | 22.x    | WASM binding build/test                                   | `npm` ships with Node                                                                                           |
| JDK                             | 21+     | JVM binding build/test                                    | Corretto in CI; provides `java` and `jar`                                                                       |
| Kotlin (`kotlinc`)              | 2.4.0   | JVM binding build                                         |                                                                                                                 |
| `ktlint`                        | 1.8.0   | JVM binding formatting                                    |                                                                                                                 |
| Gradle                          | 9.6.1   | JVM binding build/test                                    | Must be on `PATH` — `bindings-jvm/build.sh` and the JVM test runner invoke `gradle`                             |
| Python                          | 3.12+   | Python binding build/test, license generation, `scripts/` | `setuptools` for the wheel build; no other packages required                                                    |
| Go                              | 1.26+   | Go binding build/test                                     | cgo must be enabled (default); Windows also needs `rustup target add x86_64-pc-windows-gnu` and MinGW-w64 `gcc` |
| `uniffi-bindgen-go`             | 0.7.1   | Go binding generation                                     | `cargo install --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.7.1+v0.31.0`                    |
| `git`, `curl`, `openssl`        | —       | source control, fetching JVM deps, verifying releases     | Usually preinstalled                                                                                            |

## 1. Rust toolchain

```bash
# Install rustup (provides cargo + rustc)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

`src/rust-toolchain.toml` pins the channel to `1.96.0` and declares the `rustfmt` component and the
`wasm32-unknown-unknown` target. rustup installs the correct toolchain, component, and target automatically the first
time you run a cargo command inside `src/`.

## 2. Cargo tools

```bash
cargo install cargo-about@0.9.1 cargo-audit@0.22.2 wasm-pack@0.15.0
```

## 3. Node.js (Node/WASM binding)

Install Node.js 22.x - any version manager works:

```bash
# macOS (Homebrew)
brew install node@22

# or via nvm (any platform)
nvm install 22 && nvm use 22
```

## 4. JVM toolchain (JVM binding)

Install a JDK (21+), the Kotlin compiler, ktlint, and Gradle.

```bash
# macOS (Homebrew) - installs current releases
brew install openjdk@21 kotlin ktlint gradle
```

To match CI versions exactly (recommended for the JVM binding), use SDKMAN for the JVM tools:

```bash
curl -s "https://get.sdkman.io" | bash && source "$HOME/.sdkman/bin/sdkman-init.sh"
sdk install java 21-amzn        # Amazon Corretto 21 (pick a 21.x build from `sdk list java`)
sdk install kotlin 2.4.0
sdk install gradle 9.6.1

# ktlint 1.8.0 (pinned release binary)
curl -sSLO https://github.com/pinterest/ktlint/releases/download/1.8.0/ktlint \
  && chmod +x ktlint && sudo mv ktlint /usr/local/bin/
```

## 5. Python (Python binding, license generation & helper scripts)

Python 3.12+ is required for the Python binding build (`bindings-python/build.sh`, which needs `setuptools` for the
wheel), for `scripts/generate_licenses.py` (invoked by the Build Artifacts workflow), and for the other developer
scripts under `scripts/`. The binding build itself needs only `setuptools`; the test runner
(`bindings-python/tests/run.sh`) additionally fetches `coverage` into a throwaway virtualenv, so running the Python
tests needs network access.

## Build

Run cargo commands from the `src/` directory.

```bash
cd src

# Build the entire workspace (debug)
cargo build

# Published CLI binary -> release-bin/cfn-validate-<os>-<arch> (repository root)
./cfn-validate/build.sh

# WASM binding (Node.js) -> bindings-wasm/dist/
./bindings-wasm/build.sh

# JVM binding (Kotlin/Java) -> bindings-jvm/generated/cloudformation-validate.jar
./bindings-jvm/build.sh

# Python binding -> bindings-python/generated/dist/*.whl
./bindings-python/build.sh

# Go binding -> bindings-go/go/ (generated FFI package + static library)
./bindings-go/build.sh
```

## Download and verify release artifacts

Each GitHub release attaches the prebuilt artifacts as signed assets (`<version>` is the release tag, e.g. `1.6.0`):

- `cloudformation-validate-<version>.jar` - the JVM (Kotlin/Java) binding
- `cloudformation-validate-wasm-<version>.zip` - the Node.js (WASM) binding
- `cloudformation_validate-<version>-py3-none-<platform>.whl` - the Python binding, with one wheel per supported
  native target so installers download only the compatible library; a `-beta` release ships as `<version>b0`
- `cloudformation-validate-go-<version>.zip` - the Go module, carrying every supported platform's static library
- `cfn-validate-<version>-<os>-<arch>` - the CLI binary, one per supported platform (e.g.
  `cfn-validate-1.6.0-linux-x64`, `cfn-validate-1.6.0-darwin-aarch64`)

Alongside each artifact are a detached signature (`<artifact>.sig`), the public key (`signing-key.pem`), and the key's
SHA-256 fingerprint (`signing-key.pem.sha256`). Artifacts are signed with an AWS KMS RSA key
(`RSASSA_PKCS1_V1_5_SHA_256`).

Download the artifact you want, its `.sig`, and `signing-key.pem` from the same release, then verify the signature:

```bash
openssl dgst -sha256 -verify signing-key.pem -signature <artifact>.sig <artifact>
# e.g. openssl dgst -sha256 -verify signing-key.pem -signature cloudformation-validate-wasm-1.6.0.zip.sig cloudformation-validate-wasm-1.6.0.zip
```

A valid artifact prints `Verified OK`. Any other output means verification failed - do not use the artifact.

Optionally, confirm the bundled key is the real signing key by matching its fingerprint against one you trust:

```bash
openssl pkey -pubin -in signing-key.pem -outform DER | openssl dgst -sha256
cat signing-key.pem.sha256
```

The two values must match.
