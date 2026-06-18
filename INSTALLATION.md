# Installation & Development Setup

This guide covers everything needed to build, test, and develop `cloudformation-validate` from source, plus how to
download and verify signed release artifacts.

Pinned tool versions live in [`.github/workflows/configs.yml`](.github/workflows/configs.yml) and
[`src/rust-toolchain.toml`](src/rust-toolchain.toml). The versions below match CI — staying on them avoids
environment drift.

## Required tools

| Tool                            | Version | Required for                                              | Notes                                                           |
|---------------------------------|---------|-----------------------------------------------------------|-----------------------------------------------------------------|
| Rust (`cargo`, `rustc`)         | 1.96.0  | everything                                                | Pinned by `src/rust-toolchain.toml`; rustup installs it for you |
| `rustfmt`                       | bundled | `cargo fmt` lint                                          | Declared as a component in the toolchain file                   |
| `wasm32-unknown-unknown` target | bundled | WASM binding                                              | Added automatically by the toolchain file                       |
| `wasm-pack`                     | 0.14.0  | WASM binding build/test                                   | `cargo install`                                                 |
| `cargo-about`                   | 0.9.0   | third-party license generation (Build Artifacts workflow) | `cargo install`                                                 |
| `cargo-audit`                   | 0.22.2  | dependency vulnerability audit                            | `cargo install`                                                 |
| Node.js + npm                   | 22.x    | WASM binding build/test                                   | `npm` ships with Node                                           |
| JDK                             | 21+     | JVM binding build/test                                    | Corretto in CI; provides `java` and `jar`                       |
| Kotlin (`kotlinc`)              | 2.3.10  | JVM binding build                                         |                                                                 |
| `ktlint`                        | 1.8.0   | JVM binding formatting                                    |                                                                 |
| Gradle                          | 8.14    | JVM binding tests                                         | Must be on `PATH` — the JVM test runner invokes `gradle`        |
| Python                          | 3.10+   | license generation + `scripts/` helpers                   | No third-party packages required                                |
| `git`, `curl`, `openssl`        | —       | source control, fetching JVM deps, verifying releases     | Usually preinstalled                                            |

JNA (`5.18.1`) and Gson (`2.14.0`) — the JVM binding's runtime dependencies — are downloaded automatically from Maven
Central by `bindings-jvm/build.sh`; you do not install them yourself. The `uniffi-bindgen` tool used to generate the
Kotlin bindings is built from the workspace as part of the JVM binding build.

## 1. Rust toolchain

```bash
# Install rustup (provides cargo + rustc)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

`src/rust-toolchain.toml` pins the channel to `1.93.1` and declares the `rustfmt` component and the
`wasm32-unknown-unknown` target. rustup installs the correct toolchain, component, and target automatically the first
time you run a cargo command inside `src/`.

## 2. Cargo tools

```bash
cargo install cargo-about@0.9.0 cargo-audit@0.22.2 wasm-pack@0.14.0
```

## 3. Node.js (Node/WASM binding)

Install Node.js 22.x — any version manager works:

```bash
# macOS (Homebrew)
brew install node@22

# or via nvm (any platform)
nvm install 22 && nvm use 22
```

## 4. JVM toolchain (JVM binding)

Install a JDK (21+), the Kotlin compiler, ktlint, and Gradle.

```bash
# macOS (Homebrew) — installs current releases
brew install openjdk@21 kotlin ktlint gradle
```

To match CI versions exactly (recommended for the JVM binding), use SDKMAN for the JVM tools:

```bash
curl -s "https://get.sdkman.io" | bash && source "$HOME/.sdkman/bin/sdkman-init.sh"
sdk install java 21-amzn        # Amazon Corretto 21 (pick a 21.x build from `sdk list java`)
sdk install kotlin 2.3.10
sdk install gradle 8.14

# ktlint 1.8.0 (pinned release binary)
curl -sSLO https://github.com/pinterest/ktlint/releases/download/1.8.0/ktlint \
  && chmod +x ktlint && sudo mv ktlint /usr/local/bin/
```

## 5. Python (license generation & helper scripts)

Python 3.10+ is required for `scripts/generate_licenses.py` (invoked by the Build Artifacts workflow) and the other
developer scripts under `scripts/`. No third-party packages are needed.

## Build

Run cargo commands from the `src/` directory.

```bash
cd src

# Build the entire workspace (debug)
cargo build

# CLI binary -> target/debug/cfn-validate
cargo build -p cfn-validate
# add --release for an optimized binary at target/release/cfn-validate

# CLI release binary -> release/cfn-validate-<os>-<arch>
./cfn-validate/build.sh

# WASM binding (Node.js) -> bindings-wasm/dist/
./bindings-wasm/build.sh

# JVM binding (Kotlin/Java) -> bindings-jvm/generated/cloudformation-validate.jar
./bindings-jvm/build.sh
```

Note: `THIRD-PARTY-LICENSES.txt` is generated by the Build Artifacts workflow, not by `build.sh`. To refresh it
locally, run `python3 scripts/generate_licenses.py`.

## Test

These commands mirror CI. Run them from the `src/` directory.

```bash
cd src

# Format check (must pass clean)
cargo fmt --all --check

# Rust workspace tests
cargo test --locked --release --workspace

# Dependency vulnerability audit
cargo audit

# JVM binding tests — build the JVM binding first
./bindings-jvm/build.sh
( cd bindings-jvm/tests && ./run.sh )

# WASM binding tests — build the WASM binding first
./bindings-wasm/build.sh
( cd bindings-wasm/tests && ./run.sh )
```

## Download and verify release artifacts

Each GitHub release attaches the prebuilt artifacts as signed assets:

- `cloudformation-validate.jar` — the JVM (Kotlin/Java) binding
- `cloudformation-validate.zip` — the Node.js (WASM) binding package
- `cfn-validate-<os>-<arch>` — the CLI binary, one per supported platform (e.g. `cfn-validate-linux-x64`,
  `cfn-validate-darwin-aarch64`)

Alongside each artifact are a detached signature (`<artifact>.sig`), the public key (`signing-key.pem`), and the key's
SHA-256 fingerprint (`signing-key.pem.sha256`). Artifacts are signed with an AWS KMS RSA key
(`RSASSA_PKCS1_V1_5_SHA_256`).

Download the artifact you want, its `.sig`, and `signing-key.pem` from the same release, then verify the signature:

```bash
openssl dgst -sha256 -verify signing-key.pem -signature <artifact>.sig <artifact>
# e.g. openssl dgst -sha256 -verify signing-key.pem -signature cloudformation-validate.zip.sig cloudformation-validate.zip
```

A valid artifact prints `Verified OK`. Any other output means verification failed — do not use the artifact.

Optionally, confirm the bundled key is the real signing key by matching its fingerprint against one you trust:

```bash
openssl pkey -pubin -in signing-key.pem -outform DER | openssl dgst -sha256
cat signing-key.pem.sha256
```

The two values must match.
