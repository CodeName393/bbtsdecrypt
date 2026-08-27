# BBTS Decryptor

A tool for decrypting protected **BBTS / MPEG-TS** streams with support for **HEVC**, **Dolby Vision**, and **HDR Vivid** metadata.

## Features

* BBTS / MPEG-TS 188-byte packet support
* PAT / PMT parsing
* HEVC / H.265 decryption
* AES-128 key support
* Dolby Vision RPU preservation
* HDR Vivid metadata preservation
* Dynamic HDR metadata handling
* Native Rust implementation

## Build

```bash
cargo build --release
```

Executable:

```text
target/release/bbts
```

On Windows:

```text
target\release\bbts.exe
```

## Usage

AES key:

```bash
bbts -i input.bbts -o output.ts -k 306162d1837731abd3ad41c707943c27
```

KID + key:

```bash
bbts -i input.bbts -o output.ts -k 31379f0d5fcd5234862efd8aa9a4e95f:e81836fb4d37ddbc30ae4b80a3573146
```

## Requirements

* Rust
* Cargo
* Rust Edition 2024

## Issues and Support

If you encounter any issues, please open an issue in the repository.
Support and maintenance will be provided as time permits.

---

## Acknowledgements

Thank you for your interest in this project.
