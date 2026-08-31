# bbtsdecrypt

A high-performance, lightweight tool for decrypting protected **BBTS / MPEG-TS** streams with full lossless preservation of **AVC (H.264)**, **HEVC (H.265)**, **Dolby Vision**, and **HDR** bitstreams.

## Features

- **Sequential 188-byte MPEG-TS Streaming**: High-throughput buffered I/O with automatic adaptation field stuffing.
- **Dynamic Video PID Detection**: Real-time PAT and PMT parsing to detect and decrypt dynamic video stream PIDs (PID 32, 33, 256, etc.).
- **Automatic Base IV Extraction**: Extracts 16-byte Base IV from SDT (PID 17) and packet markers (`|v...|`).
- **128-bit Lossless CTR Engine**: 128-bit big-endian counter increment (`ctr_inc`) with 0-based 10:1 Sample-AES block interval.
- **Pure Bitstream Preservation**: 100% untouched preservation of SPS, PPS, VPS, SEI, Dolby Vision RPU, and HDR metadata without distortion or arbitrary injection.
- **Strict Key Validation**: Enforces exact `KID:KEY` (32 hex : 32 hex) format.
- **Pure Rust Implementation**: Zero external C dependencies with Link-Time Optimization (LTO) support.

## Build

```bash
cargo build --release
```

Binary outputs:
- **Linux / macOS**: `target/release/bbtsdecrypt`
- **Windows**: `target\release\bbtsdecrypt.exe`

## Usage

```bash
# Decrypt using KID:KEY pair (32 hex : 32 hex)
bbtsdecrypt -i input.bbts -o output.ts -k 31379f0d5fcd5234862efd8aa9a4e95f:e81836fb4d37ddbc30ae4b80a3573146
```

### Options

- `-i, --input <PATH>`   : Input BBTS / TS file
- `-o, --output <PATH>`  : Output decrypted TS file
- `-k, --key <KID:KEY>`  : Key specification in `KID:KEY` format (32 hex : 32 hex)
- `-h, --help`           : Print help information

## Requirements

- Rust (Edition 2024 or later)
- Cargo

## License

This project is licensed under the GPL-3.0 License.

## Acknowledgements

This project is a fork based on [BBTS-Decryptor](https://github.com/Hugoved/BBTS-Decryptor), originally created by [@Hugoved](https://github.com/Hugoved).

