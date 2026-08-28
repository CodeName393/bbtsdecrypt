mod cli;
mod common;
mod crypto;
mod decrypt;
mod detect;
mod dolby;
mod hevc;
mod hdr;
mod sdr;
mod ts;
mod ui;

use crate::cli::parse_cli;
use crate::common::AppResult;
use crate::decrypt::decrypt_bbts_streaming;
use crate::detect::detect_stream_mode;
use crate::ui::ProgressUi;

fn run() -> AppResult<()> {
    let cli = parse_cli()?;
    let mode = detect_stream_mode(&cli.input, &cli.key)?;
    let total_size = std::fs::metadata(&cli.input)?.len();
    let mut progress = ProgressUi::begin(total_size)?;
    decrypt_bbts_streaming(&cli.input, &cli.output, &cli.key, &mut progress, mode)?;
    println!("Decrypted successfully.");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}
