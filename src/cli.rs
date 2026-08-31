use crate::common::AppResult;
use std::env;
use std::path::PathBuf;

#[derive(Debug)]
pub(crate) struct Cli {
    pub(crate) input: PathBuf,
    pub(crate) output: PathBuf,
    pub(crate) key: String,
}

fn print_usage(program: &str) {
    eprintln!("Usage: {program} -i <input.bbts> -o <output.ts> -k <kid:key>");
    eprintln!("  kid:key = 32 hex characters : 32 hex characters");
}

pub(crate) fn parse_cli() -> AppResult<Cli> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "bbtsdecrypt".to_string());
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut key: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-i" | "--input" => {
                input = Some(PathBuf::from(
                    args.next().ok_or("Missing value for --input")?,
                ));
            }
            "-o" | "--output" => {
                output = Some(PathBuf::from(
                    args.next().ok_or("Missing value for --output")?,
                ));
            }
            "-k" | "--key" => {
                key = Some(args.next().ok_or("Missing value for --key")?);
            }
            "-h" | "--help" => {
                print_usage(&program);
                std::process::exit(0);
            }
            other => {
                print_usage(&program);
                return Err(format!("Unknown argument: {other}").into());
            }
        }
    }

    let Some(input) = input else {
        print_usage(&program);
        return Err("Missing required --input".into());
    };
    let Some(output) = output else {
        print_usage(&program);
        return Err("Missing required --output".into());
    };
    let Some(key) = key else {
        print_usage(&program);
        return Err("Missing required --key".into());
    };

    if input == output {
        return Err("Input and output paths must be different".into());
    }

    Ok(Cli { input, output, key })
}
