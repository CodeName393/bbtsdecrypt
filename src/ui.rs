use std::io::{self, IsTerminal, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_GREEN: &str = "\x1b[92m";
const ANSI_BLUE: &str = "\x1b[94m";
const ANSI_DIM: &str = "\x1b[90m";
const BAR_WIDTH: usize = 24;
const UPDATE_INTERVAL: Duration = Duration::from_millis(100);

pub(crate) struct ProgressUi {
    total_bytes: u64,
    total_packets: u64,
    start: Instant,
    last_render: Instant,
    last_percent: i32,
    interactive: bool,
    ansi: bool,
    rendered: bool,
    fallback_width: usize,
}

impl ProgressUi {
    pub(crate) fn begin(total_bytes: u64) -> io::Result<Self> {
        let interactive = io::stdout().is_terminal();
        let ansi = interactive && enable_ansi_console();
        let total_packets = total_bytes / 188;
        let now = Instant::now();
        let mut ui = Self {
            total_bytes,
            total_packets,
            start: now,
            last_render: now.checked_sub(Duration::from_secs(1)).unwrap_or(now),
            last_percent: -1,
            interactive,
            ansi,
            rendered: false,
            fallback_width: 0,
        };

        if ansi {
            println!(
                "[{} {ANSI_GREEN}INFO{ANSI_RESET}  bbts::decrypt] BBTS -> MPEG-TS | AES-128 CTR",
                utc_timestamp_now()
            );
        } else {
            println!(
                "[{} INFO  bbts::decrypt] BBTS -> MPEG-TS | AES-128 CTR",
                utc_timestamp_now()
            );
        }

        ui.render(0, true)?;
        Ok(ui)
    }

    pub(crate) fn update(&mut self, done_bytes: u64) -> io::Result<()> {
        self.render(done_bytes, false)
    }

    pub(crate) fn finish(&mut self) -> io::Result<()> {
        self.render(self.total_bytes, true)
    }

    fn render(&mut self, done_bytes: u64, force: bool) -> io::Result<()> {
        let done_bytes = done_bytes.min(self.total_bytes);
        let ratio = if self.total_bytes == 0 {
            1.0
        } else {
            (done_bytes as f64 / self.total_bytes as f64).clamp(0.0, 1.0)
        };
        let percent_int = (ratio * 100.0).floor() as i32;
        let now = Instant::now();

        if !force {
            if now.duration_since(self.last_render) < UPDATE_INTERVAL {
                return Ok(());
            }
            if percent_int == self.last_percent {
                return Ok(());
            }
        }

        let done_packets = (done_bytes / 188).min(self.total_packets);
        let filled = ((BAR_WIDTH as f64 * ratio).floor() as usize).min(BAR_WIDTH);
        let elapsed = now.duration_since(self.start);
        let elapsed_secs = elapsed.as_secs_f64().max(0.001);
        let speed_bps = done_bytes as f64 / elapsed_secs;
        let eta_secs = if speed_bps > 0.0 && done_bytes < self.total_bytes {
            (self.total_bytes - done_bytes) as f64 / speed_bps
        } else {
            0.0
        };
        let speed_mib = speed_bps / (1024.0 * 1024.0);
        let done_mib = done_bytes as f64 / (1024.0 * 1024.0);
        let total_mib = self.total_bytes as f64 / (1024.0 * 1024.0);

        let plain_bar = format!("{}{}", "█".repeat(filled), "░".repeat(BAR_WIDTH - filled));
        let progress_plain = format!(
            "{plain_bar}  {done_packets}/{total} packets ({percent_int}%)",
            total = self.total_packets
        );
        let detail_line = format!(
            "speed: {speed_mib:.1} MiB/s | processed: {done_mib:.2}/{total_mib:.2} MiB | elapsed: {} | ETA: {}",
            format_hms(elapsed.as_secs_f64()),
            format_hms(eta_secs)
        );

        if self.ansi {
            let progress_color = format!(
                "{ANSI_BLUE}{}{ANSI_RESET}{ANSI_DIM}{}{ANSI_RESET}  {done_packets}/{total} packets ({percent_int}%)",
                "█".repeat(filled),
                "░".repeat(BAR_WIDTH - filled),
                total = self.total_packets
            );
            if self.rendered {
                print!("\x1b[2F");
            }
            print!("\x1b[2K{progress_color}\n\x1b[2K{detail_line}\n");
        } else if self.interactive {

            let compact = format!("{progress_plain} | {detail_line}");
            let width = self.fallback_width.max(compact.chars().count());
            print!("\r{compact:<width$}", width = width);
            self.fallback_width = width;
            if force {
                println!();
            }
        } else {

            if force || percent_int == 0 || percent_int == 100 || percent_int % 25 == 0 {
                println!("{progress_plain}");
                println!("{detail_line}");
            }
        }

        io::stdout().flush()?;
        self.rendered = true;
        self.last_render = now;
        self.last_percent = percent_int;
        Ok(())
    }
}

#[cfg(windows)]
fn enable_ansi_console() -> bool {
    use std::ffi::c_void;

    type Handle = *mut c_void;
    const STD_OUTPUT_HANDLE: i32 = -11;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(n_std_handle: i32) -> Handle;
        fn GetConsoleMode(h_console_handle: Handle, lp_mode: *mut u32) -> i32;
        fn SetConsoleMode(h_console_handle: Handle, dw_mode: u32) -> i32;
    }

    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle.is_null() {
            return false;
        }
        let mut mode = 0u32;
        if GetConsoleMode(handle, &mut mode) == 0 {
            return false;
        }
        SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

#[cfg(not(windows))]
fn enable_ansi_console() -> bool {
    true
}

fn format_hms(seconds: f64) -> String {
    let total = seconds.max(0.0).floor() as u64;
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

fn utc_timestamp_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let hour = day_seconds / 3600;
    let minute = (day_seconds % 3600) / 60;
    let second = day_seconds % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    (year as i32, month as u32, day as u32)
}
