use std::io::{self, Write};

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_WHITE: &str = "\x1b[97m";
const BAR_WIDTH: usize = 64;

pub(crate) struct ProgressUi {
    total: u64,
    last_percent: i32,
    ansi: bool,
}

impl ProgressUi {
    pub(crate) fn begin(total: u64) -> io::Result<Self> {
        let ansi = enable_ansi_console();
        let mut ui = Self {
            total,
            last_percent: -1,
            ansi,
        };
        ui.render(0, true)?;
        Ok(ui)
    }

    pub(crate) fn update(&mut self, done: u64) -> io::Result<()> {
        self.render(done, false)
    }

    pub(crate) fn finish(&mut self) -> io::Result<()> {
        self.render(self.total, true)
    }

    fn render(&mut self, done: u64, force: bool) -> io::Result<()> {
        let done = done.min(self.total);
        let ratio = if self.total == 0 {
            1.0
        } else {
            (done as f64 / self.total as f64).clamp(0.0, 1.0)
        };
        let percent = (ratio * 100.0).floor() as i32;

        if !force && percent == self.last_percent {
            return Ok(());
        }

        let filled = ((BAR_WIDTH as f64 * ratio).floor() as usize).min(BAR_WIDTH);
        let bar = format!(
            "[{}{}] {:>3}%",
            "■".repeat(filled),
            " ".repeat(BAR_WIDTH - filled),
            percent
        );

        let stdout = io::stdout();
        let mut handle = stdout.lock();

        if self.ansi {
            write!(handle, "\r\x1b[2K{ANSI_WHITE}{bar}{ANSI_RESET}")?;
        } else {
            write!(handle, "\r{bar}")?;
        }

        if force && done == self.total {
            writeln!(handle)?;
        }

        handle.flush()?;
        self.last_percent = percent;
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
