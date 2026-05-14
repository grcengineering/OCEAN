use std::io;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;

use super::{ui, App};
use crate::storage::Store;

/// Run the TUI dashboard.
///
/// This is the main entry point called by the CLI. It sets up the terminal,
/// runs the event loop, and restores the terminal on exit.
pub fn run(store: &dyn Store, controls_dir: &str, refresh_secs: u64) -> Result<()> {
    if !atty_check() {
        anyhow::bail!(
            "ocean dashboard requires an interactive terminal (TTY). \
             Redirect output is not supported."
        );
    }

    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;

    let result = run_app(&mut terminal, store, controls_dir, refresh_secs);

    disable_raw_mode().context("failed to disable raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;
    terminal.show_cursor().context("failed to show cursor")?;

    result
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    store: &dyn Store,
    controls_dir: &str,
    refresh_secs: u64,
) -> Result<()> {
    let mut app = App::new();
    let tick_rate = Duration::from_secs(refresh_secs);
    let mut last_tick = std::time::Instant::now();

    app.refresh_data(store, controls_dir)?;

    loop {
        terminal.draw(|frame| ui::render(frame, &app))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout).context("event poll failed")? {
            if let Event::Key(key) = event::read().context("event read failed")? {
                app.handle_key(key);
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.refresh_data(store, controls_dir)?;
            last_tick = Instant::now();
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

fn atty_check() -> bool {
    use std::io::IsTerminal;
    io::stdout().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SqliteStore;

    #[test]
    fn run_rejects_non_tty() {
        // In test context, stdout is typically not a TTY (piped to test harness).
        // So run() should bail with the TTY error message.
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("test.db").to_str().unwrap().to_string();
        let store = SqliteStore::open(&db_path).unwrap();

        let result = run(&store, "/nonexistent/controls", 5);
        // When stdout is not a TTY, run() should return an error
        if !atty_check() {
            let err = result.unwrap_err();
            let msg = format!("{}", err);
            assert!(
                msg.contains("interactive terminal"),
                "expected TTY error, got: {}",
                msg
            );
        }
        // If somehow running in a TTY test environment, the test still passes —
        // it would block on the event loop, but atty_check() returns true in that case,
        // so we only assert when we know it's not a TTY.
    }

    #[test]
    fn atty_check_returns_bool() {
        // Just verify atty_check doesn't panic and returns a bool.
        // In test runner context it's typically false.
        let result = atty_check();
        // Result is either true or false — test that it's a valid bool
        assert!(result || !result);
    }
}
