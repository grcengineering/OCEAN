pub mod data;
pub mod ui;

use std::io;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;

use crate::storage::Store;
use data::ControlRow;

/// Which view the dashboard is currently showing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum View {
    /// Main table listing all controls.
    Main,
    /// Detail view for the control at the given index.
    Detail(usize),
}

/// Application state for the TUI dashboard.
pub struct App {
    pub view: View,
    pub controls: Vec<ControlRow>,
    pub selected: usize,
    pub last_refresh: chrono::DateTime<chrono::Utc>,
    pub scroll_offset: usize,
    pub should_quit: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            view: View::Main,
            controls: Vec::new(),
            selected: 0,
            last_refresh: chrono::Utc::now(),
            scroll_offset: 0,
            should_quit: false,
        }
    }

    /// Navigate selection down.
    pub fn next(&mut self) {
        if !self.controls.is_empty() {
            self.selected = (self.selected + 1) % self.controls.len();
        }
    }

    /// Navigate selection up.
    pub fn previous(&mut self) {
        if !self.controls.is_empty() {
            self.selected = if self.selected == 0 {
                self.controls.len() - 1
            } else {
                self.selected - 1
            };
        }
    }

    /// Enter detail view for the currently selected control.
    pub fn enter_detail(&mut self) {
        if !self.controls.is_empty() {
            self.scroll_offset = 0;
            self.view = View::Detail(self.selected);
        }
    }

    /// Return to main view.
    pub fn back_to_main(&mut self) {
        self.view = View::Main;
        self.scroll_offset = 0;
    }

    /// Scroll down in detail view.
    pub fn scroll_down(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_add(1);
    }

    /// Scroll up in detail view.
    pub fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }

    /// Handle a key event.
    pub fn handle_key(&mut self, key: event::KeyEvent) {
        // Ctrl+C always quits
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }

        match &self.view {
            View::Main => match key.code {
                KeyCode::Char('q') => self.should_quit = true,
                KeyCode::Down | KeyCode::Char('j') => self.next(),
                KeyCode::Up | KeyCode::Char('k') => self.previous(),
                KeyCode::Enter => self.enter_detail(),
                _ => {}
            },
            View::Detail(_) => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => self.back_to_main(),
                KeyCode::Down | KeyCode::Char('j') => self.scroll_down(),
                KeyCode::Up | KeyCode::Char('k') => self.scroll_up(),
                _ => {}
            },
        }
    }

    /// Refresh data from the store.
    pub fn refresh_data(&mut self, store: &dyn Store, controls_dir: &str) -> Result<()> {
        self.controls = data::load_controls(controls_dir, store)?;
        self.last_refresh = chrono::Utc::now();
        // Clamp selection if controls list shrunk
        if !self.controls.is_empty() && self.selected >= self.controls.len() {
            self.selected = self.controls.len() - 1;
        }
        Ok(())
    }
}

/// Run the TUI dashboard.
///
/// This is the main entry point called by the CLI. It sets up the terminal,
/// runs the event loop, and restores the terminal on exit.
pub fn run(store: &dyn Store, controls_dir: &str, refresh_secs: u64) -> Result<()> {
    // Check for TTY
    if !atty_check() {
        anyhow::bail!(
            "ocean dashboard requires an interactive terminal (TTY). \
             Redirect output is not supported."
        );
    }

    // Setup terminal
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;

    // Run app (wrapped so we always restore terminal)
    let result = run_app(&mut terminal, store, controls_dir, refresh_secs);

    // Restore terminal
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
    let mut last_tick = Instant::now();

    // Initial data load
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

/// Check if stdout is a TTY.
fn atty_check() -> bool {
    use std::io::IsTerminal;
    io::stdout().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEvent, KeyEventKind, KeyEventState};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn new_app_starts_in_main_view() {
        let app = App::new();
        assert_eq!(app.view, View::Main);
        assert_eq!(app.selected, 0);
        assert!(!app.should_quit);
    }

    #[test]
    fn next_wraps_around() {
        let mut app = App::new();
        app.controls = vec![data::ControlRow::empty("a"), data::ControlRow::empty("b")];
        app.next();
        assert_eq!(app.selected, 1);
        app.next();
        assert_eq!(app.selected, 0); // wrapped
    }

    #[test]
    fn previous_wraps_around() {
        let mut app = App::new();
        app.controls = vec![data::ControlRow::empty("a"), data::ControlRow::empty("b")];
        app.previous();
        assert_eq!(app.selected, 1); // wrapped from 0
    }

    #[test]
    fn next_noop_empty_controls() {
        let mut app = App::new();
        app.next();
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn enter_detail_sets_view() {
        let mut app = App::new();
        app.controls = vec![data::ControlRow::empty("a")];
        app.enter_detail();
        assert_eq!(app.view, View::Detail(0));
    }

    #[test]
    fn enter_detail_noop_empty() {
        let mut app = App::new();
        app.enter_detail();
        assert_eq!(app.view, View::Main);
    }

    #[test]
    fn back_to_main_resets_view() {
        let mut app = App::new();
        app.view = View::Detail(2);
        app.scroll_offset = 5;
        app.back_to_main();
        assert_eq!(app.view, View::Main);
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn handle_key_q_quits_main() {
        let mut app = App::new();
        app.handle_key(key(KeyCode::Char('q')));
        assert!(app.should_quit);
    }

    #[test]
    fn handle_key_q_backs_out_detail() {
        let mut app = App::new();
        app.controls = vec![data::ControlRow::empty("a")];
        app.view = View::Detail(0);
        app.handle_key(key(KeyCode::Char('q')));
        assert_eq!(app.view, View::Main);
        assert!(!app.should_quit);
    }

    #[test]
    fn handle_key_esc_backs_out_detail() {
        let mut app = App::new();
        app.view = View::Detail(0);
        app.handle_key(key(KeyCode::Esc));
        assert_eq!(app.view, View::Main);
    }

    #[test]
    fn handle_key_arrows_navigate() {
        let mut app = App::new();
        app.controls = vec![
            data::ControlRow::empty("a"),
            data::ControlRow::empty("b"),
            data::ControlRow::empty("c"),
        ];
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.selected, 1);
        app.handle_key(key(KeyCode::Up));
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn handle_key_jk_navigate() {
        let mut app = App::new();
        app.controls = vec![data::ControlRow::empty("a"), data::ControlRow::empty("b")];
        app.handle_key(key(KeyCode::Char('j')));
        assert_eq!(app.selected, 1);
        app.handle_key(key(KeyCode::Char('k')));
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn handle_key_enter_opens_detail() {
        let mut app = App::new();
        app.controls = vec![data::ControlRow::empty("a")];
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.view, View::Detail(0));
    }

    #[test]
    fn scroll_in_detail_view() {
        let mut app = App::new();
        app.view = View::Detail(0);
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.scroll_offset, 1);
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.scroll_offset, 2);
        app.handle_key(key(KeyCode::Up));
        assert_eq!(app.scroll_offset, 1);
    }

    #[test]
    fn scroll_up_does_not_underflow() {
        let mut app = App::new();
        app.view = View::Detail(0);
        app.handle_key(key(KeyCode::Up));
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn ctrl_c_always_quits() {
        let mut app = App::new();
        app.handle_key(KeyEvent {
            code: KeyCode::Char('c'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        });
        assert!(app.should_quit);
    }
}
