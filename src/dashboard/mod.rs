pub mod data;
pub mod terminal;
pub mod ui;

use anyhow::Result;
use crossterm::event::{self, KeyCode, KeyModifiers};

use crate::storage::Store;
use data::ControlRow;

pub use terminal::run;

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

    #[test]
    fn ctrl_c_quits_from_detail_view() {
        let mut app = App::new();
        app.view = View::Detail(0);
        app.handle_key(KeyEvent {
            code: KeyCode::Char('c'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        });
        assert!(app.should_quit);
    }

    #[test]
    fn handle_key_unknown_keys_are_ignored_in_main() {
        let mut app = App::new();
        app.handle_key(key(KeyCode::F(1)));
        assert_eq!(app.view, View::Main);
        assert!(!app.should_quit);
    }

    #[test]
    fn handle_key_unknown_keys_are_ignored_in_detail() {
        let mut app = App::new();
        app.view = View::Detail(0);
        app.handle_key(key(KeyCode::F(1)));
        assert_eq!(app.view, View::Detail(0));
        assert!(!app.should_quit);
    }

    #[test]
    fn previous_noop_empty_controls() {
        let mut app = App::new();
        app.previous();
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn scroll_down_increments_offset() {
        let mut app = App::new();
        app.scroll_down();
        assert_eq!(app.scroll_offset, 1);
        app.scroll_down();
        assert_eq!(app.scroll_offset, 2);
    }

    #[test]
    fn scroll_up_saturates_at_zero() {
        let mut app = App::new();
        app.scroll_up();
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn app_default_is_same_as_new() {
        let a = App::new();
        let b = App::default();
        assert_eq!(a.view, b.view);
        assert_eq!(a.selected, b.selected);
        assert_eq!(a.should_quit, b.should_quit);
        assert_eq!(a.scroll_offset, b.scroll_offset);
    }

    #[test]
    fn refresh_data_clamps_selection() {
        use crate::storage::SqliteStore;
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("test.db").to_str().unwrap().to_string();
        let store = SqliteStore::open(&db_path).unwrap();

        let mut app = App::new();
        // Start with selection at index 5
        app.selected = 5;
        // Refresh with an empty controls dir → controls list becomes empty
        let result = app.refresh_data(&store, "/nonexistent/controls/dir");
        assert!(result.is_ok());
        // Empty list → selected should be clamped (no change since list is empty)
        assert_eq!(app.selected, 5); // No clamping when empty — only clamps if selected >= len
    }

    #[test]
    fn handle_key_jk_scroll_in_detail_view() {
        let mut app = App::new();
        app.view = View::Detail(0);
        app.handle_key(key(KeyCode::Char('j')));
        assert_eq!(app.scroll_offset, 1);
        app.handle_key(key(KeyCode::Char('k')));
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn refresh_data_clamps_selection_when_controls_shrink() {
        use crate::storage::SqliteStore;

        let dir = tempfile::TempDir::new().unwrap();

        // Write a single valid control YAML
        let yaml = r#"
id: clamp-test-ctrl
name: Clamp Test
description: ""
framework_mappings: []
observers: []
testers: []
evaluation_logic:
  preset: all_effective
  cel_expression: ""
"#;
        std::fs::write(dir.path().join("ctrl.yaml"), yaml).unwrap();

        let db_dir = tempfile::TempDir::new().unwrap();
        let db_path = db_dir.path().join("test.db").to_str().unwrap().to_string();
        let store = SqliteStore::open(&db_path).unwrap();

        let mut app = App::new();
        // Set selected to something higher than the 1 control that will load
        app.selected = 10;
        let result = app.refresh_data(&store, dir.path().to_str().unwrap());
        assert!(result.is_ok());
        // 1 control loaded, selected was 10, should be clamped to 0
        assert_eq!(app.controls.len(), 1);
        assert_eq!(app.selected, 0); // clamped to len() - 1 = 0
    }
}
