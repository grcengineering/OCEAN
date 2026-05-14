use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use super::{App, View};

/// Render the current app state to the terminal frame.
pub fn render(frame: &mut Frame, app: &App) {
    match &app.view {
        View::Main => render_main(frame, app),
        View::Detail(idx) => render_detail(frame, app, *idx),
    }
}

/// Render the main control status table.
fn render_main(frame: &mut Frame, app: &App) {
    let area = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(5),   // table
            Constraint::Length(3), // footer
        ])
        .split(area);

    // Header
    let header_text = format!(
        " OCEAN Dashboard v{}  |  Last refresh: {}  |  {} controls",
        env!("CARGO_PKG_VERSION"),
        app.last_refresh.format("%H:%M:%S UTC"),
        app.controls.len(),
    );
    let header = Paragraph::new(header_text)
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::BOTTOM));
    frame.render_widget(header, chunks[0]);

    // Table
    let header_row = Row::new(vec![
        Cell::from(" Control").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Status").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Confidence").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Uptime").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Framework").style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .height(1);

    let rows: Vec<Row> = app
        .controls
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let status_style = match row.status_text() {
                "effective" => Style::default().fg(Color::Green),
                "ineffective" => Style::default().fg(Color::Red),
                _ => Style::default().fg(Color::Yellow),
            };

            let is_selected = i == app.selected;
            let prefix = if is_selected { ">" } else { " " };

            let row_style = if is_selected {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(format!("{} {}", prefix, row.control.id)),
                Cell::from(row.status_text().to_uppercase()).style(status_style),
                Cell::from(row.confidence_text().to_string()),
                Cell::from(row.uptime_text()),
                Cell::from(row.framework.clone()),
            ])
            .style(row_style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(30),
            Constraint::Length(14),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(16),
        ],
    )
    .header(header_row)
    .block(Block::default().borders(Borders::NONE));

    frame.render_widget(table, chunks[1]);

    // Footer
    let footer_text = " ↑↓/jk Navigate  Enter Detail  q Quit";
    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::TOP));
    frame.render_widget(footer, chunks[2]);
}

/// Render the detail view for a specific control.
fn render_detail(frame: &mut Frame, app: &App, idx: usize) {
    let area = frame.area();

    let row = match app.controls.get(idx) {
        Some(r) => r,
        None => {
            let msg = Paragraph::new("No control data available.")
                .style(Style::default().fg(Color::Red));
            frame.render_widget(msg, area);
            return;
        }
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(5), // status summary
            Constraint::Min(8),   // evidence + transcript
            Constraint::Length(3), // footer
        ])
        .split(area);

    // Header
    let header_text = format!(" {}  —  {}", row.control.id, row.control.name);
    let header = Paragraph::new(header_text)
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::BOTTOM));
    frame.render_widget(header, chunks[0]);

    // Status summary
    let status_color = match row.status_text() {
        "effective" => Color::Green,
        "ineffective" => Color::Red,
        _ => Color::Yellow,
    };
    let eval_details = row
        .status
        .as_ref()
        .map(|s| s.evaluation_details.as_str())
        .unwrap_or("no evaluation data");

    let summary = Paragraph::new(vec![
        Line::from(vec![
            Span::raw("  Status: "),
            Span::styled(
                row.status_text().to_uppercase(),
                Style::default().fg(status_color).add_modifier(Modifier::BOLD),
            ),
            Span::raw("    Confidence: "),
            Span::raw(row.confidence_text()),
            Span::raw("    Uptime (30d): "),
            Span::raw(row.uptime_text()),
        ]),
        Line::from(format!("  Evaluation: {}", eval_details)),
        Line::from(format!("  Description: {}", row.control.description)),
    ])
    .block(Block::default().borders(Borders::NONE));
    frame.render_widget(summary, chunks[1]);

    // Evidence timeline + transcript
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(
        Span::styled(
            "  Evidence Timeline:",
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ));

    if row.evidence.is_empty() {
        lines.push(Line::from("    No evidence records found."));
    } else {
        for ev in &row.evidence {
            let status_color = match ev.status_id {
                crate::evidence::StatusId::Effective => Color::Green,
                crate::evidence::StatusId::Ineffective => Color::Red,
                _ => Color::Yellow,
            };
            let confidence = match ev.confidence_level {
                crate::evidence::ConfidenceLevel::PassiveObservation => "passive",
                crate::evidence::ConfidenceLevel::ActiveVerification => "active",
            };
            lines.push(Line::from(vec![
                Span::raw(format!("    {}  ", ev.time.format("%Y-%m-%d %H:%M"))),
                Span::raw(format!("{:<28} ", ev.metadata.module.name)),
                Span::styled(
                    format!("{:<14}", ev.status.to_uppercase()),
                    Style::default().fg(status_color),
                ),
                Span::raw(confidence),
            ]));
        }
    }

    // Test transcripts
    let has_transcript = row
        .evidence
        .iter()
        .any(|e| e.test_transcript.is_some());

    if has_transcript {
        lines.push(Line::from(""));
        lines.push(Line::from(
            Span::styled(
                "  Test Transcripts:",
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ));
        for ev in &row.evidence {
            if let Some(ref transcript) = ev.test_transcript {
                lines.push(Line::from(format!(
                    "    Module: {}",
                    ev.metadata.module.name
                )));
                for (i, action) in transcript.actions_attempted.iter().enumerate() {
                    lines.push(Line::from(format!(
                        "      Action {}: {}",
                        i + 1,
                        action.action,
                    )));
                }
                for obs in &transcript.observations {
                    let marker = if obs.expected { "OK" } else { "UNEXPECTED" };
                    lines.push(Line::from(format!(
                        "      Observation: {} [{}]",
                        obs.observation, marker,
                    )));
                }
                for cleanup in &transcript.cleanup_actions {
                    let status = if cleanup.success { "OK" } else { "FAILED" };
                    lines.push(Line::from(format!(
                        "      Cleanup: {} [{}]",
                        cleanup.action, status,
                    )));
                }
            }
        }
    }

    // Apply scroll offset
    let visible_lines: Vec<Line> = lines
        .into_iter()
        .skip(app.scroll_offset)
        .collect();

    let evidence_section = Paragraph::new(visible_lines)
        .block(Block::default().borders(Borders::TOP).title(" Evidence "));
    frame.render_widget(evidence_section, chunks[2]);

    // Footer
    let footer_text = " ↑↓/jk Scroll  Esc/q Back  Ctrl+C Quit";
    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::TOP));
    frame.render_widget(footer, chunks[3]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStatus;
    use crate::dashboard::data::ControlRow;
    use crate::evidence::{
        ConfidenceLevel, Evidence, Metadata, ModuleInfo, SourceInfo, StatusId,
    };
    use crate::evidence::transcript::{
        TestTranscript, TranscriptAction, TranscriptCleanup, TranscriptObservation,
    };
    use chrono::Utc;
    use ratatui::backend::TestBackend;
    use uuid::Uuid;

    /// Helper: create a minimal evidence record with the given status.
    fn make_evidence_with_status(status_id: StatusId, status: &str) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            control_id: "test.ctrl".to_string(),
            class_uid: 1001,
            category_uid: 10,
            activity_id: 1,
            time: Utc::now(),
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "test.module".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "observer".to_string(),
                },
                source: SourceInfo {
                    system: "mock".to_string(),
                    api_version: "v1".to_string(),
                    endpoint: "mock://endpoint".to_string(),
                },
                original_time: None,
                processed_time: Utc::now(),
                safety_classification: None,
            },
            observables: vec![],
            status_id,
            status: status.to_string(),
            raw_data: serde_json::json!({}),
            findings: vec![],
            test_transcript: None,
            enrichments: vec![],
        }
    }

    /// Helper: create a ControlRow with a status.
    fn make_row_with_status(id: &str, status: &str) -> ControlRow {
        let mut row = ControlRow::empty(id);
        row.status = Some(ControlStatus {
            id: Uuid::new_v4(),
            control_id: id.to_string(),
            timestamp: Utc::now(),
            status: status.to_string(),
            confidence: "high".to_string(),
            evidence_ids: vec![],
            evaluation_details: "evaluated ok".to_string(),
        });
        row.uptime_percent = Some(99.5);
        row.framework = "SOC2 CC6.1".to_string();
        row
    }

    // ---- render() dispatch tests ----

    #[test]
    fn render_dispatches_to_main_view() {
        let app = App::new();
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, &app)).unwrap();
        // If we get here without panic, dispatch worked
    }

    #[test]
    fn render_dispatches_to_detail_view() {
        let mut app = App::new();
        app.controls = vec![make_row_with_status("ctrl-1", "effective")];
        app.view = View::Detail(0);
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, &app)).unwrap();
    }

    // ---- render_main tests ----

    #[test]
    fn render_main_empty_controls() {
        let app = App::new();
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_main(f, &app)).unwrap();
    }

    #[test]
    fn render_main_single_control_selected() {
        let mut app = App::new();
        app.controls = vec![make_row_with_status("ctrl-1", "effective")];
        app.selected = 0;
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_main(f, &app)).unwrap();
    }

    #[test]
    fn render_main_multiple_controls_with_selection() {
        let mut app = App::new();
        app.controls = vec![
            make_row_with_status("ctrl-1", "effective"),
            make_row_with_status("ctrl-2", "ineffective"),
            make_row_with_status("ctrl-3", "unknown"),
        ];
        app.selected = 1;
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_main(f, &app)).unwrap();
    }

    #[test]
    fn render_main_effective_status_color() {
        let mut app = App::new();
        app.controls = vec![make_row_with_status("ctrl-1", "effective")];
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_main(f, &app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("EFFECTIVE"));
    }

    #[test]
    fn render_main_ineffective_status_color() {
        let mut app = App::new();
        app.controls = vec![make_row_with_status("ctrl-1", "ineffective")];
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_main(f, &app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("INEFFECTIVE"));
    }

    #[test]
    fn render_main_unknown_status_gets_yellow() {
        let mut app = App::new();
        // ControlRow::empty has status=None → status_text()="unknown" → yellow branch
        app.controls = vec![ControlRow::empty("ctrl-unknown")];
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_main(f, &app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("UNKNOWN"));
    }

    #[test]
    fn render_main_partial_status_gets_yellow() {
        // "partial" is neither "effective" nor "ineffective" → yellow wildcard
        let mut app = App::new();
        app.controls = vec![make_row_with_status("ctrl-1", "partial")];
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_main(f, &app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("PARTIAL"));
    }

    #[test]
    fn render_main_selected_row_has_prefix() {
        let mut app = App::new();
        app.controls = vec![
            make_row_with_status("ctrl-1", "effective"),
            make_row_with_status("ctrl-2", "effective"),
        ];
        app.selected = 0;
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_main(f, &app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        // Selected row should have ">" prefix
        assert!(content.contains("> ctrl-1"));
    }

    #[test]
    fn render_main_nonselected_row_has_space_prefix() {
        let mut app = App::new();
        app.controls = vec![
            make_row_with_status("ctrl-1", "effective"),
            make_row_with_status("ctrl-2", "effective"),
        ];
        app.selected = 0; // ctrl-1 selected, ctrl-2 not
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_main(f, &app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("  ctrl-2")); // space prefix
    }

    #[test]
    fn render_main_shows_header_with_version() {
        let app = App::new();
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_main(f, &app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("OCEAN Dashboard"));
        assert!(content.contains("0 controls"));
    }

    #[test]
    fn render_main_shows_footer() {
        let app = App::new();
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_main(f, &app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("Navigate"));
        assert!(content.contains("Quit"));
    }

    #[test]
    fn render_main_shows_framework_column() {
        let mut app = App::new();
        let mut row = make_row_with_status("ctrl-fw", "effective");
        row.framework = "SOC2 CC6.1".to_string();
        app.controls = vec![row];
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_main(f, &app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("SOC2 CC6.1"));
    }

    #[test]
    fn render_main_shows_uptime_column() {
        let mut app = App::new();
        let mut row = make_row_with_status("ctrl-up", "effective");
        row.uptime_percent = Some(98.5);
        app.controls = vec![row];
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_main(f, &app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("98.5%"));
    }

    #[test]
    fn render_main_no_status_shows_dash_confidence() {
        let mut app = App::new();
        app.controls = vec![ControlRow::empty("ctrl-none")];
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_main(f, &app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("-")); // dash for no confidence
    }

    // ---- render_detail tests ----

    #[test]
    fn render_detail_out_of_bounds_shows_error() {
        let app = App::new(); // no controls
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("No control data available"));
    }

    #[test]
    fn render_detail_out_of_bounds_large_index() {
        let mut app = App::new();
        app.controls = vec![make_row_with_status("ctrl-1", "effective")];
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 99)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("No control data available"));
    }

    #[test]
    fn render_detail_effective_status() {
        let mut app = App::new();
        app.controls = vec![make_row_with_status("ctrl-eff", "effective")];
        let backend = TestBackend::new(120, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("EFFECTIVE"));
        assert!(content.contains("ctrl-eff"));
    }

    #[test]
    fn render_detail_ineffective_status() {
        let mut app = App::new();
        app.controls = vec![make_row_with_status("ctrl-ineff", "ineffective")];
        let backend = TestBackend::new(120, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("INEFFECTIVE"));
    }

    #[test]
    fn render_detail_partial_status_yellow() {
        let mut app = App::new();
        app.controls = vec![make_row_with_status("ctrl-part", "partial")];
        let backend = TestBackend::new(120, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("PARTIAL"));
    }

    #[test]
    fn render_detail_no_status_shows_no_evaluation_data() {
        let mut app = App::new();
        app.controls = vec![ControlRow::empty("ctrl-none")];
        let backend = TestBackend::new(120, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("no evaluation data"));
    }

    #[test]
    fn render_detail_shows_evaluation_details() {
        let mut app = App::new();
        let mut row = make_row_with_status("ctrl-eval", "effective");
        if let Some(ref mut s) = row.status {
            s.evaluation_details = "All checks passed successfully".to_string();
        }
        app.controls = vec![row];
        let backend = TestBackend::new(120, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("All checks passed"));
    }

    #[test]
    fn render_detail_no_evidence_shows_message() {
        let mut app = App::new();
        let mut row = make_row_with_status("ctrl-noev", "effective");
        row.evidence = vec![];
        app.controls = vec![row];
        let backend = TestBackend::new(120, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("No evidence records found"));
    }

    #[test]
    fn render_detail_with_effective_evidence() {
        let mut app = App::new();
        let mut row = make_row_with_status("ctrl-ev", "effective");
        row.evidence = vec![make_evidence_with_status(
            StatusId::Effective,
            "effective",
        )];
        app.controls = vec![row];
        let backend = TestBackend::new(120, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("EFFECTIVE"));
        assert!(content.contains("passive"));
        assert!(content.contains("test.module"));
    }

    #[test]
    fn render_detail_with_ineffective_evidence() {
        let mut app = App::new();
        let mut row = make_row_with_status("ctrl-ev", "ineffective");
        row.evidence = vec![make_evidence_with_status(
            StatusId::Ineffective,
            "ineffective",
        )];
        app.controls = vec![row];
        let backend = TestBackend::new(120, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("INEFFECTIVE"));
    }

    #[test]
    fn render_detail_with_unknown_evidence_status() {
        let mut app = App::new();
        let mut row = make_row_with_status("ctrl-ev", "unknown");
        row.evidence = vec![make_evidence_with_status(
            StatusId::Unknown,
            "unknown",
        )];
        app.controls = vec![row];
        let backend = TestBackend::new(120, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
    }

    #[test]
    fn render_detail_with_other_evidence_status() {
        let mut app = App::new();
        let mut row = make_row_with_status("ctrl-ev", "other");
        row.evidence = vec![make_evidence_with_status(
            StatusId::Other,
            "other",
        )];
        app.controls = vec![row];
        let backend = TestBackend::new(120, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
    }

    #[test]
    fn render_detail_with_active_verification_confidence() {
        let mut app = App::new();
        let mut row = make_row_with_status("ctrl-ev", "effective");
        let mut ev = make_evidence_with_status(StatusId::Effective, "effective");
        ev.confidence_level = ConfidenceLevel::ActiveVerification;
        row.evidence = vec![ev];
        app.controls = vec![row];
        let backend = TestBackend::new(120, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("active"));
    }

    #[test]
    fn render_detail_with_transcript() {
        let mut app = App::new();
        let mut row = make_row_with_status("ctrl-tr", "effective");
        let mut ev = make_evidence_with_status(StatusId::Effective, "effective");
        ev.test_transcript = Some(TestTranscript {
            actions_attempted: vec![
                TranscriptAction {
                    action: "send_probe_request".to_string(),
                    timestamp: Utc::now(),
                    parameters: serde_json::json!({"url": "https://example.com"}),
                },
            ],
            observations: vec![
                TranscriptObservation {
                    observation: "request was blocked".to_string(),
                    timestamp: Utc::now(),
                    expected: true,
                },
                TranscriptObservation {
                    observation: "alert not fired".to_string(),
                    timestamp: Utc::now(),
                    expected: false,
                },
            ],
            cleanup_actions: vec![
                TranscriptCleanup {
                    action: "restore_rule".to_string(),
                    timestamp: Utc::now(),
                    success: true,
                },
                TranscriptCleanup {
                    action: "delete_temp_file".to_string(),
                    timestamp: Utc::now(),
                    success: false,
                },
            ],
        });
        row.evidence = vec![ev];
        app.controls = vec![row];
        let backend = TestBackend::new(120, 60);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("Test Transcripts"));
        assert!(content.contains("send_probe_request"));
        assert!(content.contains("request was blocked"));
        assert!(content.contains("OK"));
        assert!(content.contains("UNEXPECTED"));
        assert!(content.contains("restore_rule"));
        assert!(content.contains("FAILED"));
    }

    #[test]
    fn render_detail_mixed_evidence_with_and_without_transcript() {
        let mut app = App::new();
        let mut row = make_row_with_status("ctrl-mix", "effective");

        // First evidence: no transcript
        let ev1 = make_evidence_with_status(StatusId::Effective, "effective");

        // Second evidence: with transcript
        let mut ev2 = make_evidence_with_status(StatusId::Ineffective, "ineffective");
        ev2.metadata.module.name = "tester.module".to_string();
        ev2.test_transcript = Some(TestTranscript {
            actions_attempted: vec![TranscriptAction {
                action: "probe_port".to_string(),
                timestamp: Utc::now(),
                parameters: serde_json::Value::Null,
            }],
            observations: vec![],
            cleanup_actions: vec![],
        });

        row.evidence = vec![ev1, ev2];
        app.controls = vec![row];
        let backend = TestBackend::new(120, 60);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        // Transcript section should appear because at least one evidence has a transcript
        assert!(content.contains("Test Transcripts"));
        assert!(content.contains("probe_port"));
    }

    #[test]
    fn render_detail_no_transcripts_at_all() {
        let mut app = App::new();
        let mut row = make_row_with_status("ctrl-notr", "effective");
        // Evidence without transcripts
        row.evidence = vec![
            make_evidence_with_status(StatusId::Effective, "effective"),
            make_evidence_with_status(StatusId::Effective, "effective"),
        ];
        app.controls = vec![row];
        let backend = TestBackend::new(120, 60);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        // No transcript section
        assert!(!content.contains("Test Transcripts"));
    }

    #[test]
    fn render_detail_scroll_offset_skips_lines() {
        let mut app = App::new();
        let mut row = make_row_with_status("ctrl-scroll", "effective");
        // Add several evidence records so there are many lines
        for _ in 0..5 {
            row.evidence.push(make_evidence_with_status(
                StatusId::Effective,
                "effective",
            ));
        }
        app.controls = vec![row];
        // Scroll down a lot
        app.scroll_offset = 3;
        let backend = TestBackend::new(120, 60);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        // Just verify no panic with scroll offset
    }

    #[test]
    fn render_detail_scroll_offset_beyond_content() {
        let mut app = App::new();
        app.controls = vec![make_row_with_status("ctrl-bigscroll", "effective")];
        app.scroll_offset = 1000; // way beyond content
        let backend = TestBackend::new(120, 60);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        // No panic — visible_lines just becomes empty
    }

    #[test]
    fn render_detail_shows_header_with_control_id_and_name() {
        let mut app = App::new();
        let mut row = make_row_with_status("AC-001", "effective");
        row.control.name = "Access Control Policy".to_string();
        app.controls = vec![row];
        let backend = TestBackend::new(120, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("AC-001"));
        assert!(content.contains("Access Control Policy"));
    }

    #[test]
    fn render_detail_shows_description() {
        let mut app = App::new();
        let mut row = make_row_with_status("ctrl-desc", "effective");
        row.control.description = "Ensures access controls are in place".to_string();
        app.controls = vec![row];
        let backend = TestBackend::new(120, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("Ensures access controls"));
    }

    #[test]
    fn render_detail_shows_confidence_and_uptime() {
        let mut app = App::new();
        let mut row = make_row_with_status("ctrl-cu", "effective");
        row.uptime_percent = Some(97.3);
        if let Some(ref mut s) = row.status {
            s.confidence = "medium".to_string();
        }
        app.controls = vec![row];
        let backend = TestBackend::new(120, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("medium"));
        assert!(content.contains("97.3%"));
    }

    #[test]
    fn render_detail_shows_footer() {
        let mut app = App::new();
        app.controls = vec![make_row_with_status("ctrl-foot", "effective")];
        let backend = TestBackend::new(120, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("Scroll"));
        assert!(content.contains("Back"));
    }

    #[test]
    fn render_detail_evidence_timeline_header() {
        let mut app = App::new();
        app.controls = vec![make_row_with_status("ctrl-tl", "effective")];
        let backend = TestBackend::new(120, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("Evidence Timeline"));
    }

    #[test]
    fn render_detail_multiple_evidence_entries() {
        let mut app = App::new();
        let mut row = make_row_with_status("ctrl-multi", "effective");

        let mut ev1 = make_evidence_with_status(StatusId::Effective, "effective");
        ev1.metadata.module.name = "observer.aws_iam".to_string();
        ev1.confidence_level = ConfidenceLevel::PassiveObservation;

        let mut ev2 = make_evidence_with_status(StatusId::Ineffective, "ineffective");
        ev2.metadata.module.name = "tester.port_scan".to_string();
        ev2.confidence_level = ConfidenceLevel::ActiveVerification;

        row.evidence = vec![ev1, ev2];
        app.controls = vec![row];
        let backend = TestBackend::new(120, 60);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("observer.aws_iam"));
        assert!(content.contains("tester.port_scan"));
    }

    #[test]
    fn render_main_with_very_small_terminal() {
        // Test that rendering doesn't panic on tiny terminal
        let mut app = App::new();
        app.controls = vec![make_row_with_status("ctrl-1", "effective")];
        let backend = TestBackend::new(20, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_main(f, &app)).unwrap();
    }

    #[test]
    fn render_detail_with_very_small_terminal() {
        let mut app = App::new();
        app.controls = vec![make_row_with_status("ctrl-1", "effective")];
        let backend = TestBackend::new(20, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
    }

    #[test]
    fn render_main_header_shows_control_count() {
        let mut app = App::new();
        app.controls = vec![
            make_row_with_status("c1", "effective"),
            make_row_with_status("c2", "ineffective"),
            make_row_with_status("c3", "unknown"),
        ];
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_main(f, &app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("3 controls"));
    }

    #[test]
    fn render_detail_transcript_multiple_actions() {
        let mut app = App::new();
        let mut row = make_row_with_status("ctrl-multi-act", "effective");
        let mut ev = make_evidence_with_status(StatusId::Effective, "effective");
        ev.test_transcript = Some(TestTranscript {
            actions_attempted: vec![
                TranscriptAction {
                    action: "action_one".to_string(),
                    timestamp: Utc::now(),
                    parameters: serde_json::Value::Null,
                },
                TranscriptAction {
                    action: "action_two".to_string(),
                    timestamp: Utc::now(),
                    parameters: serde_json::Value::Null,
                },
                TranscriptAction {
                    action: "action_three".to_string(),
                    timestamp: Utc::now(),
                    parameters: serde_json::Value::Null,
                },
            ],
            observations: vec![],
            cleanup_actions: vec![],
        });
        row.evidence = vec![ev];
        app.controls = vec![row];
        let backend = TestBackend::new(120, 60);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render_detail(f, &app, 0)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let content = buffer_to_string(&buf);
        assert!(content.contains("Action 1"));
        assert!(content.contains("Action 2"));
        assert!(content.contains("Action 3"));
    }

    /// Helper to convert a ratatui Buffer into a single String for assertions.
    fn buffer_to_string(buf: &ratatui::buffer::Buffer) -> String {
        let mut s = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                let cell = &buf[(x, y)];
                s.push_str(cell.symbol());
            }
            s.push('\n');
        }
        s
    }
}
