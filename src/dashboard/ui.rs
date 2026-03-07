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
