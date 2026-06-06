use ratatui::{
    layout::{Constraint, Direction, Layout, Alignment},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, List, ListItem, ListState}, // Added ListState
    Frame,
};
use crate::app::App;

/// Draw the entire TUI
pub fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
            ]
            .as_ref(),
        )
        .split(f.area());

    // Draw header
    draw_header(f, chunks[0], app);

    // Draw packet list
    draw_packet_list(f, chunks[1], app);

    // Draw footer
    draw_footer(f, chunks[2], app);
}

/// Draw header with title and pause status
fn draw_header(f: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let title = Line::from(vec![
        Span::styled(
            "🔍 Aunty Network Sniffer",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" - "),
        Span::styled(
            format!("{} packets", app.packets.len()),
            Style::default().fg(Color::Yellow),
        ),
        if app.paused {
            Span::styled(" [PAUSED]", Style::default().fg(Color::Red))
        } else {
            Span::styled(" [CAPTURING]", Style::default().fg(Color::Green))
        },
    ]);

    let header = Paragraph::new(title)
        .block(Block::default().borders(Borders::BOTTOM).title("Packet Sniffer"))
        .alignment(Alignment::Left);

    f.render_widget(header, area);
}

/// Draw the packet list with built-in scrolling support
fn draw_packet_list(f: &mut Frame, area: ratatui::layout::Rect, app: &mut App) {
    let items: Vec<ListItem> = app
        .packets
        .iter()
        .map(|packet| {
            let content = format!(
                "{:<10} | {:<30} | {:<30} | {:<10} | {}B",
                packet.protocol, 
                truncate_str(&packet.source, 28),
                truncate_str(&packet.destination, 28),
                packet.port_info,
                packet.length
            );

            ListItem::new(content)
        })
        .collect();

    // Configure your list and use built-in highlight styling 
    // instead of manually calculating indices inside map()
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Captured Packets"),
        )
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        );

    // 1. Sync your app's manual selected_index into Ratatui's ListState
    let mut list_state = ListState::default();
    if !app.packets.is_empty() {
        list_state.select(Some(app.selected_index));
    } else {
        list_state.select(None);
    }

    // 2. CRITICAL: Use render_stateful_widget instead of render_widget
    // This forces Ratatui to manage viewport tracking / tracking scroll offsets.
    f.render_stateful_widget(list, area, &mut list_state);

    // Draw selected packet details on the right if there's space
    if area.width > 150 {
        draw_selected_packet_details(f, area, app);
    }
}

/// Draw details of the selected packet
fn draw_selected_packet_details(f: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    if let Some(packet) = app.selected_packet() {
        let details = vec![
            format!("Protocol: {}", packet.protocol),
            format!("Source: {}", packet.source),
            format!("Destination: {}", packet.destination),
            format!("Ports: {}", packet.port_info),
            format!("Length: {} bytes", packet.length),
        ];

        let text: Vec<Line> = details.iter().map(|l| Line::from(l.as_str())).collect();

        let details_widget = Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Packet Details"),
            )
            .style(Style::default().fg(Color::Cyan));

        // Position on the right side
        let right_area = ratatui::layout::Rect {
            x: area.width / 2,
            y: area.y,
            width: area.width / 2,
            height: area.height,
        };

        f.render_widget(details_widget, right_area);
    }
}

/// Draw footer with keyboard shortcuts
fn draw_footer(f: &mut Frame, area: ratatui::layout::Rect, _app: &App) {
    let instructions = vec![
        Span::styled("↑↓", Style::default().fg(Color::Cyan)),
        Span::raw(" Navigate • "),
        Span::styled("Space", Style::default().fg(Color::Cyan)),
        Span::raw(" Pause/Resume • "),
        Span::styled("q", Style::default().fg(Color::Cyan)),
        Span::raw(" Quit"),
    ];

    let footer = Paragraph::new(Line::from(instructions))
        .block(Block::default().borders(Borders::TOP))
        .alignment(Alignment::Center);

    f.render_widget(footer, area);
}

/// Truncate string to a maximum length with ellipsis
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
}