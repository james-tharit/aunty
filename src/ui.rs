use crate::app::{App, Endpoint};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Text},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};

pub fn draw(f: &mut Frame, app: &mut App) {
    let [main, foot] = Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(f.area());
    let [left, right] = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(main);

    let title = format!(
        " {} · app: {} · {} endpoints · {} packets seen{} ",
        app.device.as_deref().unwrap_or("-"),
        app.filter.as_deref().unwrap_or("all"),
        app.visible().len(),
        crate::capture::SEEN.load(std::sync::atomic::Ordering::Relaxed),
        if app.paused { " · PAUSED" } else { "" }
    );
    let items: Vec<ListItem> = app
        .visible()
        .iter()
        .map(|e| {
            let apps = e.apps.iter().cloned().collect::<Vec<_>>().join(",");
            ListItem::new(format!("{}  [{}] {}", e.host, e.sources.iter().copied().collect::<Vec<_>>().join("+"), apps))
        })
        .collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD));
    f.render_stateful_widget(list, left, &mut app.list);
    app.list_area = left;

    let text = app.selected().map(details).unwrap_or_else(|| Text::raw("waiting for traffic..."));
    let pane = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(" Details "))
        .wrap(Wrap { trim: false });
    f.render_widget(pane, right);

    let footer = if app.root {
        Paragraph::new("hover/↑↓ select · a app filter · space pause · q quit").style(Style::new().fg(Color::Gray))
    } else {
        Paragraph::new(WARN).style(Style::new().fg(Color::Yellow))
    };
    f.render_widget(footer, foot);

    if app.device.is_none() {
        picker(f, app);
    }
}

const WARN: &str = "⚠ not running as root: capture will likely fail. Re-run with sudo.";

fn picker(f: &mut Frame, app: &mut App) {
    let a = f.area();
    let (w, h) = (60.min(a.width), (app.interfaces.len() as u16 + 10).min(a.height));
    let area = Rect { x: a.x + (a.width - w) / 2, y: a.y + (a.height - h) / 2, width: w, height: h };
    let block = Block::default().borders(Borders::ALL).title(" Select interface · ↑↓ Enter · q quit ");
    let inner = block.inner(area);
    f.render_widget(Clear, area);
    f.render_widget(block, area);

    let mut msgs = vec![];
    if !app.root {
        msgs.push(Line::styled(WARN, Style::new().fg(Color::Yellow)));
    }
    if let Some(e) = &app.error {
        msgs.push(Line::styled(format!("error: {e}"), Style::new().fg(Color::Red)));
    }
    let mh = (msgs.len() as u16 * 3).min(inner.height / 2);
    let [top, bottom] = Layout::vertical([Constraint::Length(mh), Constraint::Min(1)]).areas(inner);
    f.render_widget(Paragraph::new(msgs).wrap(Wrap { trim: true }), top);

    let list = List::new(app.interfaces.iter().map(|i| ListItem::new(i.as_str())))
        .highlight_style(Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD));
    f.render_stateful_widget(list, bottom, &mut app.picker);
}

fn details(e: &Endpoint) -> Text<'static> {
    let head = |s: &str| Line::styled(s.to_string(), Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    let kv = |k: &str, v: &str| Line::raw(format!("  {k}: {v}"));
    let mut t = vec![
        Line::styled(e.host.clone(), Style::new().add_modifier(Modifier::BOLD)),
        Line::raw(format!("{} packets · {} B", e.packets, e.bytes)),
        Line::raw(format!("apps: {}", if e.apps.is_empty() { "unknown".into() } else { e.apps.iter().cloned().collect::<Vec<_>>().join(", ") })),
        Line::raw(""),
        head("IP addresses"),
    ];
    if e.ips.is_empty() {
        t.push(Line::raw("  unknown (seen only as a DNS query)"));
    }
    t.extend(e.ips.iter().map(|ip| Line::raw(format!("  {ip}"))));
    t.push(Line::raw(""));
    t.push(head("Ports"));
    t.push(Line::raw(format!("  {}", e.ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", "))));
    t.push(Line::raw(""));

    match &e.http {
        Some(r) => {
            t.push(head("Request"));
            t.push(Line::raw(format!("  {} {}", r.method, r.path)));
            t.push(Line::raw(""));
            t.push(head("Parameters"));
            if r.query.is_empty() { t.push(Line::raw("  (none)")); }
            t.extend(r.query.iter().map(|(k, v)| kv(k, v)));
            t.push(Line::raw(""));
            t.push(head("Headers"));
            t.extend(r.headers.iter().map(|(k, v)| kv(k, v)));
            t.push(Line::raw(""));
            t.push(head("Body"));
            t.extend(if r.body.is_empty() { vec!["  (empty in this packet)"] } else { r.body.lines().collect() }.into_iter().map(|l| Line::raw(format!("  {l}"))));
        }
        None if e.sources.contains("TLS") => {
            t.push(Line::styled(
                "Encrypted (TLS): headers, parameters and body are not visible.\nOnly the hostname is, from the ClientHello.",
                Style::new().fg(Color::Yellow),
            ));
        }
        None => {}
    }
    Text::from(t)
}
