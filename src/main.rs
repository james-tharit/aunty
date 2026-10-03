//! Passive sniffer TUI: lists each hostname the machine talks to,
//! with IPs, ports and (for plain HTTP) request headers/params/body.
//! Usage: sudo aunty [interface]   (no interface: pick one in the TUI)
//!        aunty --mitm              (proxy only, no root; add an interface to sniff too)
mod app;
mod capture;
mod proc;
mod proxy;
mod ui;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, MouseButton, MouseEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{io, sync::mpsc, time::Duration};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (tx, rx) = mpsc::channel();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mitm = args.iter().any(|a| a == "--mitm");
    let iface = args.into_iter().find(|a| !a.starts_with("--"));
    // proxy-only mode needs no root
    let mut app = app::App::new(capture::interfaces()?, unsafe { geteuid() } == 0 || (mitm && iface.is_none()));
    if mitm {
        let l = std::net::TcpListener::bind(PROXY_ADDR)?;
        l.set_nonblocking(true)?;
        proxy::spawn(l, tx.clone()).map_err(|e| e.to_string())?;
        app.mitm = true;
        app.show_cmd = true;
        if iface.is_none() {
            app.device = Some(format!("MITM proxy {PROXY_ADDR}"));
        }
    }
    if let Some(name) = iface {
        start(&mut app, name, &tx);
    }

    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
    let mut term = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    let result = run(&mut term, app, tx, rx);

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    result
}

const PROXY_ADDR: &str = "127.0.0.1:8080";

extern "C" {
    fn geteuid() -> u32;
}

/// Open `name` and start capturing; on failure stay in the picker and show why.
fn start(app: &mut app::App, name: String, tx: &mpsc::Sender<capture::Hit>) {
    match capture::open(&name) {
        Ok(cap) => {
            capture::spawn(cap, tx.clone());
            app.error = None;
            app.device = Some(name);
        }
        Err(e) => app.error = Some(format!("{name}: {e}")),
    }
}

fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    data.chunks(3)
        .flat_map(|c| {
            let n = c.iter().enumerate().fold(0u32, |a, (i, &b)| a | (b as u32) << (16 - 8 * i));
            (0..4).map(move |i| if i <= c.len() { T[(n >> (18 - 6 * i)) as usize & 63] as char } else { '=' })
        })
        .collect()
}

/// Copy to the system clipboard via the OSC 52 escape (works over sudo/ssh; needs terminal support, e.g. kitty).
fn copy(text: Option<String>) {
    use std::io::Write;
    let Some(text) = text else { return };
    let _ = write!(io::stdout(), "\x1b]52;c;{}\x07", b64(text.as_bytes())).and_then(|_| io::stdout().flush());
}

#[test]
fn base64() {
    assert_eq!((b64(b"Man"), b64(b"Ma"), b64(b"M")), ("TWFu".into(), "TWE=".into(), "TQ==".into()));
}

fn run(
    term: &mut Terminal<CrosstermBackend<io::Stdout>>,
    mut app: app::App,
    tx: mpsc::Sender<capture::Hit>,
    rx: mpsc::Receiver<capture::Hit>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        term.draw(|f| ui::draw(f, &mut app))?;
        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(k) if app.show_cmd => match k.code {
                    KeyCode::Enter => {
                        copy(Some(app::BROWSER_CMD.into()));
                        app.copied = true;
                    }
                    KeyCode::Char('q') => return Ok(()),
                    _ => app.show_cmd = false,
                },
                Event::Key(k) => match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Up | KeyCode::Char('k') => app.step(-1),
                    KeyCode::Down | KeyCode::Char('j') => app.step(1),
                    KeyCode::Enter if app.device.is_none() => {
                        if let Some(name) = app.picker.selected().and_then(|i| app.interfaces.get(i)).cloned() {
                            start(&mut app, name, &tx);
                        }
                    }
                    KeyCode::Char('a') => app.next_app(),
                    KeyCode::Char('y') => copy(app.selected().map(|e| ui::details(e).to_string())),
                    KeyCode::Char('u') => copy(app.selected().map(|e| e.urls.last().unwrap_or(&e.host).clone())),
                    KeyCode::Char('b') if app.mitm => {
                        app.show_cmd = true;
                        app.copied = false;
                    }
                    KeyCode::Char(' ') => app.paused = !app.paused,
                    _ => {}
                },
                Event::Mouse(m) => match m.kind {
                    MouseEventKind::Moved | MouseEventKind::Down(MouseButton::Left) if app.device.is_some() => {
                        app.hover(m.column, m.row)
                    }
                    MouseEventKind::ScrollUp => app.step(-1),
                    MouseEventKind::ScrollDown => app.step(1),
                    _ => {}
                },
                _ => {}
            }
        }
        while let Ok(hit) = rx.try_recv() {
            app.add(hit);
        }
    }
}
