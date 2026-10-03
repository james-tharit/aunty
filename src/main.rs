//! Passive sniffer TUI: lists each hostname the machine talks to,
//! with IPs, ports and (for plain HTTP) request headers/params/body.
//! Usage: sudo aunty [interface]   (no interface: pick one in the TUI)
mod app;
mod capture;
mod proc;
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
    let mut app = app::App::new(capture::interfaces()?, unsafe { geteuid() } == 0);
    if let Some(name) = std::env::args().nth(1) {
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
