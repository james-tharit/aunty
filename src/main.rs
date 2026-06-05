mod app;
mod packet;
mod packet_capture;
mod ui;

use app::App;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    Terminal,
};
use std::sync::mpsc;
use std::time::Duration;
use std::io;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    // Create the application
    let mut app = App::new(500); // Keep last 500 packets in memory

    // Create communication channel
    let (tx, rx) = mpsc::channel::<packet::PacketInfo>();

    // Start the packet capture thread
    packet_capture::start_capture_thread(tx);

    // Main event loop
    let result = run_app(&mut terminal, &mut app, rx);

    // Cleanup terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        println!("Error: {}", e);
    }

    Ok(())
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    rx: std::sync::mpsc::Receiver<packet::PacketInfo>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        // Render the UI
        terminal.draw(|f| {
            ui::draw(f, app);
        })?;

        // Non-blocking input event loop with timeout
        if crossterm::event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        app.should_quit = true;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        app.select_up();
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        app.select_down();
                    }
                    KeyCode::Char(' ') => {
                        app.toggle_pause();
                    }
                    _ => {}
                }
            }
        }

        // Process incoming packets from the capture thread
        // Use try_recv to avoid blocking
        while let Ok(packet) = rx.try_recv() {
            app.add_packet(packet);
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}