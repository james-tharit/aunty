use crate::packet::PacketInfo;

/// Application state and packet buffer
pub struct App {
    pub packets: Vec<PacketInfo>,
    pub selected_index: usize,
    pub paused: bool,
    pub should_quit: bool,
    pub max_packets: usize,
}

impl App {
    pub fn new(max_packets: usize) -> Self {
        Self {
            packets: Vec::new(),
            selected_index: 0,
            paused: false,
            should_quit: false,
            max_packets,
        }
    }

    /// Add a new packet, maintaining max size by removing old ones
    pub fn add_packet(&mut self, packet: PacketInfo) {
        if !self.paused {
            self.packets.insert(0, packet);
            if self.packets.len() > self.max_packets {
                self.packets.pop();
            }
        }
    }

    /// Move selection up
    pub fn select_up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    /// Move selection down
    pub fn select_down(&mut self) {
        if self.selected_index < self.packets.len().saturating_sub(1) {
            self.selected_index += 1;
        }
    }

    /// Toggle pause state
    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
    }

    /// Get the selected packet
    pub fn selected_packet(&self) -> Option<&PacketInfo> {
        self.packets.get(self.selected_index)
    }
}
