use crate::capture::{Hit, Http};
use ratatui::{layout::Rect, widgets::ListState};
use std::{collections::BTreeSet, net::IpAddr};

/// Everything seen so far for one hostname.
pub struct Endpoint {
    pub host: String,
    pub ips: BTreeSet<IpAddr>,
    pub ports: BTreeSet<u16>,
    pub sources: BTreeSet<&'static str>,
    pub packets: u32,
    pub bytes: u64,
    pub http: Option<Http>, // latest plain-HTTP request
}

pub struct App {
    pub device: Option<String>, // None while the interface picker is showing
    pub interfaces: Vec<String>,
    pub picker: ListState,
    pub error: Option<String>,
    pub root: bool,
    pub endpoints: Vec<Endpoint>,
    pub list: ListState,
    pub list_area: Rect, // set by ui, used for mouse hit-testing
    pub paused: bool,
}

impl App {
    pub fn new(interfaces: Vec<String>, root: bool) -> Self {
        let mut picker = ListState::default();
        picker.select(Some(0));
        Self { device: None, interfaces, picker, error: None, root, endpoints: vec![], list: ListState::default(), list_area: Rect::default(), paused: false }
    }

    pub fn add(&mut self, hit: Hit) {
        if self.paused { return; }
        let i = match self.endpoints.iter().position(|e| e.host == hit.host) {
            Some(i) => i,
            None => {
                self.endpoints.push(Endpoint {
                    host: hit.host, ips: Default::default(), ports: Default::default(),
                    sources: Default::default(), packets: 0, bytes: 0, http: None,
                });
                self.endpoints.len() - 1
            }
        };
        let e = &mut self.endpoints[i];
        e.ips.extend(hit.ip);
        e.ports.insert(hit.port);
        e.sources.insert(hit.source);
        e.packets += 1;
        e.bytes += hit.bytes as u64;
        e.http = hit.http.or(e.http.take());
        if self.list.selected().is_none() { self.list.select(Some(0)); }
    }

    pub fn selected(&self) -> Option<&Endpoint> {
        self.endpoints.get(self.list.selected()?)
    }

    pub fn step(&mut self, delta: isize) {
        let (list, n) = match self.device {
            None => (&mut self.picker, self.interfaces.len()),
            Some(_) => (&mut self.list, self.endpoints.len()),
        };
        let i = list.selected().unwrap_or(0) as isize;
        list.select(Some((i + delta).clamp(0, n.saturating_sub(1) as isize) as usize));
    }

    /// Select the row under the mouse (inside the list border).
    pub fn hover(&mut self, col: u16, row: u16) {
        let a = self.list_area;
        if col <= a.x || col >= a.right() - 1 || row <= a.y || row >= a.bottom() - 1 { return; }
        let i = self.list.offset() + (row - a.y - 1) as usize;
        if i < self.endpoints.len() { self.list.select(Some(i)); }
    }
}
