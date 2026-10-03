use crate::capture::{Hit, Http};
use ratatui::{layout::Rect, widgets::ListState};
use std::{collections::BTreeSet, net::IpAddr};

/// Everything seen so far for one hostname.
pub struct Endpoint {
    pub host: String,
    pub ips: BTreeSet<IpAddr>,
    pub ports: BTreeSet<u16>,
    pub sources: BTreeSet<&'static str>,
    pub apps: BTreeSet<String>,
    pub urls: Vec<String>, // recent requested URLs (HTTP and MITM)
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
    pub mouse: bool, // mouse capture on (hover select); off lets the terminal select text
    pub mitm: bool, // proxy-only mode: show how to point a browser at it
    pub filter: Option<String>, // show only endpoints used by this app
}

impl App {
    pub fn new(interfaces: Vec<String>, root: bool) -> Self {
        let mut picker = ListState::default();
        picker.select(Some(0));
        Self { device: None, interfaces, picker, error: None, root, mouse: true, mitm: false, filter: None, endpoints: vec![], list: ListState::default(), list_area: Rect::default(), paused: false }
    }

    pub fn add(&mut self, hit: Hit) {
        if self.paused { return; }
        let i = match self.endpoints.iter().position(|e| e.host == hit.host) {
            Some(i) => i,
            None => {
                self.endpoints.push(Endpoint {
                    host: hit.host, ips: Default::default(), ports: Default::default(),
                    sources: Default::default(), apps: Default::default(), urls: vec![], packets: 0, bytes: 0, http: None,
                });
                self.endpoints.len() - 1
            }
        };
        let e = &mut self.endpoints[i];
        e.ips.extend(hit.ip);
        e.ports.insert(hit.port);
        e.sources.insert(hit.source);
        e.apps.extend(hit.app);
        e.packets += 1;
        e.bytes += hit.bytes as u64;
        if let Some(r) = &hit.http {
            let url = format!("{}://{}{}", if hit.source == "HTTP" { "http" } else { "https" }, e.host, r.target);
            if e.urls.last() != Some(&url) {
                e.urls.push(url);
                if e.urls.len() > 100 { e.urls.remove(0); }
            }
        }
        e.http = hit.http.or(e.http.take());
        if self.list.selected().is_none() { self.list.select(Some(0)); }
    }

    /// Endpoints passing the app filter; list indices refer to this.
    pub fn visible(&self) -> Vec<&Endpoint> {
        self.endpoints.iter().filter(|e| self.filter.as_ref().map_or(true, |f| e.apps.contains(f))).collect()
    }

    pub fn selected(&self) -> Option<&Endpoint> {
        self.visible().get(self.list.selected()?).copied()
    }

    /// Cycle the app filter: all -> each app seen (sorted) -> all.
    pub fn next_app(&mut self) {
        let apps: Vec<String> = self.endpoints.iter().flat_map(|e| e.apps.clone()).collect::<BTreeSet<_>>().into_iter().collect();
        let next = self.filter.as_ref().map_or(0, |f| apps.iter().position(|a| a == f).map_or(0, |i| i + 1));
        self.filter = apps.get(next).cloned();
        self.list.select(Some(0));
    }

    pub fn step(&mut self, delta: isize) {
        let n = if self.device.is_none() { self.interfaces.len() } else { self.visible().len() };
        let list = if self.device.is_none() { &mut self.picker } else { &mut self.list };
        let i = list.selected().unwrap_or(0) as isize;
        list.select(Some((i + delta).clamp(0, n.saturating_sub(1) as isize) as usize));
    }

    /// Select the row under the mouse (inside the list border).
    pub fn hover(&mut self, col: u16, row: u16) {
        let a = self.list_area;
        if col <= a.x || col >= a.right() - 1 || row <= a.y || row >= a.bottom() - 1 { return; }
        let i = self.list.offset() + (row - a.y - 1) as usize;
        if i < self.visible().len() { self.list.select(Some(i)); }
    }
}
