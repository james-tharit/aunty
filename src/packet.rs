/// Represents a captured network packet with parsed information
#[derive(Clone, Debug)]
pub struct PacketInfo {
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub port_info: String,
    pub length: u32,
    #[allow(dead_code)]
    pub timestamp: std::time::SystemTime,
}

impl PacketInfo {
    pub fn new(
        protocol: String,
        source: String,
        destination: String,
        port_info: String,
        length: u32,
    ) -> Self {
        Self {
            protocol,
            source,
            destination,
            port_info,
            length,
            timestamp: std::time::SystemTime::now(),
        }
    }

    /// Format packet info as a table row string
    #[allow(dead_code)]
    pub fn format_row(&self) -> String {
        format!(
            "{:<10} | {:<40} | {:<40} | {:<10} | {:<10}",
            self.protocol, self.source, self.destination, self.port_info, self.length
        )
    }
}
