use crate::{
    build_block_response, build_error_response, parse_dns_question, DnsPacketError,
    DNS_RCODE_NXDOMAIN, DNS_RCODE_SERVFAIL,
};
use blocker_core::{BlockAction, BlockEvent, BlockerEngine};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DnsServerConfig {
    pub listen_addr: SocketAddr,
    pub upstream_addr: SocketAddr,
    pub blocked_ttl_seconds: u32,
    pub upstream_timeout: Duration,
}

#[derive(Debug)]
pub enum DnsServerError {
    Io(std::io::Error),
    Packet(DnsPacketError),
}

#[derive(Debug)]
struct HandledDnsPacket {
    response_packet: Vec<u8>,
    event: Option<BlockEvent>,
}

impl std::fmt::Display for DnsServerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsServerError::Io(error) => write!(formatter, "I/O error: {error}"),
            DnsServerError::Packet(error) => write!(formatter, "DNS packet error: {error}"),
        }
    }
}

impl std::error::Error for DnsServerError {}

impl From<std::io::Error> for DnsServerError {
    fn from(error: std::io::Error) -> Self {
        DnsServerError::Io(error)
    }
}

impl From<DnsPacketError> for DnsServerError {
    fn from(error: DnsPacketError) -> Self {
        DnsServerError::Packet(error)
    }
}

pub fn run_udp_dns_server(
    config: DnsServerConfig,
    engine: &BlockerEngine,
) -> Result<(), DnsServerError> {
    run_udp_dns_server_with_event_handler(config, engine, |_event| {})
}

pub fn run_udp_dns_server_with_event_handler<F>(
    config: DnsServerConfig,
    engine: &BlockerEngine,
    event_handler: F,
) -> Result<(), DnsServerError>
where
    F: FnMut(&BlockEvent),
{
    run_udp_dns_server_with_domain_checker(
        config,
        |domain| {
            engine
                .check_domain_with_event(domain)
                .map_err(|error| format!("{error:?}"))
        },
        event_handler,
    )
}

pub fn run_udp_dns_server_with_domain_checker<C, F>(
    config: DnsServerConfig,
    mut domain_checker: C,
    mut event_handler: F,
) -> Result<(), DnsServerError>
where
    C: FnMut(&str) -> Result<BlockEvent, String>,
    F: FnMut(&BlockEvent),
{
    let socket = UdpSocket::bind(config.listen_addr)?;

    println!("The Blocker DNS server is running");
    println!("  listening: {}", config.listen_addr);
    println!("  upstream: {}", config.upstream_addr);
    println!("  blocked ttl: {} seconds", config.blocked_ttl_seconds);
    println!();
    println!("Press Ctrl+C to stop.");
    println!();

    let mut buffer = [0u8; 4096];

    loop {
        let (packet_len, client_addr) = socket.recv_from(&mut buffer)?;
        let query_packet = &buffer[..packet_len];

        println!("RECV {packet_len} bytes from {client_addr}");

        match handle_dns_packet_with_domain_checker(
            query_packet,
            &config,
            &mut domain_checker,
        ) {
            Ok(handled) => {
                if let Some(event) = handled.event.as_ref() {
                    event_handler(event);
                }

                let sent = socket.send_to(&handled.response_packet, client_addr)?;
                println!("SENT {sent} bytes to {client_addr}");
            }
            Err(error) => {
                eprintln!("Failed to handle DNS packet from {client_addr}: {error}");
            }
        }
    }
}

fn handle_dns_packet_with_domain_checker<C>(
    query_packet: &[u8],
    config: &DnsServerConfig,
    domain_checker: &mut C,
) -> Result<HandledDnsPacket, DnsServerError>
where
    C: FnMut(&str) -> Result<BlockEvent, String>,
{
    let question = parse_dns_question(query_packet)?;

    if is_reverse_lookup_domain(&question.domain) {
        println!("NXDOMAIN {}", question.domain);

        let response_packet =
            build_error_response(query_packet, &question, DNS_RCODE_NXDOMAIN)?;

        return Ok(HandledDnsPacket {
            response_packet,
            event: None,
        });
    }

    let event = domain_checker(&question.domain).map_err(DnsPacketError::Core)?;

    match event.action {
        BlockAction::Blocked => {
            println!("BLOCK {}", event.domain);

            let response_packet =
                build_block_response(query_packet, &question, config.blocked_ttl_seconds)?;

            Ok(HandledDnsPacket {
                response_packet,
                event: Some(event),
            })
        }
        BlockAction::AllowedByUserRule | BlockAction::AllowedByDefault => {
            println!("FORWARD {}", event.domain);

            let response_packet = match forward_dns_query(query_packet, config) {
                Ok(response) => response,
                Err(error) => {
                    eprintln!("UPSTREAM FAILED for {}: {error}", event.domain);

                    build_error_response(query_packet, &question, DNS_RCODE_SERVFAIL)?
                }
            };

            Ok(HandledDnsPacket {
                response_packet,
                event: Some(event),
            })
        }
    }
}

fn forward_dns_query(
    query_packet: &[u8],
    config: &DnsServerConfig,
) -> Result<Vec<u8>, DnsServerError> {
    let upstream_socket = UdpSocket::bind("0.0.0.0:0")?;
    upstream_socket.set_read_timeout(Some(config.upstream_timeout))?;
    upstream_socket.set_write_timeout(Some(config.upstream_timeout))?;

    upstream_socket.send_to(query_packet, config.upstream_addr)?;

    let mut response_buffer = [0u8; 4096];
    let (response_len, _from_addr) = upstream_socket.recv_from(&mut response_buffer)?;

    Ok(response_buffer[..response_len].to_vec())
}

fn is_reverse_lookup_domain(domain: &str) -> bool {
    domain.ends_with(".in-addr.arpa") || domain.ends_with(".ip6.arpa")
}