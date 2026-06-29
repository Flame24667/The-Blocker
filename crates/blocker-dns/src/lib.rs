mod server;

pub use server::{
    run_udp_dns_server, run_udp_dns_server_with_domain_checker,
    run_udp_dns_server_with_event_handler, DnsServerConfig, DnsServerError,
};

use blocker_core::{normalize_domain, BlockDecision, BlockerEngine};

pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_RCODE_SERVFAIL: u16 = 2;
pub const DNS_RCODE_NXDOMAIN: u16 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub domain: String,
    pub qtype: u16,
    pub qclass: u16,
    pub question_end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsQueryDecision {
    Forward {
        domain: String,
    },
    Block {
        domain: String,
        response_packet: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsPacketError {
    PacketTooShort,
    NoQuestion,
    LabelOutOfBounds,
    QuestionTooShort,
    InvalidLabel,
    InvalidDomain(String),
    UnsupportedCompressedQuestionName,
    Core(String),
}

impl std::fmt::Display for DnsPacketError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsPacketError::PacketTooShort => write!(formatter, "DNS packet is too short"),
            DnsPacketError::NoQuestion => write!(formatter, "DNS packet has no question"),
            DnsPacketError::LabelOutOfBounds => write!(formatter, "DNS label is out of bounds"),
            DnsPacketError::QuestionTooShort => write!(formatter, "DNS question is too short"),
            DnsPacketError::InvalidLabel => write!(formatter, "DNS label is invalid"),
            DnsPacketError::InvalidDomain(error) => write!(formatter, "invalid domain: {error}"),
            DnsPacketError::UnsupportedCompressedQuestionName => {
                write!(formatter, "compressed DNS question names are not supported")
            }
            DnsPacketError::Core(error) => write!(formatter, "blocker core error: {error}"),
        }
    }
}

impl std::error::Error for DnsPacketError {}

pub fn parse_dns_question(packet: &[u8]) -> Result<DnsQuestion, DnsPacketError> {
    if packet.len() < 12 {
        return Err(DnsPacketError::PacketTooShort);
    }
    
    let question_count = read_u16(packet, 4)?;

    if question_count == 0 {
        return Err(DnsPacketError::NoQuestion);
    }

    let mut offset = 12;
    let mut labels = Vec::new();

    loop {
        let length = *packet
            .get(offset)
            .ok_or(DnsPacketError::LabelOutOfBounds)?;

        offset += 1;

        if length == 0 {
            break;
        }

        if length & 0b1100_0000 != 0 {
            return Err(DnsPacketError::UnsupportedCompressedQuestionName);
        }

        let label_length = length as usize;
        let label_end = offset + label_length;

        if label_end > packet.len() {
            return Err(DnsPacketError::LabelOutOfBounds);
        }

        let label_bytes = &packet[offset..label_end];
        let label = std::str::from_utf8(label_bytes)
            .map_err(|_| DnsPacketError::InvalidLabel)?;

        labels.push(label.to_string());
        offset = label_end;
    }

    if offset + 3 > packet.len() {
        return Err(DnsPacketError::QuestionTooShort);
    }

    let qtype = read_u16(packet, offset)?;
    let qclass = read_u16(packet, offset + 2)?;
    let question_end = offset + 4;

    let domain = labels.join(".");
    let domain = normalize_domain(&domain)
        .map_err(|error| DnsPacketError::InvalidDomain(format!("{error:?}")))?;

    Ok(DnsQuestion {domain, qtype, qclass, question_end})
}

pub fn decide_dns_query(packet: &[u8], engine: &BlockerEngine, blocked_ttl_seconds: u32) -> Result<DnsQueryDecision, DnsPacketError> {
    let question = parse_dns_question(packet)?;

    let decision = engine
        .check_domain(&question.domain)
        .map_err(|error| DnsPacketError::Core(format!("{error:?}")))?;
    
    match decision {
        BlockDecision::Blocked { .. } => {
            let response_packet = build_block_response(packet, &question, blocked_ttl_seconds)?;

            Ok(DnsQueryDecision::Block {
                domain: question.domain,
                response_packet,
            })
        }
        BlockDecision::Allowed { .. } | BlockDecision::AllowedByDefault => {
            Ok(DnsQueryDecision::Forward {
                domain: question.domain,
            })
        }
    }
}

pub fn build_block_response(query_packet: &[u8], question: &DnsQuestion, ttl_seconds:u32) -> Result<Vec<u8>, DnsPacketError> {
    if query_packet.len() < 12 {
        return Err(DnsPacketError::PacketTooShort);
    }

    if question.question_end > query_packet.len() {
        return Err(DnsPacketError::QuestionTooShort);
    }

    let mut response = Vec::new();

    let query_flags = read_u16(query_packet, 2)?;
    let recursion_desired = query_flags & 0x0100;

    let answer_data: Option<Vec<u8>> = match question.qtype {
        DNS_TYPE_A => Some(vec![0,0,0,0]),
        DNS_TYPE_AAAA => Some(vec![0; 16]),
        _ => None,
    };

    let answer_count = if answer_data.is_some() { 1u16 } else { 0u16 };

    response.extend_from_slice(&query_packet[0..2]);

    let response_flags = 0x8000 | 0x0080 | recursion_desired;
    response.extend_from_slice(&response_flags.to_be_bytes());

    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&answer_count.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());

    response.extend_from_slice(&query_packet[12..question.question_end]);

    if let Some(answer_data) = answer_data {
        response.extend_from_slice(&[0xC0, 0x0C]);
        response.extend_from_slice(&question.qtype.to_be_bytes());
        response.extend_from_slice(&question.qclass.to_be_bytes());
        response.extend_from_slice(&ttl_seconds.to_be_bytes());
        response.extend_from_slice(&(answer_data.len() as u16).to_be_bytes());
        response.extend_from_slice(&answer_data);
    }

    Ok(response)
}

pub fn build_error_response(
    query_packet: &[u8],
    question: &DnsQuestion,
    response_code: u16,
) -> Result<Vec<u8>, DnsPacketError> {
    if query_packet.len() < 12 {
        return Err(DnsPacketError::PacketTooShort);
    }

    if question.question_end > query_packet.len() {
        return Err(DnsPacketError::QuestionTooShort);
    }

    let mut response = Vec::new();

    let query_flags = read_u16(query_packet, 2)?;
    let recursion_desired = query_flags & 0x0100;

    response.extend_from_slice(&query_packet[0..2]);

    let response_flags = 0x8000 | 0x0080 | recursion_desired | (response_code & 0x000F);
    response.extend_from_slice(&response_flags.to_be_bytes());

    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());

    response.extend_from_slice(&query_packet[12..question.question_end]);

    Ok(response)
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, DnsPacketError> {
    let bytes = packet
        .get(offset..offset + 2)
        .ok_or(DnsPacketError::PacketTooShort)?;

    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use blocker_core::BlockerEngine;

    #[test]
    fn parses_a_record_question() {
        let packet = make_query_packet("ads.example.com", DNS_TYPE_A);
        let question = parse_dns_question(&packet).unwrap();

        assert_eq!(question.domain, "ads.example.com");
        assert_eq!(question.qtype, DNS_TYPE_A);
        assert_eq!(question.qclass, DNS_CLASS_IN);
    }

    #[test]
    fn blocked_a_query_returns_zero_ipv4_response () {
        let packet = make_query_packet("ads.example.com", DNS_TYPE_A);

        let mut engine = BlockerEngine::new();
        engine
            .add_block_rule("ads.example.com", Some("test"), Some("ad"))
            .unwrap();

        let decision = decide_dns_query(&packet, &engine, 60).unwrap();

        match decision {
            DnsQueryDecision::Block {
                domain,
                response_packet,
            } => {
                assert_eq!(domain, "ads.example.com");

                let answer_count = u16::from_be_bytes([response_packet[6], response_packet[7]]);
                assert_eq!(answer_count, 1);
                assert!(response_packet.ends_with(&[0,0,0,0]));
            }
            DnsQueryDecision::Forward { .. } => {
                panic!("expected blocked DNS response");
            }
        }
    }

    #[test]
    fn blocked_aaaa_query_returns_zero_ipv6_response() {
        let packet = make_query_packet("ads.example.com", DNS_TYPE_AAAA);

        let mut engine = BlockerEngine::new();
        engine
            .add_block_rule("ads.example.com", Some("test"), Some("ad"))
            .unwrap();

        let decision = decide_dns_query(&packet, &engine, 60).unwrap();

        match decision {
            DnsQueryDecision::Block {
                domain,
                response_packet,
            } => {
                assert_eq!(domain, "ads.example.com");

                let answer_count = u16::from_be_bytes([response_packet[6], response_packet[7]]);
                assert_eq!(answer_count, 1);

                assert!(response_packet.ends_with(&[0; 16]));
            }
            DnsQueryDecision::Forward { .. } => {
                panic!("expected blocked DNS response");
            }
        }
    }

    #[test]
    fn allowed_query_is_forwarded() {
        let packet = make_query_packet("normal.example.com", DNS_TYPE_A);
        let engine = BlockerEngine::new();

        let decision = decide_dns_query(&packet, &engine, 60).unwrap();

        assert_eq!(
            decision,
            DnsQueryDecision::Forward {
                domain: "normal.example.com".to_string()
            }
        );
    }

    #[test]
    fn allowlist_overrides_dns_block() {
        let packet = make_query_packet("ads.example.com", DNS_TYPE_A);

        let mut engine = BlockerEngine::new();
        engine
            .add_block_rule("ads.example.com", Some("test"), Some("ad"))
            .unwrap();
        engine
            .add_allow_rule("ads.example.com", Some("test"), Some("user"))
            .unwrap();

        let decision = decide_dns_query(&packet, &engine, 60).unwrap();

        assert_eq!(
            decision,
            DnsQueryDecision::Forward {
                domain: "ads.example.com".to_string()
            }
        );
    }

    fn make_query_packet(domain: &str, qtype: u16) -> Vec<u8> {
        let mut packet = Vec::new();

        packet.extend_from_slice(&0x1234u16.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());

        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }

        packet.push(0);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        packet
    }
}