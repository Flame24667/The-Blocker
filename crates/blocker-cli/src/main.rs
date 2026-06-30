use blocker_core::{BlockAction, BlockDecision, BlockEvent, BlockerEngine};
use blocker_db::{BlockerDb, StoredBlockEvent};
use blocker_dns::{
    decide_dns_query, run_udp_dns_server_with_domain_checker, DnsQueryDecision, DnsServerConfig,
    DNS_CLASS_IN, DNS_TYPE_A,
};
use blocker_api::{run_api_server, ApiServerConfig};
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::thread;

#[derive(Debug, Default)]
struct CheckCommand {
    domain: String,
    rule_files: Vec<String>,
    block_rules: Vec<String>,
    allow_rules: Vec<String>,
    db_path: Option<String>,
}

#[derive(Debug)]
struct EventsCommand {
    db_path: String,
    limit: i64,
}

#[derive(Debug)]
struct AllowCommand {
    domain: String,
    db_path: String,
}

#[derive(Debug)]
struct UnallowCommand {
    domain: String,
    db_path: String,
}

#[derive(Debug)]
struct AllowlistCommand {
    db_path: String,
}

#[derive(Debug, Default)]
struct DnsServeCommand {
    rule_files: Vec<String>,
    block_rules: Vec<String>,
    allow_rules: Vec<String>,
    db_path: Option<String>,
    listen_addr: String,
    upstream_addr: String,
    blocked_ttl_seconds: u32,
}

#[derive(Debug)]
struct DnsProbeCommand {
    domain: String,
    server_addr: String,
}

#[derive(Debug)]
struct ApiServeCommand {
    db_path: String,
    listen_addr: String,
}

#[derive(Debug, Default)]
struct DevRunCommand {
    rule_files: Vec<String>,
    block_rules: Vec<String>,
    allow_rules: Vec<String>,
    db_path: String,
    dns_listen_addr: String,
    api_listen_addr: String,
    upstream_addr: String,
    blocked_ttl_seconds: u32,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        print_help();
        return Ok(());
    }

    match args[0].as_str() {
        "check" => {
            let command = parse_check_command(&args[1..]).map_err(invalid_input)?;
            run_check(command)?;
        }
        "dns-check" => {
            let command = parse_check_command(&args[1..]).map_err(invalid_input)?;
            run_dns_check(command)?;
        }
        "dns-serve" => {
            let command = parse_dns_serve_command(&args[1..]).map_err(invalid_input)?;
            run_dns_serve(command)?;
        }
        "dns-probe" => {
            let command = parse_dns_probe_command(&args[1..]).map_err(invalid_input)?;
            run_dns_probe(command)?;
        }
        "api-serve" => {
            let command = parse_api_serve_command(&args[1..]).map_err(invalid_input)?;
            run_api_serve(command)?;
        }
        "dev-run" => {
            let command = parse_dev_run_command(&args[1..]).map_err(invalid_input)?;
            run_dev(command)?;
        }
        "events" => {
            let command = parse_events_command(&args[1..]).map_err(invalid_input)?;
            run_events(command)?;
        }
        "allow" => {
            let command = parse_allow_command(&args[1..]).map_err(invalid_input)?;
            run_allow(command)?;
        }
        "unallow" => {
            let command = parse_unallow_command(&args[1..]).map_err(invalid_input)?;
            run_unallow(command)?;
        }
        "allowlist" => {
            let command = parse_allowlist_command(&args[1..]).map_err(invalid_input)?;
            run_allowlist(command)?;
        }
        "help" | "--help" | "-h" => {
            print_help();
        }
        unknown => {
            return Err(invalid_input(format!("Unknown command: {unknown}")).into());
        }
    }

    Ok(())
}

fn run_check(command: CheckCommand) -> Result<(), Box<dyn Error>> {
    let mut engine = BlockerEngine::new();

    let db = if let Some(db_path) = &command.db_path {
        Some(BlockerDb::open(db_path.as_str())?)
    } else {
        None
    };

    if let Some(db) = &db {
        for domain in db.list_allow_domains()? {
            engine.add_allow_rule(&domain, Some("db-allowlist"), Some("user"))?;
        }
    }

    for rule_file in &command.rule_files {
        let text = fs::read_to_string(rule_file.as_str())?;
        let report = engine.load_rules_from_text(&text, Some(rule_file), None);

        println!("Loaded rules from: {rule_file}");
        println!("  added block rules: {}", report.added_block_rules);
        println!("  added allow rules: {}", report.added_allow_rules);
        println!("  ignored lines: {}", report.ignored_lines);
        println!("  skipped rules: {}", report.skipped_count());

        if !report.skipped_rules.is_empty() {
            println!("  skipped detail:");
            for issue in report.skipped_rules.iter().take(5) {
                println!(
                    "    line {}: {} ({})",
                    issue.line_number, issue.line, issue.reason
                );
            }

            if report.skipped_rules.len() > 5 {
                println! (
                    "    ... and {} more", report.skipped_rules.len() - 5
                );
            }
        }

        println!();
    }

    for domain in &command.block_rules {
        engine.add_block_rule(domain, Some("cli"), Some("manual"))?;
    }

    for domain in &command.allow_rules {
        engine.add_allow_rule(domain, Some("cli"), Some("manual"))?;
    }

    let decision = engine.check_domain(&command.domain)?;

    match decision {
        BlockDecision::Blocked { .. } => {
            println!("BLOCKED: {}", command.domain);
            println!("{decision:#?}");
        }
        BlockDecision::Allowed { .. } => {
            println!("ALLOWED BY LIST: {}", command.domain);
            println!("{decision:#?}");
        }
        BlockDecision::AllowedByDefault => {
            println!("ALLOWED BY DEFAULT: {}", command.domain);
            println!("{decision:#?}");
        }
    }

    println!();

    let event = engine.check_domain_with_event(&command.domain)?;
    print_event_preview(&event);

    if let Some(db) = &db {
        if should_store_event(&event.action) {
            let id = db.record_event(&event)?;
            println!();
            println!("Saved event to database:");
            println!("  id: {id}");
            println!(
                "  db: {}",
                command.db_path.as_deref().unwrap_or("unknown database")
            );
        } else {
            println!();
            println!("Not saved to database because this was allowed by default");
        }
    }

    Ok(())
}

fn run_dns_check(command: CheckCommand) -> Result<(), Box<dyn Error>> {
    let mut engine = BlockerEngine::new();

    let db = if let Some(db_path) = &command.db_path {
        Some(BlockerDb::open(db_path.as_str())?)
    } else {
        None
    };

    if let Some(db) = &db {
        for domain in db.list_allow_domains()? {
            engine.add_allow_rule(&domain, Some("db-allowlist"), Some("user"))?;
        }
    }

    for rule_file in &command.rule_files {
        let text = fs::read_to_string(rule_file.as_str())?;
        let report = engine.load_rules_from_text(&text, Some(rule_file), None);

        println!("Loaded rules from: {rule_file}");
        println!("  added block rules: {}", report.added_block_rules);
        println!("  added allow rules: {}", report.added_allow_rules);
        println!("  ignored lines: {}", report.ignored_lines);
        println!("  skipped rules: {}", report.skipped_count());
        println!();
    }

    for domain in &command.block_rules {
        engine.add_block_rule(domain, Some("cli"), Some("manual"))?;
    }

    for domain in &command.allow_rules {
        engine.add_allow_rule(domain, Some("cli"), Some("manual"))?;
    }

    let query_packet = make_dns_query_packet(&command.domain, DNS_TYPE_A);

    let decision = decide_dns_query(&query_packet, &engine, 60)?;

    println!("DNS check:");
    println!("  domain: {}", command.domain);
    println!("  qtype: A");
    println!();

    match decision {
        DnsQueryDecision::Forward { domain } => {
            println!("DNS FORWARD:");
            println!("  domain: {domain}");
            println!("  reason: allowed by blocker engine");
        }
        DnsQueryDecision::Block {
            domain,
            response_packet,
        } => {
            println!("DNS BLOCK:");
            println!("  domain: {domain}");
            println!("  response bytes: {}", response_packet.len());
            println!("  blocked answer: 0.0.0.0");
        }
    }

    Ok(())
}

fn run_dns_serve(command: DnsServeCommand) -> Result<(), Box<dyn Error>> {
    let mut base_engine = BlockerEngine::new();

    if let Some(db_path) = &command.db_path {
        let db = BlockerDb::open(db_path.as_str())?;
        let block_count = db.list_block_domains()?.len();
        let allow_count = db.list_allow_domains()?.len();

        println!("Dynamic lists enabled:");
        println!("  db: {db_path}");
        println!("  current blocked domains: {block_count}");
        println!("  current allowed domains: {allow_count}");
        println!();
    }

    for rule_file in &command.rule_files {
        let text = fs::read_to_string(rule_file.as_str())?;
        let report = base_engine.load_rules_from_text(&text, Some(rule_file), None);

        println!("Loaded rules from: {rule_file}");
        println!("  added block rules: {}", report.added_block_rules);
        println!("  added allow rules: {}", report.added_allow_rules);
        println!("  ignored lines: {}", report.ignored_lines);
        println!("  skipped rules: {}", report.skipped_count());
        println!();
    }

    for domain in &command.block_rules {
        base_engine.add_block_rule(domain, Some("cli"), Some("manual"))?;
    }

    for domain in &command.allow_rules {
        base_engine.add_allow_rule(domain, Some("cli"), Some("manual"))?;
    }

    let listen_addr: SocketAddr = command.listen_addr.parse()?;
    let upstream_addr: SocketAddr = command.upstream_addr.parse()?;

    let config = DnsServerConfig {
        listen_addr,
        upstream_addr,
        blocked_ttl_seconds: command.blocked_ttl_seconds,
        upstream_timeout: Duration::from_millis(700),
    };

    let checker_db_path = command.db_path.clone();
    let logger_db_path = command.db_path.clone();

    run_udp_dns_server_with_domain_checker(
        config,
        move |domain| {
            let mut request_engine = base_engine.clone();

            if let Some(db_path) = checker_db_path.as_deref() {
                let db = BlockerDb::open(db_path).map_err(|error| error.to_string())?;

                if !db
                    .is_protection_enabled()
                    .map_err(|error| error.to_string())?
                {
                    return Ok(BlockEvent {
                        domain: domain.to_string(),
                        action: BlockAction::AllowedByDefault,
                        matched_rule: None,
                        rule_source: Some("protection-disabled".to_string()),
                        category: None,
                        occurred_at: SystemTime::now(),
                    });
                }

                for blocked_domain in db
                    .list_block_domains()
                    .map_err(|error| error.to_string())?
                {
                    request_engine
                        .add_block_rule(
                            &blocked_domain,
                            Some("db-blocklist"),
                            Some("user"),
                        )
                        .map_err(|error| format!("{error:?}"))?;
                }

                for allowed_domain in db
                    .list_allow_domains()
                    .map_err(|error| error.to_string())?
                {
                    request_engine
                        .add_allow_rule(
                            &allowed_domain,
                            Some("db-allowlist"),
                            Some("user"),
                        )
                        .map_err(|error| format!("{error:?}"))?;
                }
            }

            request_engine
                .check_domain_with_event(domain)
                .map_err(|error| format!("{error:?}"))
        },
        move |event| {
            if !should_store_event(&event.action) {
                return;
            }

            let Some(db_path) = logger_db_path.as_deref() else {
                return;
            };

            let result = BlockerDb::open(db_path)
                .and_then(|db| db.record_event(event));

            match result {
                Ok(id) => {
                    println!(
                        "DB EVENT #{id} {} {}",
                        format_action(&event.action),
                        event.domain
                    );
                    println!("  db: {db_path}");
                }
                Err(error) => {
                    eprintln!("DB EVENT FAILED for {}: {error}", event.domain);
                }
            }
        },
    )?;

    Ok(())
}

fn run_dns_probe(command: DnsProbeCommand) -> Result<(), Box<dyn Error>> {
    let server_addr: SocketAddr = command.server_addr.parse()?;
    let query_packet = make_dns_query_packet(&command.domain, DNS_TYPE_A);

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;

    println!("DNS probe:");
    println!("  domain: {}", command.domain);
    println!("  server: {}", server_addr);
    println!("  query bytes: {}", query_packet.len());
    println!();

    let sent = socket.send_to(&query_packet, server_addr)?;
    println!("SENT {sent} bytes");

    let mut buffer = [0u8; 4096];

    match socket.recv_from(&mut buffer) {
        Ok((response_len, from_addr)) => {
            let response = &buffer[..response_len];

            println!("RECV {response_len} bytes from {from_addr}");

            if response_len >= 12 {
                print_dns_response_summary(response);
            }

            if response_len >= 4 {
                let tail_start = response_len.saturating_sub(16);
                println!("  last bytes: {:?}", &response[tail_start..]);
            }
        }
        Err(error) => {
            println!("NO RESPONSE");
            println!("  error: {error}");
        }
    }

    Ok(())
}

fn run_events(command: EventsCommand) -> Result<(), Box<dyn Error>> {
    let db = BlockerDb::open(command.db_path.as_str())?;
    let events = db.recent_events(command.limit)?;

    println!("Recent events from: {}", command.db_path);
    println!("Limit: {}", command.limit);
    println!();

    if events.is_empty() {
        println!("No stored events yet.");
        return Ok(());
    }

    for event in &events {
        print_stored_event(event);
        println!();
    }

    Ok(())
}

fn run_allow(command:AllowCommand) -> Result<(), Box<dyn Error>> {
    let db = BlockerDb::open(command.db_path.as_str())?;
    let added = db.add_allow_domain(&command.domain)?;

    if added {
        println!("Added to allowlist:");
    } else {
        println!("Already in allowlist:");
    }

    println!("  domain: {}", command.domain);
    println!("  db: {}", command.db_path);

    Ok(())
}

fn run_unallow(command: UnallowCommand) -> Result <(), Box<dyn Error>> {
    let db = BlockerDb::open(command.db_path.as_str())?;
    let removed = db.remove_allow_domain(&command.domain)?;

    if removed {
        println!("Removed from allowlist:");
    } else {
        println!("Domain was not in allowlist:");
    }

    println!("  domain: {}", command.domain);
    println!("  db: {}", command.db_path);

    Ok(())
}

fn run_allowlist(command: AllowlistCommand) -> Result<(), Box <dyn Error>> {
    let db = BlockerDb::open(command.db_path.as_str())?;
    let domains = db.list_allow_domains()?;

    println!("Allowlist from: {}", command.db_path);
    println!();

    if domains.is_empty() {
        println!("No allowed domains yet.");
        return Ok(());
    }

    for domain in domains {
        println!("- {domain}");
    }

    Ok(())
}

fn run_api_serve(command: ApiServeCommand) -> Result<(), Box<dyn Error>> {
    let listen_addr: SocketAddr = command.listen_addr.parse()?;

    let config = ApiServerConfig {
        listen_addr,
        db_path: command.db_path,
    };

    run_api_server(config)?;

    Ok(())
}

fn run_dev(command: DevRunCommand) -> Result<(), Box<dyn Error>> {
    println!("Starting The Blocker dev runtime");
    println!("  db: {}", command.db_path);
    println!("  api: {}", command.api_listen_addr);
    println!("  dns: {}", command.dns_listen_addr);
    println!("  upstream: {}", command.upstream_addr);
    println!();

    let api_listen_addr: SocketAddr = command.api_listen_addr.parse()?;
    let api_db_path = command.db_path.clone();

    thread::spawn(move || {
        let config = ApiServerConfig {
            listen_addr: api_listen_addr,
            db_path: api_db_path,
        };

        if let Err(error) = run_api_server(config) {
            eprintln!("API server stopped with error: {error}");
        }
    });

    let dns_command = DnsServeCommand {
        rule_files: command.rule_files,
        block_rules: command.block_rules,
        allow_rules: command.allow_rules,
        db_path: Some(command.db_path),
        listen_addr: command.dns_listen_addr,
        upstream_addr: command.upstream_addr,
        blocked_ttl_seconds: command.blocked_ttl_seconds,
    };

    run_dns_serve(dns_command)?;

    Ok(())
}

fn print_event_preview(event: &BlockEvent) {
    let occurred_at = event
        .occurred_at
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    println!("Event preview:");
    println!("  domain: {}", event.domain);
    println!("  action: {}", format_action(&event.action));
    println!("  matched rule: {}", event.matched_rule.as_deref().unwrap_or("-"));
    println!("  rule source: {}", event.rule_source.as_deref().unwrap_or("-"));
    println!("  category: {}", event.category.as_deref().unwrap_or("-"));
    println!("  occurred at unix: {occurred_at}");
}

fn print_stored_event(event: &StoredBlockEvent) {
    println!("#{} {} {}", event.id, event.action, event.domain);
    println!("  matched rule: {}", event.matched_rule.as_deref().unwrap_or("-"));
    println!("  rule source: {}", event.rule_source.as_deref().unwrap_or("-"));
    println!("  category: {}", event.category.as_deref().unwrap_or("-"));
    println!(" occurred at unix: {}", event.occurred_at_unix);
}

fn format_action(action: &BlockAction) -> &'static str {
    match action {
        BlockAction::Blocked => "blocked",
        BlockAction::AllowedByUserRule => "allowed_by_user_rule",
        BlockAction::AllowedByDefault => "allowed_by_default",
    }
}

fn should_store_event(action: &BlockAction) -> bool {
    matches!(action, BlockAction::Blocked)
}

fn parse_check_command(args: &[String]) -> Result<CheckCommand, String> {
    if args.is_empty() {
        return Err("Missing domain for check command".to_string());
    }

    let mut command = CheckCommand {
        domain: args[0].clone(),
        ..CheckCommand::default()
    };

    let mut index = 1;

    while index < args.len() {
        match args[index].as_str() {
            "--rules" => {
                let value = next_value(args, index, "--rules")?;
                command.rule_files.push(value.to_string());
                index += 2;
            }
            "--block" => {
                let value = next_value(args, index, "--block")?;
                command.block_rules.push(value.to_string());
                index += 2;
            }
            "--allow" => {
                let value = next_value(args, index, "--allow")?;
                command.allow_rules.push(value.to_string());
                index += 2;
            }
            "--db" => {
                let value = next_value(args, index, "--db")?;
                command.db_path = Some(value.to_string());
                index += 2;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            unknown => {
                return Err(format!("Unknown check option: {unknown}"));
            }
        }
    }

    Ok(command)
}

fn parse_events_command(args: &[String]) -> Result<EventsCommand, String> {
    let mut command = EventsCommand {
        db_path: "blocker.db".to_string(),
        limit: 50,
    };

    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--db" => {
                let value = next_value(args, index, "--db")?;
                command.db_path = value.to_string();
                index +=2;
            }
            "--limit" => {
                let value = next_value(args, index, "--limit")?;
                command.limit = value
                    .parse::<i64>()
                    .map_err(|_| format!("Invalid --limit value: {value}"))?;
                index += 2;
            }"--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            unknown => {
                return Err(format!("Unknown events option: {unknown}"));
            }
        }
    }

    Ok(command)
}

fn parse_allow_command(args: &[String]) -> Result<AllowCommand, String> {
    let (domain, db_path) = parse_domain_db_command(args, "allow")?;

    Ok(AllowCommand { domain, db_path })
}

fn parse_unallow_command(args: &[String]) -> Result<UnallowCommand, String> {
    let (domain, db_path) = parse_domain_db_command(args, "unallow")?;

    Ok(UnallowCommand { domain, db_path })
}

fn parse_allowlist_command(args: &[String]) -> Result<AllowlistCommand, String> {
    let mut db_path = "blocker.db".to_string();

    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--db" => {
                let value = next_value(args, index, "--db")?;
                db_path = value.to_string();
                index += 2;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            unknown => {
                return Err(format!("Unkown allowlist option: {unknown}"));
            }
        }
    }

    Ok(AllowlistCommand { db_path })
}

fn parse_domain_db_command(args: &[String], command_name: &str) -> Result<(String, String), String> {
    if args.is_empty() {
        return Err(format!("Missing domain for {command_name} command"));
    }

    let domain = args[0].clone();
    let mut db_path = "blocker.db".to_string();

    let mut index = 1;

    while index < args.len() {
        match args[index].as_str() {
            "--db" => {
                let value = next_value(args, index, "--db")?;
                db_path = value.to_string();
                index += 2;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            unknown => {
                return Err(format!("Unknown {command_name} option: {unknown}"));
            }
        }
    }
    
    Ok((domain, db_path))
}

fn parse_dns_serve_command(args: &[String]) -> Result<DnsServeCommand, String> {
    let mut command = DnsServeCommand {
        listen_addr: "127.0.0.1:5353".to_string(),
        upstream_addr: "1.1.1.1:53".to_string(),
        blocked_ttl_seconds: 60,
        ..DnsServeCommand::default()
    };

    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--rules" => {
                let value = next_value(args, index, "--rules")?;
                command.rule_files.push(value.to_string());
                index += 2;
            }
            "--block" => {
                let value = next_value(args, index, "--block")?;
                command.block_rules.push(value.to_string());
                index += 2;
            }
            "--allow" => {
                let value = next_value(args, index, "--allow")?;
                command.allow_rules.push(value.to_string());
                index += 2;
            }
            "--db" => {
                let value = next_value(args, index, "--db")?;
                command.db_path = Some(value.to_string());
                index += 2;
            }
            "--listen" => {
                let value = next_value(args, index, "--listen")?;
                command.listen_addr = value.to_string();
                index += 2;
            }
            "--upstream" => {
                let value = next_value(args, index, "--upstream")?;
                command.upstream_addr = value.to_string();
                index += 2;
            }
            "--ttl" => {
                let value = next_value(args, index, "--ttl")?;
                command.blocked_ttl_seconds = value
                    .parse::<u32>()
                    .map_err(|_| format!("Invalid --ttl value: {value}"))?;
                index += 2;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            unknown => {
                return Err(format!("Unknown dns-serve option: {unknown}"));
            }
        }
    }

    Ok(command)
}

fn parse_dns_probe_command(args: &[String]) -> Result<DnsProbeCommand, String> {
    if args.is_empty() {
        return Err("Missing domain for dns-probe command".to_string());
    }

    let domain = args[0].clone();
    let mut server_addr = "127.0.0.1:5300".to_string();

    let mut index = 1;

    while index < args.len() {
        match args[index].as_str() {
            "--server" => {
                let value = next_value(args, index, "--server")?;
                server_addr = value.to_string();
                index += 2;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            unknown => {
                return Err(format!("Unknown dns-probe option: {unknown}"));
            }
        }
    }

    Ok(DnsProbeCommand {
        domain,
        server_addr,
    })
}

fn parse_api_serve_command(args: &[String]) -> Result<ApiServeCommand, String> {
    let mut command = ApiServeCommand {
        db_path: "blocker.db".to_string(),
        listen_addr: "127.0.0.1:4780".to_string(),
    };

    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--db" => {
                let value = next_value(args, index, "--db")?;
                command.db_path = value.to_string();
                index += 2;
            }
            "--listen" => {
                let value = next_value(args, index, "--listen")?;
                command.listen_addr = value.to_string();
            }
            "help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            unknown => {
                return Err(format!("Unknown api-serve option: {unknown}"))
            }
        }
    }

    Ok(command)
}

fn parse_dev_run_command(args: &[String]) -> Result<DevRunCommand, String> {
    let mut command = DevRunCommand {
        db_path: "blocker.db".to_string(),
        dns_listen_addr: "0.0.0.0:5300".to_string(),
        api_listen_addr: "127.0.0.1:4780".to_string(),
        upstream_addr: "1.1.1.1:53".to_string(),
        blocked_ttl_seconds: 60,
        ..DevRunCommand::default()
    };

    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--rules" => {
                let value = next_value(args, index, "--rules")?;
                command.rule_files.push(value.to_string());
                index += 2;
            }
            "--block" => {
                let value = next_value(args, index, "--block")?;
                command.block_rules.push(value.to_string());
                index += 2;
            }
            "--allow" => {
                let value = next_value(args, index, "--allow")?;
                command.allow_rules.push(value.to_string());
                index += 2;
            }
            "--db" => {
                let value = next_value(args, index, "--db")?;
                command.db_path = value.to_string();
                index += 2;
            }
            "--dns-listen" => {
                let value = next_value(args, index, "--dns-listen")?;
                command.dns_listen_addr = value.to_string();
                index += 2;
            }
            "--api-listen" => {
                let value = next_value(args, index, "--api-listen")?;
                command.api_listen_addr = value.to_string();
                index += 2;
            }
            "--upstream" => {
                let value = next_value(args, index, "--upstream")?;
                command.upstream_addr = value.to_string();
                index += 2;
            }
            "--ttl" => {
                let value = next_value(args, index, "--ttl")?;
                command.blocked_ttl_seconds = value
                    .parse::<u32>()
                    .map_err(|_| format!("Invalid --ttl value: {value}"))?;
                index += 2;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            unknown => {
                return Err(format!("Unknown dev-run option: {unknown}"));
            }
        }
    }

    Ok(command)
}

fn next_value<'a>(args: &'a [String], option_index: usize, option_name: &str) -> Result<&'a str, String> {
    args.get(option_index + 1)
        .map(|value| value.as_str())
        .ok_or_else(|| format!("Missing value after {option_name}"))
}

fn invalid_input(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn make_dns_query_packet(domain: &str, qtype: u16) -> Vec<u8> {
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

fn print_dns_response_summary(response: &[u8]) {
    let flags = u16::from_be_bytes([response[2], response[3]]);
    let rcode = flags & 0x000F;

    let question_count = u16::from_be_bytes([response[4], response[5]]);
    let answer_count = u16::from_be_bytes([response[6], response[7]]);
    let authority_count = u16::from_be_bytes([response[8], response[9]]);
    let additional_count = u16::from_be_bytes([response[10], response[11]]);

    println!("  flags: 0x{flags:04x}");
    println!("  rcode: {rcode}");
    println!("  question count: {question_count}");
    println!("  answer count: {answer_count}");
    println!("  authority count: {authority_count}");
    println!("  additional count: {additional_count}");

    if answer_count > 0 {
        print_last_a_record_answer(response);
    }
}

fn print_last_a_record_answer(response: &[u8]) {
    if response.len() < 4 {
        return;
    }

    let last_four = &response[response.len() - 4..];

    println!(
        "  possible A answer: {}.{}.{}.{}",
        last_four[0], last_four[1], last_four[2], last_four[3]
    );
}

fn print_help() {
    println!("The Blocker CLI");
    println!();
    println!("Usage:");
    println!("  blocker-cli check <domain> [options]");
    println!("  blocker-cli dns-check <domain> [options]");
    println!("  blocker-cli dns-serve [options]");
    println!("  blocker-cli dns-probe <domain> [options]");
    println!("  blocker-cli api-serve [options]");
    println!("  blocker-cli dev-run [options]");
    println!("  blocker-cli events [options]");
    println!("  blocker-cli allow <domain> [options]");
    println!("  blocker-cli unallow <domain> [options]");
    println!("  blocker-cli allowlist [options]");
    println!();
    println!("Check options:");
    println!("  --rules <file>     Load block/allow rules from a text file");
    println!("  --block <domain>   Add one manual block rule");
    println!("  --allow <domain>   Add one manual allow rule");
    println!("  --db <file>        Save blocked/user-allowed events to SQLite");
    println!();
    println!("Events options:");
    println!("  --db <file>        SQLite database path");
    println!("  --limit <number>   Number of events to show, default 50");
    println!();
    println!("Allowlist options:");
    println!("  --db <file>        SQLite database path, default blocker.db");
    println!();
    println!("DNS serve options:");
    println!("  --rules <file>         Load block/allow rules from a text file");
    println!("  --block <domain>       Add one manual block rule");
    println!("  --allow <domain>       Add one manual allow rule");
    println!("  --db <file>            Load allowlist from SQLite");
    println!("  --listen <addr:port>   Listen address, default 127.0.0.1:5353");
    println!("  --upstream <addr:port> Upstream DNS, default 1.1.1.1:53");
    println!("  --ttl <seconds>        TTL for blocked DNS answers, default 60");
    println!();
    println!("DNS probe options:");
    println!("  --server <addr:port>  DNS server address, default 127.0.0.1:5300");
    println!();
    println!("API serve options:");
    println!("  --db <file>            SQLite database path, default blocker.db");
    println!("  --listen <addr:port>   Listen address, default 127.0.0.1:4780");
    println!();
    println!("Dev runtime options:");
    println!("  --rules <file>             Load block/allow rules from a text file");
    println!("  --block <domain>           Add one manual block rule");
    println!("  --allow <domain>           Add one manual allow rule");
    println!("  --db <file>                SQLite database path, default blocker.db");
    println!("  --dns-listen <addr:port>   DNS listen address, default 0.0.0.0:5300");
    println!("  --api-listen <addr:port>   API listen address, default 127.0.0.1:4780");
    println!("  --upstream <addr:port>     Upstream DNS, default 1.1.1.1:53");
    println!("  --ttl <seconds>            TTL for blocked DNS answers, default 60");
    println!();
    println!("Examples:");
    println!("  cargo run -p blocker-cli -- check ads.example.com --block ads.example.com");
    println!("  cargo run -p blocker-cli -- check ads.example.com --block ads.example.com --db blocker.db");
    println!("  cargo run -p blocker-cli -- dns-check ads.example.com --block ads.example.com");
    println!("  cargo run -p blocker-cli -- dns-serve --block ads.example.com");
    println!("  cargo run -p blocker-cli -- dns-probe ads.example.com --server 127.0.0.1:5300");
    println!("  cargo run -p blocker-cli -- api-serve --db blocker.db");
    println!("  curl http://127.0.0.1:4780/events");
    println!("  curl -X POST \"http://127.0.0.1:4780/allow?domain=ads.example.com\"");
    println!("  cargo run -p blocker-cli -- dev-run --block ads.example.com --db blocker.db");
    println!("  curl.exe http://127.0.0.1:4780/events");
    println!("  curl.exe http://127.0.0.1:4780/status");
    println!("  curl.exe -X POST http://127.0.0.1:4780/protection/disable");
    println!("  curl.exe -X POST http://127.0.0.1:4780/protection/enable");
    println!("  cargo run -p blocker-cli -- dns-probe ads.example.com --server 127.0.0.1:5300");
    println!("  cargo run -p blocker-cli -- events --db blocker.db");
    println!("  cargo run -p blocker-cli -- allow ads.example.com --db blocker.db");
    println!("  cargo run -p blocker-cli -- allowlist --db blocker.db");
    println!("  cargo run -p blocker-cli -- unallow ads.example.com --db blocker.db");
}