use crate::app::{App, VpnState, F};
use crate::Source;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

pub fn draw(f: &mut Frame, app: &App) {
    let [header, body, log, help] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(app.fields.len() as u16 + 2),
        Constraint::Min(6),
        Constraint::Length(1),
    ])
    .areas(f.area());
    let [form, probes] =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(body);

    draw_header(f, app, header);
    draw_form(f, app, form);
    draw_probes(f, app, probes);
    draw_log(f, app, log);
    f.render_widget(
        Paragraph::new(
            " Tab/↑↓ field · Enter connect / send creds · ^F fetch .ovpn · ^D disconnect · ^E egress IP · ^G probe repo · ^K clone · ^U clear field · PgUp/PgDn log · ^Q quit",
        )
        .style(Style::new().fg(Color::DarkGray)),
        help,
    );
}

fn state_color(s: &VpnState) -> Color {
    match s {
        VpnState::Connected => Color::Green,
        VpnState::NeedsCreds | VpnState::Reconnecting(_) | VpnState::LockedOut(_) => Color::Yellow,
        VpnState::Failed(_) => Color::Red,
        VpnState::Idle => Color::Gray,
        _ => Color::Cyan,
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![
        Span::raw(" VPN "),
        Span::styled(
            app.state.label(),
            Style::new()
                .fg(state_color(&app.state))
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if let Some(ip) = &app.tunnel_ip {
        spans.push(Span::raw(format!("  tunnel {ip}")));
    }
    spans.push(Span::raw(format!(
        "  in {} out {}  token {}  failures {}  mode {}{}",
        human(app.bytes.0),
        human(app.bytes.1),
        if app.session_token { "yes" } else { "no" },
        app.failures.len(),
        app.route_mode().name(),
        if app.busy.is_empty() {
            String::new()
        } else {
            format!("  busy: {}", app.busy.join(","))
        },
    )));
    let title = format!(
        " ghvpn-tui · {} {}",
        app.value(F::Gateway),
        if app.use_sudo { "(sudo)" } else { "(root)" }
    );
    f.render_widget(
        Paragraph::new(Line::from(spans)).block(Block::bordered().title(title)),
        area,
    );
}

fn draw_form(f: &mut Frame, app: &App, area: Rect) {
    let lines: Vec<Line> = app
        .fields
        .iter()
        .enumerate()
        .map(|(i, fld)| {
            let focused = i == app.focus;
            let value = if fld.secret {
                "•".repeat(fld.value.chars().count())
            } else {
                fld.value.clone()
            };
            let mut spans = vec![
                Span::styled(
                    if focused { "▶ " } else { "  " },
                    Style::new().fg(Color::Yellow),
                ),
                Span::styled(
                    format!("{:<16}", fld.label),
                    Style::new().fg(if focused { Color::Yellow } else { Color::Gray }),
                ),
                Span::raw(value),
            ];
            if focused {
                spans.push(Span::styled("▏", Style::new().fg(Color::Yellow)));
            }
            if fld.value.is_empty() && !fld.hint.is_empty() {
                spans.push(Span::styled(
                    format!(" {}", fld.hint),
                    Style::new().fg(Color::DarkGray).italic(),
                ));
            }
            Line::from(spans)
        })
        .collect();
    f.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" Settings ")),
        area,
    );
}

fn draw_probes(f: &mut Frame, app: &App, area: Rect) {
    let height = area.height.saturating_sub(2) as usize;
    let lines: Vec<Line> = app
        .probes
        .iter()
        .rev()
        .take(height)
        .rev()
        .map(|p| {
            Line::from(vec![
                Span::styled(
                    format!("{:>6.0}s ", p.at.as_secs_f64()),
                    Style::new().fg(Color::DarkGray),
                ),
                Span::styled(
                    if p.outcome.ok { "✔ " } else { "✘ " },
                    Style::new().fg(if p.outcome.ok {
                        Color::Green
                    } else {
                        Color::Red
                    }),
                ),
                Span::styled(format!("{} ", p.name), Style::new().bold()),
                Span::styled(
                    if p.via_vpn { "[vpn] " } else { "[direct] " },
                    Style::new().fg(Color::Cyan),
                ),
                Span::raw(p.outcome.summary.clone()),
            ])
        })
        .collect();
    let body = if lines.is_empty() {
        Paragraph::new("No probes yet. ^E egress IP, ^G GitHub API + git ls-remote, ^K shallow clone.\nRun them before and after connecting to compare.")
            .style(Style::new().fg(Color::DarkGray))
    } else {
        Paragraph::new(lines)
    };
    f.render_widget(
        body.wrap(Wrap { trim: false })
            .block(Block::bordered().title(" Probes ")),
        area,
    );
}

fn draw_log(f: &mut Frame, app: &App, area: Rect) {
    let height = area.height.saturating_sub(2) as usize;
    let end = app.log.len().saturating_sub(app.log_scroll);
    let start = end.saturating_sub(height);
    let lines: Vec<Line> = app
        .log
        .range(start..end)
        .map(|l| {
            let (tag, color) = match l.source {
                Source::App => ("app ", Color::White),
                Source::Vpn => ("vpn ", Color::Cyan),
                Source::Mgmt => ("mgmt", Color::Magenta),
                Source::OpenVpn => ("ovpn", Color::DarkGray),
                Source::Probe => ("prob", Color::Green),
            };
            Line::from(vec![
                Span::styled(
                    format!("{:>7.1} ", l.at.as_secs_f64()),
                    Style::new().fg(Color::DarkGray),
                ),
                Span::styled(format!("{tag} "), Style::new().fg(color)),
                Span::raw(l.text.clone()),
            ])
        })
        .collect();
    let title = if app.log_scroll > 0 {
        format!(" Log (scrolled {} up, End to follow) ", app.log_scroll)
    } else {
        " Log ".into()
    };
    f.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(title)),
        area,
    );
}

fn human(b: u64) -> String {
    match b {
        0..1024 => format!("{b} B"),
        1024..1_048_576 => format!("{:.1} KiB", b as f64 / 1024.0),
        _ => format!("{:.1} MiB", b as f64 / 1_048_576.0),
    }
}
