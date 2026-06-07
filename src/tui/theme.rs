//! Centralized color theme for the Ghidrai TUI.
//!
//! Palette: Orange-Yellow + Fire-Red gradient, inspired by Gemini's visual
//! identity.  Every widget must import colors / styles from this module.
//!
//! The gradient system supports per-character and per-line color
//! interpolation so borders, banners, and tab bars all share the same
//! living-fire look.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

// ─── Core Palette ─────────────────────────────────────────────────────────────

/// Bright amber / orange-gold — primary accent, selected items, prompts.
pub const AMBER: Color = Color::Rgb(255, 176, 0);

/// Fire red — secondary accent, errors, hot highlights.
pub const FIRE: Color = Color::Rgb(232, 72, 35);

/// Deep ember — used for warm background tints, subtle separators.
pub const EMBER: Color = Color::Rgb(180, 60, 20);

/// Solar yellow — tertiary accent, mild highlights.
pub const SOLAR: Color = Color::Rgb(255, 210, 63);

/// Warm orange — gradient midpoint, hover states.
pub const ORANGE: Color = Color::Rgb(255, 140, 0);

/// Muted gold — for de-emphasized but still "warm" text.
pub const MUTED_GOLD: Color = Color::Rgb(180, 140, 60);

/// Faint ash — dim text, ghost text, inactive borders.
pub const ASH: Color = Color::Rgb(100, 90, 80);

/// Smoke — very dim text, background info.
pub const SMOKE: Color = Color::Rgb(70, 65, 58);

/// Charcoal — deep background tint for contrast.
pub const CHARCOAL: Color = Color::Rgb(30, 28, 26);

/// Off-white for primary readable text.
pub const BONE: Color = Color::Rgb(230, 220, 200);

/// Slightly dimmer text for secondary content.
pub const SAND: Color = Color::Rgb(190, 175, 155);

// ─── Gradient Engine ──────────────────────────────────────────────────────────

/// Extract (r, g, b) from a `Color::Rgb`.  Falls back to (128,128,128).
fn rgb(c: Color) -> (u8, u8, u8) {
    match c {
        Color::Rgb(r, g, b) => (r, g, b),
        _ => (128, 128, 128),
    }
}

/// Linearly interpolate between two `Color::Rgb` values.
/// `t` is clamped to `[0.0, 1.0]`.
pub fn lerp_color(a: Color, b: Color, t: f32) -> Color {
    let t = t.clamp(0.0, 1.0);
    let (ar, ag, ab) = rgb(a);
    let (br, bg, bb) = rgb(b);
    Color::Rgb(
        (ar as f32 + (br as f32 - ar as f32) * t) as u8,
        (ag as f32 + (bg as f32 - ag as f32) * t) as u8,
        (ab as f32 + (bb as f32 - ab as f32) * t) as u8,
    )
}

/// Build a multi-stop gradient and sample it at position `t ∈ [0, 1]`.
pub fn gradient(stops: &[Color], t: f32) -> Color {
    if stops.is_empty() {
        return AMBER;
    }
    if stops.len() == 1 {
        return stops[0];
    }
    let t = t.clamp(0.0, 1.0);
    let segments = stops.len() - 1;
    let pos = t * segments as f32;
    let idx = (pos as usize).min(segments - 1);
    let local_t = pos - idx as f32;
    lerp_color(stops[idx], stops[idx + 1], local_t)
}

/// The canonical fire gradient: deep red → ember → orange → amber → solar gold.
pub const FIRE_GRADIENT: &[Color] = &[
    Color::Rgb(160, 30, 10),  // deep crimson
    FIRE,                      // fire red
    EMBER,                     // ember
    ORANGE,                    // warm orange
    AMBER,                     // amber gold
    SOLAR,                     // solar yellow
];

/// Render a string as a single `Line` with per-character horizontal gradient.
pub fn gradient_text<'a>(text: &str, stops: &[Color], bold: bool) -> Line<'a> {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len().max(1);
    let spans: Vec<Span> = chars
        .into_iter()
        .enumerate()
        .map(|(i, ch)| {
            let t = i as f32 / (len - 1).max(1) as f32;
            let color = gradient(stops, t);
            let mut style = Style::default().fg(color);
            if bold {
                style = style.add_modifier(Modifier::BOLD);
            }
            Span::styled(ch.to_string(), style)
        })
        .collect();
    Line::from(spans)
}

/// Render each line of the banner with its own gradient row color, plus
/// per-character horizontal gradient within each row.
pub fn gradient_banner<'a>() -> Vec<Line<'a>> {
    BANNER_LINES
        .iter()
        .enumerate()
        .map(|(row, text)| {
            let row_t = row as f32 / (BANNER_LINES.len() - 1).max(1) as f32;
            // Per-row base color from the fire gradient
            let row_color = gradient(FIRE_GRADIENT, row_t);
            // Slight horizontal shimmer: shift hue ±15% around the row base
            let chars: Vec<char> = text.chars().collect();
            let len = chars.len().max(1);
            let spans: Vec<Span> = chars
                .into_iter()
                .enumerate()
                .map(|(col, ch)| {
                    let col_t = col as f32 / (len - 1).max(1) as f32;
                    // Blend the row color slightly toward SOLAR for a horizontal glow
                    let shimmer = lerp_color(row_color, SOLAR, col_t * 0.25);
                    Span::styled(
                        ch.to_string(),
                        Style::default().fg(shimmer).add_modifier(Modifier::BOLD),
                    )
                })
                .collect();
            Line::from(spans)
        })
        .collect()
}

/// Produce a gradient-colored horizontal rule: `─────…──` that fades
/// from `a` to `b` across `width` columns.
pub fn gradient_rule<'a>(width: usize, a: Color, b: Color) -> Line<'a> {
    let spans: Vec<Span> = (0..width)
        .map(|i| {
            let t = i as f32 / (width - 1).max(1) as f32;
            Span::styled("─", Style::default().fg(lerp_color(a, b, t)))
        })
        .collect();
    Line::from(spans)
}

/// Produce a gradient-colored status bar string.
pub fn gradient_status<'a>(text: &str) -> Line<'a> {
    gradient_text(text, &[ASH, MUTED_GOLD, ORANGE], false)
}

// ─── Semantic Styles ──────────────────────────────────────────────────────────

/// Style for the currently selected / active tab.
pub fn tab_active() -> Style {
    Style::default().fg(AMBER).add_modifier(Modifier::BOLD)
}

/// Style for inactive tabs.
pub fn tab_inactive() -> Style {
    Style::default().fg(ASH)
}

/// Border style for the focused pane.
pub fn border_focused() -> Style {
    Style::default().fg(AMBER)
}

/// Border style for unfocused panes.
pub fn border_dim() -> Style {
    Style::default().fg(SMOKE)
}

/// Highlighted list item (cursor is on it).
pub fn list_highlight() -> Style {
    Style::default()
        .bg(Color::Rgb(60, 40, 15))
        .fg(AMBER)
        .add_modifier(Modifier::BOLD)
}

/// Normal list item text.
pub fn list_normal() -> Style {
    Style::default().fg(SAND)
}

/// The `❯ ` prompt cursor in the command console.
pub fn prompt() -> Style {
    Style::default().fg(FIRE).add_modifier(Modifier::BOLD)
}

/// User-typed text in the console.
pub fn input_text() -> Style {
    Style::default().fg(AMBER)
}

/// Ghost / autocomplete text.
pub fn ghost() -> Style {
    Style::default().fg(ASH)
}

/// Blinking cursor block.
pub fn cursor() -> Style {
    Style::default().fg(ORANGE)
}

/// Status / info messages in the event log.
pub fn log_status() -> Style {
    Style::default().fg(SAND)
}

/// Error messages in the event log.
pub fn log_error() -> Style {
    Style::default().fg(FIRE)
}

/// Panel title text.
pub fn title() -> Style {
    Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)
}

/// The address column in lists (hex addresses).
pub fn address() -> Style {
    Style::default().fg(MUTED_GOLD)
}

/// Callers / incoming references.
pub fn xref_caller() -> Style {
    Style::default().fg(FIRE)
}

/// Callees / outgoing references.
pub fn xref_callee() -> Style {
    Style::default().fg(SOLAR)
}

/// Section header / separator lines.
pub fn section_header() -> Style {
    Style::default()
        .fg(ORANGE)
        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
}

/// Enabled / "pass" security feature.
pub fn security_pass() -> Style {
    Style::default().fg(Color::Rgb(100, 200, 80))
}

/// Disabled / "fail" security feature.
pub fn security_fail() -> Style {
    Style::default().fg(FIRE)
}

/// Unknown / N/A security feature.
pub fn security_unknown() -> Style {
    Style::default().fg(ASH)
}

// ─── ASCII Art Banner ─────────────────────────────────────────────────────────

/// Multi-line ASCII art logo for the startup splash.
pub const BANNER_LINES: &[&str] = &[
    r"   ██████╗ ██╗  ██╗██╗██████╗ ██████╗  █████╗ ██╗",
    r"  ██╔════╝ ██║  ██║██║██╔══██╗██╔══██╗██╔══██╗██║",
    r"  ██║  ███╗███████║██║██║  ██║██████╔╝███████║██║",
    r"  ██║   ██║██╔══██║██║██║  ██║██╔══██╗██╔══██║██║",
    r"  ╚██████╔╝██║  ██║██║██████╔╝██║  ██║██║  ██║██║",
    r"   ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝",
];

/// Subtitle line rendered under the banner.
pub const BANNER_SUBTITLE: &str = "Terminal Reverse-Engineering Toolkit";
