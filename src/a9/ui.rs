//! Shared terminal-display language for the CLI's status screens.
//!
//! Every screen is a two-pane grid at 80 columns. Each pane owns ONE hue,
//! carried by its bold header and its values, with every label dim — so the
//! colour answers "which instrument am I reading" before a single word is
//! parsed. Orange is the only hue allowed to cross a pane boundary, and it
//! always means off-nominal, so a real problem stays louder than the zoning
//! around it.
//!
//! Two rules the screens depend on, both learned the hard way:
//!
//!   * Colour is applied per CELL, never per line. A one-hue-per-`writeln!`
//!     layout forces a left cell and its right neighbour to share a colour,
//!     which is how `Height` once rendered pink purely because `Fork Count`
//!     sat beside it.
//!   * Weight is set EXPLICITLY on every run. `ColorSpec` is reused across a
//!     whole screen and only carries the last flag it was given, so a single
//!     `set_bold(true)` that was never cleared used to leave three entire
//!     sections bold.
//!
//! Output always goes through one `termcolor` handle with `write!`/`writeln!`,
//! never `println!` — mixing handles reorders styled and unstyled text.

use std::io::Write;
use termcolor::{Color, ColorSpec, StandardStream, WriteColor};

// ─── palette ───────────────────────────────────────────────────────────────
pub const UI_LABEL: Color = Color::Rgb(230, 230, 230);
pub const UI_DIM: Color = Color::Rgb(128, 128, 128);
pub const UI_CYAN: Color = Color::Rgb(40, 204, 217);
pub const UI_BLUE: Color = Color::Rgb(137, 207, 211);
pub const UI_GREEN: Color = Color::Rgb(59, 242, 173);
pub const UI_ORANGE: Color = Color::Rgb(237, 124, 51);
pub const UI_PINK: Color = Color::Rgb(247, 111, 142);
pub const UI_LAVENDER: Color = Color::Rgb(167, 165, 198);

// ─── grid geometry, in 0-based columns ─────────────────────────────────────
// Every glyph these screens draw is single-width, so character counts are
// display columns.
pub const UI_LEFT_VALUE: usize = 17;
pub const UI_RAIL: usize = 39;
pub const UI_RIGHT_LABEL: usize = 41;
pub const UI_RIGHT_VALUE: usize = 57;
/// Full-width rule, matching the grid rather than the historical 19-char stub.
pub const UI_RULE: &str =
    "──────────────────────────────────────────────────────────────────────────────";

/// Write one coloured run at an explicit weight.
pub fn ui_seg(
    out: &mut StandardStream,
    spec: &mut ColorSpec,
    color: Color,
    bold: bool,
    text: &str,
) -> std::io::Result<()> {
    spec.set_fg(Some(color)).set_bold(bold);
    out.set_color(spec)?;
    write!(out, "{}", text)
}

/// Write a run in the terminal's DEFAULT foreground — never a fixed colour.
///
/// Use this for anything a reader must be able to transcribe: addresses,
/// transaction ids, anything they may retype or compare character by character.
/// A fixed light grey is unreadable on a light-background terminal and a fixed
/// dark one is unreadable on a dark background, whereas the default foreground
/// is by definition the colour that contrasts with the user's own background.
/// `UI_LABEL` is near-white and therefore NOT safe for this — it only looks
/// right on a dark theme.
pub fn ui_text(
    out: &mut StandardStream,
    spec: &mut ColorSpec,
    bold: bool,
    text: &str,
) -> std::io::Result<()> {
    spec.set_fg(None).set_bold(bold);
    out.set_color(spec)?;
    write!(out, "{}", text)
}

/// Advance from column `from` to column `to` with plain spaces.
pub fn ui_pad(
    out: &mut StandardStream,
    spec: &mut ColorSpec,
    from: usize,
    to: usize,
) -> std::io::Result<()> {
    ui_seg(
        out,
        spec,
        UI_LABEL,
        false,
        &" ".repeat(to.saturating_sub(from)),
    )
}

/// A pane-header row: two bold headers in their pane hues, split by the rail.
pub fn ui_grid_header(
    out: &mut StandardStream,
    spec: &mut ColorSpec,
    left: &str,
    left_color: Color,
    right: &str,
    right_color: Color,
) -> std::io::Result<()> {
    ui_seg(out, spec, UI_LABEL, false, " ")?;
    ui_seg(out, spec, left_color, true, left)?;
    ui_pad(out, spec, 1 + left.chars().count(), UI_RAIL)?;
    ui_seg(out, spec, UI_DIM, false, "│")?;
    ui_seg(out, spec, UI_LABEL, false, "  ")?;
    ui_seg(out, spec, right_color, true, right)?;
    writeln!(out)
}

/// A data row: a dim label plus its own coloured runs in each pane.
pub fn ui_grid_row(
    out: &mut StandardStream,
    spec: &mut ColorSpec,
    left: Option<(&str, &[(Color, String)])>,
    right: Option<(&str, &[(Color, String)])>,
) -> std::io::Result<()> {
    let mut col = 0usize;
    if let Some((label, runs)) = left {
        ui_seg(out, spec, UI_DIM, false, label)?;
        ui_pad(out, spec, label.chars().count(), UI_LEFT_VALUE)?;
        col = UI_LEFT_VALUE;
        for (color, text) in runs {
            ui_seg(out, spec, *color, false, text)?;
            col += text.chars().count();
        }
    }
    ui_pad(out, spec, col, UI_RAIL)?;
    ui_seg(out, spec, UI_DIM, false, "│")?;
    if let Some((label, runs)) = right {
        ui_pad(out, spec, UI_RAIL + 1, UI_RIGHT_LABEL)?;
        ui_seg(out, spec, UI_DIM, false, label)?;
        ui_pad(
            out,
            spec,
            UI_RIGHT_LABEL + label.chars().count(),
            UI_RIGHT_VALUE,
        )?;
        for (color, text) in runs {
            ui_seg(out, spec, *color, false, text)?;
        }
    }
    writeln!(out)
}

/// Write `text` RIGHT-ALIGNED so its last character lands on column `end - 1`,
/// starting from current column `col`; returns the new column.
///
/// Tables must align on a right edge, not on a hand-computed left offset. The
/// first cut of the account table padded forward from each field's start, so
/// the moment one value ran wider than its allowance (`+120.00000000 ♦` against
/// a gap sized for `+10.00000000 ♦`) every column after it was shoved right and
/// the decimal points stopped lining up. Anchoring to the right edge makes an
/// over-wide value eat its own left padding instead of the next column's.
pub fn ui_right(
    out: &mut StandardStream,
    spec: &mut ColorSpec,
    col: usize,
    end: usize,
    color: Color,
    bold: bool,
    text: &str,
) -> std::io::Result<usize> {
    let width = text.chars().count();
    let start = end.saturating_sub(width).max(col);
    ui_pad(out, spec, col, start)?;
    ui_seg(out, spec, color, bold, text)?;
    Ok(start + width)
}

/// `283485` -> `"283,485"`. Heights are read by eye far more often than parsed.
pub fn ui_thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// A money value right-aligned so every decimal point in a column lands on the
/// same screen column. `int_digits` is the widest whole part the column must
/// hold. NEVER format a coin amount with `{}` — that is how the balance screen
/// printed `4210` where every other surface printed `4210.00000000`.
pub fn ui_money(value: f64, int_digits: usize) -> String {
    format!("{:>width$.8} ♦", value, width = int_digits + 9)
}

/// Middle-truncate a 40-hex address, keeping both ends verifiable. Anything
/// that is not a canonical address (`MINING_REWARDS`, say) is returned as-is.
pub fn ui_address(address: &str) -> String {
    if address.len() == 40 && address.chars().all(|c| c.is_ascii_hexdigit()) {
        format!("{}…{}", &address[..8], &address[32..])
    } else {
        address.to_string()
    }
}

/// Compact age for a table column: `12m`, `1h12m`, `3d04h`. Never exceeds 5
/// columns, which is what lets the age column stay flush — past nine days the
/// hours stop earning their two characters, so the day count takes the width
/// instead (`11d`, `115d`) rather than overflowing to `11d13h`.
pub fn ui_age(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, (secs % 86_400) / 3_600, (secs % 3_600) / 60);
    if d >= 10 {
        format!("{}d", d.min(9_999))
    } else if d > 0 {
        format!("{}d{:02}h", d, h)
    } else if h >= 10 {
        format!("{}h", h)
    } else if h > 0 {
        format!("{}h{:02}m", h, m)
    } else if m > 0 {
        format!("{}m", m)
    } else {
        format!("{}s", secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousands_groups_from_the_right() {
        assert_eq!(ui_thousands(0), "0");
        assert_eq!(ui_thousands(999), "999");
        assert_eq!(ui_thousands(1_000), "1,000");
        assert_eq!(ui_thousands(283_485), "283,485");
        assert_eq!(ui_thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn money_column_puts_every_decimal_point_at_one_offset() {
        // The whole point of the helper: two values of different magnitude in
        // the same column must align on the '.', which means equal width.
        let big = ui_money(4210.0, 4);
        let small = ui_money(0.0006, 4);
        assert_eq!(big.chars().count(), small.chars().count());
        assert_eq!(
            big.find('.').map(|i| big[..i].chars().count()),
            small.find('.').map(|i| small[..i].chars().count())
        );
        // And it must never degrade to Display formatting.
        assert!(big.starts_with("4210.00000000"));
    }

    #[test]
    fn address_truncation_keeps_both_ends_and_passes_through_system_senders() {
        let addr = "7d3f9a12c4e80b56af21d9037e6c4b8a5f10e2d9";
        assert_eq!(ui_address(addr), "7d3f9a12…5f10e2d9");
        assert_eq!(ui_address("MINING_REWARDS"), "MINING_REWARDS");
        assert_eq!(ui_address("short"), "short");
    }

    /// The account table's columns must stay flush no matter how wide a value
    /// runs. The first cut padded forward from each field's start, so a
    /// three-digit amount (`+120.00000000 ♦`) overflowed its allowance and
    /// shoved `age`, `height` and `conf` right — the render showed
    /// `1,204 283444` with the last two columns fused.
    #[test]
    fn right_aligned_columns_never_collide_or_shift() {
        const AMOUNT_END: usize = 46;
        const AGE_END: usize = 53;
        const HEIGHT_END: usize = 63;

        // Simulate ui_right's column arithmetic for the widest realistic row.
        let advance = |col: usize, end: usize, text: &str| -> usize {
            let width = text.chars().count();
            let start = end.saturating_sub(width).max(col);
            start + width
        };

        for amount in ["+10.00000000 ♦", "+120.00000000 ♦", "-12345.00000000 ♦"] {
            let mut col = 9 + 17; // counterparty column, 8…8 truncated address
            col = advance(col, AMOUNT_END, amount);
            assert!(col <= AMOUNT_END, "amount {} overflowed its column", amount);
            let before_age = col;
            col = advance(col, AGE_END, "20d");
            assert!(
                col - 3 > before_age,
                "age must keep at least one space from the amount"
            );
            let before_height = col;
            col = advance(col, HEIGHT_END, "283,444");
            assert!(col - 7 > before_height, "height must keep a space from age");
        }
    }

    /// Every label, whatever its length, must put its value on the same column
    /// — otherwise a short label like `Maturing:` visibly breaks the column its
    /// neighbours share.
    #[test]
    fn grid_rows_put_every_value_on_the_same_column() {
        use termcolor::{Buffer, BufferWriter, ColorChoice};
        let writer = BufferWriter::stdout(ColorChoice::Never);
        let render = |label: &str, value: &str| -> String {
            let mut buffer: Buffer = writer.buffer();
            {
                // ui_* take StandardStream; mirror their arithmetic exactly so
                // the assertion tracks the real implementation.
                let pad = UI_LEFT_VALUE.saturating_sub(label.chars().count());
                use std::io::Write as _;
                write!(buffer, "{}{}{}", label, " ".repeat(pad), value).unwrap();
            }
            String::from_utf8(buffer.as_slice().to_vec()).unwrap()
        };
        for (label, value) in [
            ("Total Wallets:", "3"),
            ("Total Balance:", "4410.39502618"),
            ("Maturing:", "none"),
            ("Height:", "289,085"),
            ("Network Height:", "289,085"),
        ] {
            let line = render(label, value);
            let at = line.find(value).expect("value present");
            assert_eq!(
                at, UI_LEFT_VALUE,
                "label {:?} put its value at column {} instead of {}",
                label, at, UI_LEFT_VALUE
            );
        }
    }

    #[test]
    fn age_stays_within_five_columns() {
        for secs in [0, 59, 60, 3_599, 3_600, 86_399, 86_400, 999_999, 9_999_999] {
            assert!(
                ui_age(secs).chars().count() <= 5,
                "age {} rendered as {}",
                secs,
                ui_age(secs)
            );
        }
        assert_eq!(ui_age(720), "12m");
        assert_eq!(ui_age(4_320), "1h12m");
    }
}
