use std::collections::VecDeque;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

use crate::a9::blockchain::TARGET_BLOCK_TIME;

#[derive(Clone, Debug)]
pub struct DifficultyOracle {
    window_size: usize,
    recent_block_times: VecDeque<u64>,
    difficulty_history: VecDeque<u64>,
}

#[derive(Clone, Copy, Debug)]
struct NetworkState {
    variance: f64,
    load: f64,
    entropy: f64,
    stability: f64,
}

impl DifficultyOracle {
    pub fn new() -> Self {
        Self {
            window_size: 50,
            recent_block_times: VecDeque::with_capacity(50),
            difficulty_history: VecDeque::with_capacity(50),
        }
    }

    pub fn record_block_metrics(&mut self, timestamp: u64, difficulty: u64) {
        if self.recent_block_times.len() >= self.window_size {
            self.recent_block_times.pop_front();
            self.difficulty_history.pop_front();
        }
        self.recent_block_times.push_back(timestamp);
        self.difficulty_history.push_back(difficulty);
    }

    pub fn calculate_difficulty_variance(&self) -> f64 {
        if self.difficulty_history.len() < 2 {
            return 1.0;
        }

        let mut changes: Vec<f64> = self
            .difficulty_history
            .iter()
            .zip(self.difficulty_history.iter().skip(1))
            .map(|(a, b)| if *a == 0 { 1.0 } else { *b as f64 / *a as f64 })
            .collect();
        changes.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let q1_idx = changes.len() / 4;
        let q3_idx = 3 * changes.len() / 4;
        let iqr = changes[q3_idx] - changes[q1_idx];
        let lower = changes[q1_idx] - 1.5 * iqr;
        let upper = changes[q3_idx] + 1.5 * iqr;

        let mut count = 0usize;
        let mut sum = 0.0f64;
        for &x in &changes {
            if x >= lower && x <= upper {
                sum += x;
                count += 1;
            }
        }
        if count == 0 {
            return 1.0;
        }

        let mean = sum / count as f64;
        let mut variance_sum = 0.0f64;
        for &x in &changes {
            if x >= lower && x <= upper {
                variance_sum += (x - mean).powi(2);
            }
        }
        let variance = variance_sum / count as f64;

        variance.sqrt()
    }

    pub fn estimate_computational_load(&self) -> f64 {
        if self.recent_block_times.len() < 2 {
            return 0.5;
        }

        let mut count = 0usize;
        let mut sum = 0.0f64;
        let mut prev = None;
        for &ts in &self.recent_block_times {
            if let Some(last) = prev {
                sum += ts.saturating_sub(last) as f64;
                count += 1;
            }
            prev = Some(ts);
        }
        if count == 0 {
            return 0.5;
        }

        let avg_interval = sum / count as f64;
        let target = TARGET_BLOCK_TIME as f64;

        ((-0.5 * (avg_interval - target).abs()).exp() + 0.1).min(1.0)
    }

    pub fn measure_network_entropy(&self) -> f64 {
        if self.difficulty_history.is_empty() {
            return 0.5;
        }

        let total = self.difficulty_history.iter().sum::<u64>() as f64;
        if total == 0.0 {
            return 0.5;
        }

        let mut entropy = 0.0f64;
        for &x in &self.difficulty_history {
            let p = (x as f64) / total;
            if p > 0.0 {
                entropy += p * p.log2();
            }
        }

        (-entropy).clamp(0.0, 1.0)
    }

    pub fn assess_network_stability(&self) -> f64 {
        if self.recent_block_times.len() < 2 {
            return 1.0;
        }

        // Welford's algorithm gives mean/variance in one pass without storing intervals.
        let mut n = 0usize;
        let mut mean = 0.0f64;
        let mut m2 = 0.0f64;
        let mut prev = None;
        for &ts in &self.recent_block_times {
            if let Some(last) = prev {
                let x = ts.saturating_sub(last) as f64;
                n += 1;
                let delta = x - mean;
                mean += delta / n as f64;
                let delta2 = x - mean;
                m2 += delta * delta2;
            }
            prev = Some(ts);
        }
        if n == 0 || mean == 0.0 {
            return 1.0;
        }
        let variance = m2 / n as f64;

        (-variance / (4.0 * mean.powi(2))).exp()
    }

    /// Return measured network state only when at least one block interval is
    /// available. The individual calculation helpers retain their historical
    /// defaults for consensus-adjacent callers, but diagnostics must never
    /// present those fallback constants as observations from the live chain.
    fn network_state(&self) -> Option<NetworkState> {
        if self.recent_block_times.len() < 2 || self.difficulty_history.len() < 2 {
            return None;
        }
        Some(NetworkState {
            variance: self.calculate_difficulty_variance(),
            load: self.estimate_computational_load(),
            entropy: self.measure_network_entropy(),
            stability: self.assess_network_stability(),
        })
    }

    pub async fn display_difficulty_metrics(
        &self,
        tip_difficulty: u64,
        next_difficulty: u64,
        timestamp_diff: u64,
    ) -> std::io::Result<()> {
        let mut stdout = StandardStream::stdout(ColorChoice::Always);
        self.write_difficulty_metrics(&mut stdout, tip_difficulty, next_difficulty, timestamp_diff)
    }

    fn write_difficulty_metrics<W: WriteColor>(
        &self,
        stdout: &mut W,
        tip_difficulty: u64,
        next_difficulty: u64,
        timestamp_diff: u64,
    ) -> std::io::Result<()> {
        let mut header = ColorSpec::new();

        // Core metrics
        let network_state = self.network_state();
        let idle_intervals = timestamp_diff.saturating_sub(TARGET_BLOCK_TIME) / TARGET_BLOCK_TIME;

        // Calculate adjustment components
        let timing_error =
            (timestamp_diff as f64 - TARGET_BLOCK_TIME as f64) / TARGET_BLOCK_TIME as f64;
        let timing_curve = 1.0 + (timing_error * -0.1);

        header.set_fg(Some(Color::Rgb(59, 242, 173))).set_bold(true);
        stdout.set_color(&header)?;
        writeln!(stdout, "\nDifficulty Engine Metrics")?;
        writeln!(stdout, "───────────────────")?;

        let mut metrics = ColorSpec::new();
        metrics.set_fg(Some(Color::Rgb(230, 230, 230)));
        stdout.set_color(&metrics)?;
        writeln!(stdout, "Base Metrics:")?;
        writeln!(stdout, "Tip Difficulty:        {}", tip_difficulty)?;
        writeln!(stdout, "Next Mining Difficulty: {}", next_difficulty)?;
        writeln!(stdout, "Tip Age:              {}s", timestamp_diff)?;
        writeln!(stdout, "Idle Target Intervals: {}", idle_intervals)?;
        writeln!(stdout, "Time Drift:           {:.2}%", timing_error * 100.0)?;

        metrics.set_fg(Some(Color::Rgb(137, 207, 211)));
        stdout.set_color(&metrics)?;
        writeln!(stdout, "\nNetwork State:")?;
        if let Some(state) = network_state {
            writeln!(
                stdout,
                "Variance:            {:.4} (stability measure)",
                state.variance
            )?;
            writeln!(stdout, "Load:                {:.1}%", state.load * 100.0)?;
            writeln!(
                stdout,
                "Entropy:             {:.4} (randomness)",
                state.entropy
            )?;
            writeln!(
                stdout,
                "Stability:           {:.1}%",
                state.stability * 100.0
            )?;
        } else {
            const UNAVAILABLE: &str = "unavailable (insufficient history)";
            writeln!(stdout, "Variance:            {UNAVAILABLE}")?;
            writeln!(stdout, "Load:                {UNAVAILABLE}")?;
            writeln!(stdout, "Entropy:             {UNAVAILABLE}")?;
            writeln!(stdout, "Stability:           {UNAVAILABLE}")?;
        }

        // Adjustment Factors
        metrics.set_fg(Some(Color::Rgb(242, 237, 161)));
        stdout.set_color(&metrics)?;
        writeln!(stdout, "\nAdjustment Factors:")?;
        writeln!(stdout, "Timing Factor:       {:.4}", timing_curve)?;

        // System Analysis - Fix the ColorSpec temporary value issue
        let mut alert_style = ColorSpec::new();
        alert_style.set_fg(Some(if idle_intervals > 12 {
            Color::Rgb(237, 124, 51) // Orange for warning
        } else {
            Color::Rgb(59, 242, 173) // Green for normal
        }));

        stdout.set_color(&alert_style)?;
        writeln!(
            stdout,
            "\nSystem Status: {}\n",
            match idle_intervals {
                0..=2 => "Active Tip",
                3..=12 => "Idle Network: waiting for next mined block",
                _ => "Extended Idle: next block will apply the slow-block floor if needed",
            }
        )?;

        stdout.reset()?;
        Ok(())
    }
}

impl Default for DifficultyOracle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use termcolor::Buffer;

    fn rendered(oracle: &DifficultyOracle) -> String {
        let mut buffer = Buffer::no_color();
        oracle
            .write_difficulty_metrics(&mut buffer, 100, 101, TARGET_BLOCK_TIME)
            .expect("render diagnostics");
        String::from_utf8(buffer.as_slice().to_vec()).expect("diagnostics are UTF-8")
    }

    #[test]
    fn diagnostics_do_not_present_defaults_as_live_measurements() {
        let mut oracle = DifficultyOracle::new();
        assert!(oracle.network_state().is_none());

        oracle.record_block_metrics(100, 100);
        assert!(oracle.network_state().is_none());
        let output = rendered(&oracle);
        assert_eq!(
            output.matches("unavailable (insufficient history)").count(),
            4
        );
        assert!(!output.contains("Load:                50.0%"));
    }

    #[test]
    fn diagnostics_use_recorded_block_history() {
        let mut oracle = DifficultyOracle::new();
        oracle.record_block_metrics(100, 100);
        oracle.record_block_metrics(105, 110);

        let state = oracle.network_state().expect("one interval is sufficient");
        assert_eq!(state.load, 1.0);
        let output = rendered(&oracle);
        assert!(!output.contains("unavailable"));
        assert!(output.contains("Load:                100.0%"));
    }
}
