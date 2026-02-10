use std::collections::VecDeque;
use std::io::Write;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

use crate::a9::blockchain::TARGET_BLOCK_TIME;

#[derive(Clone, Debug)]
pub struct DifficultyOracle {
    window_size: usize,
    recent_block_times: VecDeque<u64>,
    difficulty_history: VecDeque<u64>,
    volatility_threshold: f64,
    difficulty_damping_factor: f64,
}

impl DifficultyOracle {
    pub fn new() -> Self {
        Self {
            window_size: 50,
            recent_block_times: VecDeque::with_capacity(50),
            difficulty_history: VecDeque::with_capacity(50),
            volatility_threshold: 0.15,
            difficulty_damping_factor: 0.75,
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

        let changes: Vec<f64> = self
            .difficulty_history
            .iter()
            .zip(self.difficulty_history.iter().skip(1))
            .map(|(a, b)| *b as f64 / *a as f64)
            .collect();

        let mut sorted_changes = changes.clone();
        sorted_changes.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let q1_idx = changes.len() / 4;
        let q3_idx = 3 * changes.len() / 4;
        let iqr = sorted_changes[q3_idx] - sorted_changes[q1_idx];
        let lower = sorted_changes[q1_idx] - 1.5 * iqr;
        let upper = sorted_changes[q3_idx] + 1.5 * iqr;

        let filtered: Vec<f64> = changes
            .into_iter()
            .filter(|&x| x >= lower && x <= upper)
            .collect();

        if filtered.is_empty() {
            return 1.0;
        }

        let mean = filtered.iter().sum::<f64>() / filtered.len() as f64;
        let variance =
            filtered.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / filtered.len() as f64;

        variance.sqrt()
    }

    pub fn estimate_computational_load(&self) -> f64 {
        if self.recent_block_times.len() < 2 {
            return 0.5;
        }

        let intervals: Vec<f64> = self
            .recent_block_times
            .iter()
            .zip(self.recent_block_times.iter().skip(1))
            .map(|(a, b)| (*b - *a) as f64)
            .collect();

        let avg_interval = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let target = TARGET_BLOCK_TIME as f64;

        ((-0.5 * (avg_interval - target).abs()).exp() + 0.1).min(1.0)
    }

    pub fn measure_network_entropy(&self) -> f64 {
        if self.difficulty_history.is_empty() {
            return 0.5;
        }

        let total = self.difficulty_history.iter().sum::<u64>() as f64;
        let probabilities: Vec<f64> = self
            .difficulty_history
            .iter()
            .map(|&x| (x as f64) / total)
            .collect();

        -probabilities
            .iter()
            .filter(|&&p| p > 0.0)
            .map(|&p| p * p.log2())
            .sum::<f64>()
            .max(0.0)
            .min(1.0)
    }

    pub fn assess_network_stability(&self) -> f64 {
        if self.recent_block_times.len() < 2 {
            return 1.0;
        }

        let intervals: Vec<f64> = self
            .recent_block_times
            .iter()
            .zip(self.recent_block_times.iter().skip(1))
            .map(|(a, b)| (*b - *a) as f64)
            .collect();

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance =
            intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;

        (-variance / (4.0 * mean.powi(2))).exp()
    }

    fn calculate_weighted_adjustment(&self, variance: f64, load: f64, entropy: f64) -> f64 {
        let variance_weight = if variance > 0.5 { 0.5 } else { 0.3 };
        let load_weight = if load < 0.2 || load > 0.8 { 0.4 } else { 0.3 };
        let entropy_weight = 1.0 - variance_weight - load_weight;

        (variance * variance_weight) + (load * load_weight) + (entropy * entropy_weight) - 0.5
    }

    pub async fn display_difficulty_metrics(
        &self,
        current_difficulty: u64,
        timestamp_diff: u64,
    ) -> std::io::Result<()> {
        let mut stdout = StandardStream::stdout(ColorChoice::Always);
        let mut header = ColorSpec::new();

        // Core metrics
        let variance = self.calculate_difficulty_variance();
        let load = self.estimate_computational_load();
        let entropy = self.measure_network_entropy();
        let stability = self.assess_network_stability();
        let blocks_missed = timestamp_diff.saturating_sub(TARGET_BLOCK_TIME) / TARGET_BLOCK_TIME;

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
        writeln!(stdout, "Current Difficulty:   {}", current_difficulty)?;
        writeln!(stdout, "Block Age:           {}s", timestamp_diff)?;
        writeln!(stdout, "Blocks Missed:       {}", blocks_missed)?;
        writeln!(stdout, "Time Error:          {:.2}%", timing_error * 100.0)?;

        metrics.set_fg(Some(Color::Rgb(137, 207, 211)));
        stdout.set_color(&metrics)?;
        writeln!(stdout, "\nNetwork State:")?;
        writeln!(
            stdout,
            "Variance:            {:.4} (stability measure)",
            variance
        )?;
        writeln!(stdout, "Load:                {:.1}%", load * 100.0)?;
        writeln!(stdout, "Entropy:             {:.4} (randomness)", entropy)?;
        writeln!(stdout, "Stability:           {:.1}%", stability * 100.0)?;

        // Adjustment Factors
        metrics.set_fg(Some(Color::Rgb(242, 237, 161)));
        stdout.set_color(&metrics)?;
        writeln!(stdout, "\nAdjustment Factors:")?;
        writeln!(stdout, "Timing Factor:       {:.4}", timing_curve)?;

        // System Analysis - Fix the ColorSpec temporary value issue
        let mut alert_style = ColorSpec::new();
        alert_style.set_fg(Some(if blocks_missed > 5 {
            Color::Rgb(255, 84, 73) // Red for alert
        } else if blocks_missed > 2 {
            Color::Rgb(237, 124, 51) // Orange for warning
        } else {
            Color::Rgb(59, 242, 173) // Green for normal
        }));

        stdout.set_color(&alert_style)?;
        writeln!(
            stdout,
            "\nSystem Status: {}\n",
            match blocks_missed {
                0..=2 => "Normal Operation",
                3..=5 => "Minor Adjustment Needed",
                6..=10 => "Significant Deviation",
                _ => "Critical Adjustment Required",
            }
        )?;

        stdout.reset()?;
        Ok(())
    }
}
