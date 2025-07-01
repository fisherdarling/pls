#![deny(missing_docs)]
//! A simple, zero-dependency progress bar library for Rust.
//!
//! This library provides a thread-safe progress bar with customizable message formatting,
//! automatic rate calculation, and background display updates. It's designed to be lightweight
//! and performant, supporting thousands of increments per second with minimal overhead.
//!
//! Progress bar messages support the following placeholders:
//!
//! - `{total}`: Replaced with the current total count
//! - `{elapsed}`: Replaced with elapsed time in [HH:MM:SS] format
//! - `{rate}`: Replaced with the current rate (items per second) as a truncated integer
//!
//! # Example
//!
//! ```rust
//! use simple_progress::ProgressBar;
//! use std::thread;
//! use std::time::Duration;
//!
//! let pb = ProgressBar::new("Progress: {elapsed} | Rate: {rate}/s");
//!
//! // Single increments
//! for _ in 0..100 {
//!     pb.inc();
//!     thread::sleep(Duration::from_millis(10));
//! }
//!
//! // Batch increments
//! pb.inc_many(50);
//!
//! // Log messages above the progress bar
//! pb.log("Done!");
//! ```

use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// A thread-safe progress bar with customizable formatting and automatic rate calculation.
///
/// The progress bar runs a background thread that updates the display every 100 milliseconds.
/// It supports custom message formatting with `{elapsed}` (HH:MM:SS format) and `{rate}`
/// (items per second) placeholders.
///
/// # Thread Safety
///
/// `ProgressBar` is designed to be cloned and shared across threads.
pub struct ProgressBar {
    inner: Arc<ProgressBarInner>,
}

struct ProgressBarInner {
    count: AtomicUsize,
    start_time: Instant,
    message_format: String,
    last_count: AtomicUsize,
    last_time: Mutex<Instant>,
    last_rate: AtomicUsize,
}

impl ProgressBar {
    /// Creates a new progress bar with the specified message format.
    ///
    /// The message format supports three placeholders:
    /// - `{total}`: Replaced with the current total count
    /// - `{elapsed}`: Replaced with elapsed time in [HH:MM:SS] format
    /// - `{rate}`: Replaced with the current rate (items per second) as a truncated integer
    ///
    /// # Example
    ///
    /// ```rust
    /// use simple_progress::ProgressBar;
    ///
    /// let pb = ProgressBar::new("Processing: {total} items | {elapsed} | {rate}/s");
    /// ```
    pub fn new(message_format: impl Into<String>) -> Self {
        let inner = Arc::new(ProgressBarInner {
            count: AtomicUsize::new(0),
            start_time: Instant::now(),
            message_format: message_format.into(),
            last_count: AtomicUsize::new(0),
            last_time: Mutex::new(Instant::now()),
            last_rate: AtomicUsize::new(0),
        });

        let inner_clone = Arc::clone(&inner);
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_millis(100));
                inner_clone.display_progress();
            }
        });

        ProgressBar { inner }
    }

    /// Increments the progress counter by 1.
    pub fn inc(&self) {
        self.inner.count.fetch_add(1, Ordering::SeqCst);
    }

    /// Increments the progress counter by the specified amount.
    ///
    /// This method is more efficient than calling `inc()` multiple times
    /// when you need to add a large number of items at once.
    pub fn inc_many(&self, count: usize) {
        self.inner.count.fetch_add(count, Ordering::SeqCst);
    }

    /// Logs a message above the progress bar.
    ///
    /// The message will be printed on its own line above the progress bar,
    /// and the progress bar will continue updating on the line below.
    pub fn log(&self, msg: impl AsRef<str>) {
        print!("\r\x1b[K{}\n", msg.as_ref());
        io::stdout().flush().unwrap();
    }
}

impl Clone for ProgressBar {
    fn clone(&self) -> Self {
        ProgressBar {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl ProgressBarInner {
    fn display_progress(&self) {
        let current_count = self.count.load(Ordering::Relaxed);
        let mut message = self.message_format.clone();

        if message.contains("{total}") {
            message = message.replace("{total}", &current_count.to_string());
        }

        if message.contains("{elapsed}") {
            let elapsed = self.start_time.elapsed();
            let elapsed_str = format_elapsed(elapsed);
            message = message.replace("{elapsed}", &elapsed_str);
        }

        if message.contains("{rate}") {
            let rate = self.calculate_rate(current_count);
            message = message.replace("{rate}", &rate.to_string());
        }

        print!("\r\x1b[K{}", message);
        io::stdout().flush().unwrap();
    }

    fn calculate_rate(&self, current_count: usize) -> usize {
        let now = Instant::now();
        let mut last_time = self.last_time.lock().unwrap();
        let last_count = self.last_count.load(Ordering::Relaxed);

        let time_diff = now.duration_since(*last_time).as_secs_f64();

        if time_diff >= 0.1 {
            let count_diff = current_count.saturating_sub(last_count);
            let rate = (count_diff as f64 / time_diff) as usize;

            self.last_count.store(current_count, Ordering::Relaxed);
            *last_time = now;
            self.last_rate.store(rate, Ordering::Relaxed);

            rate
        } else {
            self.last_rate.load(Ordering::Relaxed)
        }
    }
}

fn format_elapsed(elapsed: Duration) -> String {
    let total_seconds = elapsed.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    format!("[{:02}:{:02}:{:02}]", hours, minutes, seconds)
}
