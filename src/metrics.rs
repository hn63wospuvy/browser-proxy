//! Lightweight global counters for debugging the Wisp relay. Exposed at `/debug/stats`.
//!
//! Counter names are lowercase so they read as-is in the JSON snapshot.
#![allow(non_upper_case_globals)]

use std::sync::atomic::{AtomicU64, Ordering};

macro_rules! counters {
    ($($name:ident),* $(,)?) => {
        $( pub static $name: AtomicU64 = AtomicU64::new(0); )*

        /// Render all counters as a JSON object.
        pub fn snapshot_json() -> String {
            let mut s = String::from("{\n");
            let mut first = true;
            $(
                if !first { s.push_str(",\n"); }
                first = false;
                s.push_str(&format!("  {:?}: {}", stringify!($name), $name.load(Ordering::Relaxed)));
            )*
            s.push_str("\n}\n");
            s
        }
    };
}

counters! {
    connections_total,
    connections_rejected_maxconn,
    streams_total,
    streams_connected,
    streams_connect_failed,
    streams_refused_maxstreams,
    streams_window_violation,
    streams_closed,
}

#[inline]
pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}
