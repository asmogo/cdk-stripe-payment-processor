// Metrics placeholders for Stripe provider.
// If a metrics infrastruture exists later, swap these no-ops with real counters/histograms.

#[macro_export]
macro_rules! stripe_counter_inc {
    ($name:expr $(, $key:expr => $val:expr )* $(,)?) => {
        // no-op placeholder
        let _ = ($name $(, $key, $val )*);
    };
}

#[macro_export]
macro_rules! stripe_histogram_observe_ms {
    ($name:expr, $ms:expr $(, $key:expr => $val:expr )* $(,)?) => {
        // no-op placeholder
        let _ = ($name, $ms $(, $key, $val )*);
    };
}