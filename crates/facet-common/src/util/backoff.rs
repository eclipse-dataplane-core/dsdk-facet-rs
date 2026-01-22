//  Copyright (c) 2026 Metaform Systems, Inc
//
//  This program and the accompanying materials are made available under the
//  terms of the Apache License, Version 2.0 which is available at
//  https://www.apache.org/licenses/LICENSE-2.0
//
//  SPDX-License-Identifier: Apache-2.0
//
//  Contributors:
//       Metaform Systems, Inc. - initial API and implementation
//

use log::debug;
use std::time::Duration;

/// Configuration for exponential backoff retry behavior.
#[derive(Debug, Clone, Copy)]
pub struct BackoffConfig {
    /// The multiplier applied for each consecutive failure (e.g., 2 for doubling)
    pub multiplier: u64,
    /// The maximum exponent to prevent unbounded backoff (e.g., 5 for max 2^5 = 32x)
    pub max_exponent: u32,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            multiplier: 2,
            max_exponent: 5,
        }
    }
}

impl BackoffConfig {
    /// Creates a new backoff configuration with custom values.
    pub fn new(multiplier: u64, max_exponent: u32) -> Self {
        Self {
            multiplier,
            max_exponent,
        }
    }
}

/// Calculates a duration with exponential backoff based on consecutive failures.
///
/// The backoff is calculated as: `base_duration * (multiplier ^ min(failure_count, max_exponent))`
///
/// # Arguments
/// * `base_duration` - The base duration before backoff is applied
/// * `failure_count` - The number of consecutive failures
/// * `config` - The backoff configuration
///
/// # Returns
/// The calculated duration with exponential backoff applied
pub fn calculate_backoff_interval(
    base_duration: Duration,
    failure_count: u32,
    config: &BackoffConfig,
) -> Duration {
    // Apply exponential backoff if there have been failures
    let backoff_exponent = failure_count.min(config.max_exponent);
    let backoff_multiplier = config.multiplier.pow(backoff_exponent);
    let interval = base_duration * backoff_multiplier.max(1) as u32;

    if backoff_exponent > 0 {
        debug!(
            "Applying exponential backoff: {}x (failure count: {})",
            backoff_multiplier, failure_count
        );
    }

    interval
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_backoff_on_zero_failures() {
        let base = Duration::from_secs(10);
        let config = BackoffConfig::default();

        let result = calculate_backoff_interval(base, 0, &config);

        assert_eq!(result, Duration::from_secs(10));
    }

    #[test]
    fn test_exponential_backoff_progression() {
        let base = Duration::from_secs(10);
        let config = BackoffConfig::default();

        assert_eq!(
            calculate_backoff_interval(base, 1, &config),
            Duration::from_secs(20)
        ); // 10 * 2^1
        assert_eq!(
            calculate_backoff_interval(base, 2, &config),
            Duration::from_secs(40)
        ); // 10 * 2^2
        assert_eq!(
            calculate_backoff_interval(base, 3, &config),
            Duration::from_secs(80)
        ); // 10 * 2^3
    }

    #[test]
    fn test_backoff_capped_at_max_exponent() {
        let base = Duration::from_secs(10);
        let config = BackoffConfig::default(); // max_exponent = 5

        let result_at_max = calculate_backoff_interval(base, 5, &config);
        let result_beyond_max = calculate_backoff_interval(base, 10, &config);

        assert_eq!(result_at_max, Duration::from_secs(320)); // 10 * 2^5
        assert_eq!(result_beyond_max, Duration::from_secs(320)); // Still 10 * 2^5
    }

    #[test]
    fn test_custom_multiplier() {
        let base = Duration::from_secs(10);
        let config = BackoffConfig::new(3, 5); // 3x multiplier

        assert_eq!(
            calculate_backoff_interval(base, 1, &config),
            Duration::from_secs(30)
        ); // 10 * 3^1
        assert_eq!(
            calculate_backoff_interval(base, 2, &config),
            Duration::from_secs(90)
        ); // 10 * 3^2
    }

    #[test]
    fn test_custom_max_exponent() {
        let base = Duration::from_secs(10);
        let config = BackoffConfig::new(2, 3); // max exponent = 3

        let result = calculate_backoff_interval(base, 10, &config);

        assert_eq!(result, Duration::from_secs(80)); // 10 * 2^3, capped at exponent 3
    }
}