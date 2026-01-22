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

use chrono::{DateTime, TimeDelta, Utc};
use std::sync::{Arc, Mutex};

/// Abstraction for time operations
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

pub fn default_clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

/// Real system clock
struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Mock clock for testing
pub struct MockClock {
    current_time: Arc<Mutex<DateTime<Utc>>>,
}

impl MockClock {
    pub fn new(initial: DateTime<Utc>) -> Self {
        Self {
            current_time: Arc::new(Mutex::new(initial)),
        }
    }

    pub fn advance(&self, duration: TimeDelta) {
        let mut time = self.current_time.lock().unwrap();
        *time = *time + duration;
    }

    pub fn set(&self, instant: DateTime<Utc>) {
        *self.current_time.lock().unwrap() = instant;
    }
}

impl Clock for MockClock {
    fn now(&self) -> DateTime<Utc> {
        *self.current_time.lock().unwrap()
    }
}
