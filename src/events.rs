// Copyright 2025 The dcSCTP Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::EventSink;
use crate::api::SocketEvent;
use std::collections::VecDeque;

pub struct Events {
    events: VecDeque<SocketEvent>,
}

impl Events {
    pub fn new() -> Self {
        Self { events: VecDeque::new() }
    }

    pub fn next_event(&mut self) -> Option<SocketEvent> {
        self.events.pop_front()
    }
}

impl EventSink for Events {
    fn add(&mut self, event: SocketEvent) {
        self.events.push_back(event);
    }

    fn next_event(&mut self) -> Option<SocketEvent> {
        self.events.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::LifecycleId;
    use crate::testing::event_helpers::expect_no_event;
    use crate::testing::event_helpers::expect_on_connected;
    use crate::testing::event_helpers::expect_on_lifecycle_message_fully_sent;

    #[test]
    fn can_enqueue_and_match_events() {
        let mut events = Events::new();
        events.add(SocketEvent::OnConnected());
        events.add(SocketEvent::OnLifecycleMessageFullySent(LifecycleId::from(123)));

        expect_on_connected!(events.next_event());
        assert_eq!(
            expect_on_lifecycle_message_fully_sent!(events.next_event()),
            LifecycleId::from(123)
        );
        expect_no_event!(events.next_event());
    }
}
