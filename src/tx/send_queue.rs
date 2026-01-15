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
use crate::api::LifecycleId;
use crate::api::Message;
use crate::api::Options;
use crate::api::SendOptions;
use crate::api::SocketEvent;
use crate::api::SocketTime;
use crate::api::StreamId;
use crate::api::handover::HandoverOutgoingStream;
use crate::api::handover::HandoverReadiness;
use crate::api::handover::SocketHandoverState;
use crate::packet::data::Data;
use crate::tx::stream_scheduler::StreamScheduler;
use crate::types::Fsn;
use crate::types::Mid;
use crate::types::OutgoingMessageId;
use crate::types::Ssn;
use crate::types::StreamKey;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::ops::AddAssign;
use std::ops::SubAssign;
use std::rc::Rc;
use std::time::Duration;

const DEFAULT_EXPIRY: Duration = Duration::from_secs(3600);

pub(crate) struct DataToSend {
    pub message_id: OutgoingMessageId,
    pub data: Data,
    pub max_retransmissions: u16,
    pub expires_at: SocketTime,
    pub lifecycle_id: Option<LifecycleId>,
}

struct MessageAttributes {
    pub unordered: bool,
    pub max_retransmissions: u16,
    pub expires_at: SocketTime,
    pub lifecycle_id: Option<LifecycleId>,
}

/// Streams are paused before they can be reset. To reset a stream, the socket sends an outgoing
/// stream reset command with the TSN of the last fragment of the last message, so that receivers
/// and senders can agree on when it stopped. And if the send queue is in the middle of sending a
/// message, and without fragments not yet sent and without TSNs allocated to them, it will keep
/// sending data until that message has ended.
#[derive(PartialEq)]
enum PauseState {
    /// The stream is not paused, and not scheduled to be reset.
    NotPaused,

    /// The stream has requested to be reset/paused but is still producing fragments of a message
    /// that hasn't ended yet. When it does, it will transition to the `Paused` state.
    Pending,

    /// The stream is fully paused and can be reset.
    Paused,

    /// The stream has been added to an outgoing stream reset request and a response from the peer
    /// hasn't been received yet.
    Resetting,
}

/// An enqueued message and metadata.
struct Item {
    message_id: OutgoingMessageId,
    message: Message,
    attributes: MessageAttributes,

    /// The remaining payload offset to be sent when the message is fragmented.
    remaining_offset: usize,

    /// The remaining size of the payload to be sent when the message is fragmented.
    remaining_size: usize,

    /// The allocated Message ID, assigned when the first fragment is sent.
    mid: Option<Mid>,

    /// The allocated Stream Sequence Number, assigned when the first fragment is sent.
    ssn: Option<Ssn>,

    /// The current Fragment Sequence Number, incremented for each fragment.
    current_fsn: Fsn,
}

impl Item {
    fn new(message_id: OutgoingMessageId, message: Message, attributes: MessageAttributes) -> Self {
        let payload_size = message.payload.len();
        Self {
            message_id,
            message,
            attributes,
            remaining_offset: 0,
            remaining_size: payload_size,
            mid: None,
            ssn: None,
            current_fsn: Fsn(0),
        }
    }
}

struct ThresholdWatcher<'a> {
    value: usize,
    low_threshold: usize,
    low_cb: Box<dyn Fn() + 'a>,
}

fn add_lifecycle_events(events: &Rc<RefCell<dyn EventSink>>, lifecycle_id: &Option<LifecycleId>) {
    if let Some(lid) = &lifecycle_id {
        events.borrow_mut().add(SocketEvent::OnLifecycleMessageExpired(lid.clone()));
        events.borrow_mut().add(SocketEvent::OnLifecycleEnd(lid.clone()));
    }
}

impl<'a> ThresholdWatcher<'a> {
    pub fn new(low_threshold: usize, low_cb: impl Fn() + 'a) -> Self {
        Self { value: 0, low_threshold, low_cb: Box::new(low_cb) }
    }

    pub fn set_low_threshold(&mut self, low_threshold: usize) {
        if self.low_threshold < self.value && low_threshold >= self.value {
            (self.low_cb)();
        }
        self.low_threshold = low_threshold;
    }
}

impl AddAssign<usize> for ThresholdWatcher<'_> {
    fn add_assign(&mut self, rhs: usize) {
        self.value += rhs;
    }
}

impl SubAssign<usize> for ThresholdWatcher<'_> {
    fn sub_assign(&mut self, rhs: usize) {
        debug_assert!(self.value >= rhs);

        let old_value = self.value;
        self.value -= rhs;
        if old_value > self.low_threshold && self.value <= self.low_threshold {
            (self.low_cb)();
        }
    }
}

/// Per-stream information.
struct OutgoingStream<'a> {
    priority: u16,
    pause_state: PauseState,
    next_unordered_mid: Mid,
    next_ordered_mid: Mid,
    next_ssn: Ssn,
    buffered_amount: ThresholdWatcher<'a>,
    items: VecDeque<Item>,
}

impl<'a> OutgoingStream<'a> {
    fn new(priority: u16, low_threshold: usize, low_cb: impl Fn() + 'a) -> Self {
        Self {
            priority,
            pause_state: PauseState::NotPaused,
            next_unordered_mid: Mid(0),
            next_ordered_mid: Mid(0),
            next_ssn: Ssn(0),
            buffered_amount: ThresholdWatcher::new(low_threshold, low_cb),
            items: VecDeque::new(),
        }
    }
}

pub struct SendQueue<'a> {
    enable_message_interleaving: bool,
    default_priority: u16,
    default_low_buffered_amount_low_threshold: usize,
    buffered_amount: ThresholdWatcher<'a>,
    current_message_id: OutgoingMessageId,
    scheduler: StreamScheduler,
    streams: HashMap<StreamId, OutgoingStream<'a>>,
    events: Rc<RefCell<dyn EventSink>>,
}

impl<'a> SendQueue<'a> {
    pub fn new(
        max_payload_bytes: usize,
        options: &Options,
        events: Rc<RefCell<dyn EventSink>>,
    ) -> Self {
        let buffered_amount_low_events = Rc::clone(&events);
        Self {
            enable_message_interleaving: false,
            default_priority: options.default_stream_priority,
            default_low_buffered_amount_low_threshold: options
                .default_stream_buffered_amount_low_threshold,
            buffered_amount: ThresholdWatcher::new(
                options.total_buffered_amount_low_threshold,
                move || {
                    buffered_amount_low_events
                        .borrow_mut()
                        .add(SocketEvent::OnTotalBufferedAmountLow())
                },
            ),
            current_message_id: OutgoingMessageId(0),
            streams: HashMap::new(),
            scheduler: StreamScheduler::new(max_payload_bytes),
            events: Rc::clone(&events),
        }
    }

    pub fn enable_message_interleaving(&mut self, enable: bool) {
        if enable != self.enable_message_interleaving {
            self.enable_message_interleaving = enable;
            // The stream scheduler needs to recalculate the next virtual time for every stream.
            for (stream_id, stream) in &self.streams {
                self.scheduler.set_bytes_remaining(
                    *stream_id,
                    stream.items.front().map_or(0, |i| i.remaining_size),
                    self.enable_message_interleaving.then_some(stream.priority),
                );
            }
        }
    }

    fn get_stream_to_produce_from(
        &mut self,
        now: SocketTime,
        max_size: usize,
    ) -> Option<(StreamId, usize)> {
        loop {
            let (stream_id, size) = self.scheduler.peek(max_size)?;
            let stream = self.streams.get_mut(&stream_id).unwrap();
            let item = stream.items.front().unwrap();
            if item.attributes.expires_at <= now {
                // Oops, this entire message has already expired. Try the next one.
                self.buffered_amount -= item.remaining_size;
                stream.buffered_amount -= item.remaining_size;
                add_lifecycle_events(&self.events, &item.attributes.lifecycle_id);
                stream.items.pop_front();
                let priority = self.enable_message_interleaving.then_some(stream.priority);
                self.scheduler.set_bytes_remaining(
                    stream_id,
                    stream.items.front().map(|i| i.remaining_size).unwrap_or(0),
                    priority,
                );
                continue;
            }
            self.scheduler.accept(stream_id, size);
            return Some((stream_id, size));
        }
    }

    fn make_stream(
        stream_id: StreamId,
        priority: u16,
        low_threshold: usize,
        events: Rc<RefCell<dyn EventSink>>,
    ) -> OutgoingStream<'a> {
        OutgoingStream::new(priority, low_threshold, move || {
            events.borrow_mut().add(SocketEvent::OnBufferedAmountLow(stream_id))
        })
    }

    pub fn add(&mut self, now: SocketTime, message: Message, send_options: &SendOptions) {
        let attributes = MessageAttributes {
            unordered: send_options.unordered,
            max_retransmissions: send_options.max_retransmissions.unwrap_or(u16::MAX),
            expires_at: now
                + send_options.lifetime.unwrap_or(DEFAULT_EXPIRY)
                + Duration::from_millis(1),
            lifecycle_id: send_options.lifecycle_id.clone(),
        };
        let stream_id = message.stream_id;
        let stream = self.streams.entry(stream_id).or_insert_with(|| {
            SendQueue::make_stream(
                stream_id,
                self.default_priority,
                self.default_low_buffered_amount_low_threshold,
                Rc::clone(&self.events),
            )
        });
        let message_id = self.current_message_id;
        self.current_message_id += 1;
        stream.buffered_amount += message.payload.len();
        self.buffered_amount += message.payload.len();
        stream.items.push_back(Item::new(message_id, message, attributes));
        if (stream.pause_state == PauseState::NotPaused
            || stream.pause_state == PauseState::Pending)
            && stream.items.len() == 1
        {
            let priority = self.enable_message_interleaving.then_some(stream.priority);
            self.scheduler.set_bytes_remaining(stream_id, stream.items[0].remaining_size, priority);
        }
    }

    pub fn produce(&mut self, now: SocketTime, max_size: usize) -> Option<DataToSend> {
        let (stream_id, size) = self.get_stream_to_produce_from(now, max_size)?;

        let stream = self.streams.get_mut(&stream_id).unwrap();
        let item = stream.items.front_mut().unwrap();
        if item.mid.is_none() {
            if item.attributes.unordered {
                item.mid = Some(stream.next_unordered_mid);
                stream.next_unordered_mid += 1;
            } else {
                item.mid = Some(stream.next_ordered_mid);
                stream.next_ordered_mid += 1;
                item.ssn = Some(stream.next_ssn);
                stream.next_ssn += 1;
            }
        }
        let is_beginning = item.remaining_offset == 0;
        let is_end = size == item.remaining_size;
        let fsn = item.current_fsn;
        let lifecycle_id = if is_end { item.attributes.lifecycle_id.clone() } else { None };
        item.current_fsn += 1;
        let payload = item
            .message
            .payload
            .get(item.remaining_offset..size + item.remaining_offset)
            .unwrap()
            .to_vec();
        self.buffered_amount -= payload.len();
        stream.buffered_amount -= payload.len();

        let data = Data {
            stream_key: StreamKey::new(item.attributes.unordered, stream_id),
            ssn: item.ssn.unwrap_or(Ssn(0)),
            mid: item.mid.unwrap(),
            fsn,
            ppid: item.message.ppid,
            payload,
            is_beginning,
            is_end,
        };

        let data = DataToSend {
            message_id: item.message_id,
            data,
            max_retransmissions: item.attributes.max_retransmissions,
            expires_at: item.attributes.expires_at,
            lifecycle_id,
        };
        if is_end {
            stream.items.pop_front();

            if stream.pause_state == PauseState::Pending {
                stream.pause_state = PauseState::Paused;
            }

            let bytes_next = match (&stream.pause_state, stream.items.front()) {
                (PauseState::Paused, _) => 0,
                (_, None) => 0,
                (_, Some(item)) => item.remaining_size,
            };
            self.scheduler.set_bytes_remaining(
                stream_id,
                bytes_next,
                self.enable_message_interleaving.then_some(stream.priority),
            );
        } else {
            item.remaining_offset += size;
            item.remaining_size -= size;
        }
        Some(data)
    }

    pub fn discard(&mut self, stream_id: StreamId, message_id: OutgoingMessageId) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let Some(item) = stream.items.front() else {
            return;
        };
        if item.message_id != message_id {
            return;
        }
        self.buffered_amount -= item.remaining_size;
        stream.buffered_amount -= item.remaining_size;
        add_lifecycle_events(&self.events, &item.attributes.lifecycle_id);
        stream.items.pop_front();

        let priority = self.enable_message_interleaving.then_some(stream.priority);
        if stream.pause_state == PauseState::Pending {
            stream.pause_state = PauseState::Paused;
            self.scheduler.set_bytes_remaining(stream_id, 0, priority)
        } else {
            self.scheduler.set_bytes_remaining(
                stream_id,
                stream.items.front().map(|i| i.remaining_size).unwrap_or(0),
                priority,
            );
        }
    }

    pub fn prepare_reset_stream(&mut self, stream_id: StreamId) {
        let stream = self.streams.entry(stream_id).or_insert_with(|| {
            SendQueue::make_stream(
                stream_id,
                self.default_priority,
                self.default_low_buffered_amount_low_threshold,
                Rc::clone(&self.events),
            )
        });
        if stream.pause_state != PauseState::NotPaused {
            // Already in progress.
            return;
        }
        let had_pending_items = !stream.items.is_empty();

        // From <https://datatracker.ietf.org/doc/html/rfc8831#section-6.7>:
        //
        //   Closing of a data channel MUST be signaled by resetting the corresponding outgoing
        //   streams [RFC6525]. This means that if one side decides to close the data channel, it
        //   resets the corresponding outgoing stream. When the peer sees that an incoming stream
        //   was reset, it also resets its corresponding outgoing stream. [...]
        //
        //   [RFC6525] also guarantees that all the messages are delivered (or abandoned) before the
        //   stream is reset.
        //
        // A stream is paused when it's about to be reset. In this implementation, it will throw
        // away all non-partially send messages - they will be abandoned as noted above. This is
        // subject to change. It will however not discard any partially sent messages - only whole
        // messages. Partially delivered messages (at the time of receiving a Stream Reset command)
        // will always deliver all the fragments before actually resetting the stream.
        stream.items.retain_mut(|i| {
            if i.remaining_offset == 0 {
                stream.buffered_amount -= i.remaining_size;
                self.buffered_amount -= i.remaining_size;
                add_lifecycle_events(&self.events, &i.attributes.lifecycle_id);
                return false;
            }
            true
        });
        if stream.items.is_empty() {
            stream.pause_state = PauseState::Paused;
            if had_pending_items {
                let priority = self.enable_message_interleaving.then_some(stream.priority);
                self.scheduler.set_bytes_remaining(stream_id, 0, priority);
            }
        } else {
            stream.pause_state = PauseState::Pending;
        }
    }

    pub fn has_streams_ready_to_be_reset(&self) -> bool {
        self.streams.iter().any(|(_, stream)| stream.pause_state == PauseState::Paused)
    }

    pub fn get_streams_ready_to_reset(&mut self) -> Vec<StreamId> {
        let mut ready: Vec<StreamId> = Vec::new();
        self.streams.iter_mut().for_each(|(stream_id, stream)| {
            if stream.pause_state == PauseState::Paused {
                stream.pause_state = PauseState::Resetting;
                ready.push(*stream_id);
            }
        });
        ready
    }

    pub fn commit_reset_streams(&mut self) {
        self.streams.iter_mut().for_each(|(stream_id, stream)| {
            if stream.pause_state == PauseState::Resetting {
                stream.pause_state = PauseState::NotPaused;
                stream.next_ordered_mid = Mid(0);
                stream.next_unordered_mid = Mid(0);
                stream.next_ssn = Ssn(0);
                if let Some(item) = stream.items.front() {
                    let priority = self.enable_message_interleaving.then_some(stream.priority);
                    self.scheduler.set_bytes_remaining(*stream_id, item.remaining_size, priority)
                }
            }
        });
    }

    pub fn rollback_reset_streams(&mut self) {
        self.streams.iter_mut().for_each(|(stream_id, stream)| {
            if stream.pause_state == PauseState::Resetting {
                stream.pause_state = PauseState::NotPaused;
                if let Some(item) = &stream.items.front() {
                    let priority = self.enable_message_interleaving.then_some(stream.priority);
                    self.scheduler.set_bytes_remaining(*stream_id, item.remaining_size, priority);
                }
            }
        });
    }

    pub fn reset(&mut self) {
        self.streams.iter_mut().for_each(|(stream_id, stream)| {
            stream.pause_state = PauseState::NotPaused;
            stream.next_ordered_mid = Mid(0);
            stream.next_unordered_mid = Mid(0);
            stream.next_ssn = Ssn(0);
            if let Some(item) = stream.items.front_mut() {
                let item_size = item.message.payload.len();
                self.buffered_amount += item_size - item.remaining_size;
                stream.buffered_amount += item_size - item.remaining_size;
                item.remaining_offset = 0;
                item.remaining_size = item_size;
                let priority = self.enable_message_interleaving.then_some(stream.priority);
                self.scheduler.set_bytes_remaining(*stream_id, item_size, priority)
            }
        });
    }

    pub fn buffered_amount(&self, stream_id: StreamId) -> usize {
        match self.streams.get(&stream_id) {
            Some(stream) => stream.buffered_amount.value,
            None => 0,
        }
    }

    pub fn total_buffered_amount(&self) -> usize {
        self.buffered_amount.value
    }

    pub fn buffered_amount_low_threshold(&self, stream_id: StreamId) -> usize {
        match self.streams.get(&stream_id) {
            Some(stream) => stream.buffered_amount.low_threshold,
            None => self.default_low_buffered_amount_low_threshold,
        }
    }

    pub fn set_buffered_amount_low_threshold(&mut self, stream_id: StreamId, threshold: usize) {
        let stream = self.streams.entry(stream_id).or_insert_with(|| {
            SendQueue::make_stream(
                stream_id,
                self.default_priority,
                self.default_low_buffered_amount_low_threshold,
                Rc::clone(&self.events),
            )
        });
        stream.buffered_amount.set_low_threshold(threshold);
    }

    pub fn set_priority(&mut self, stream_id: StreamId, priority: u16) {
        let stream = self.streams.entry(stream_id).or_insert_with(|| {
            SendQueue::make_stream(
                stream_id,
                self.default_priority,
                self.default_low_buffered_amount_low_threshold,
                Rc::clone(&self.events),
            )
        });
        stream.priority = priority;
    }

    pub fn get_priority(&self, stream_id: StreamId) -> u16 {
        match self.streams.get(&stream_id) {
            Some(stream) => stream.priority,
            None => self.default_priority,
        }
    }

    pub fn get_handover_readiness(&self) -> HandoverReadiness {
        if self.total_buffered_amount() == 0 {
            HandoverReadiness::READY
        } else {
            HandoverReadiness::SEND_QUEUE_NOT_EMPTY
        }
    }

    pub(crate) fn add_to_handover_state(&self, state: &mut SocketHandoverState) {
        state.tx.streams = self
            .streams
            .iter()
            .map(|(stream_id, s)| HandoverOutgoingStream {
                id: stream_id.0,
                next_ssn: s.next_ssn.0,
                next_unordered_mid: s.next_unordered_mid.0,
                next_ordered_mid: s.next_ordered_mid.0,
                priority: s.priority,
            })
            .collect()
    }

    pub(crate) fn restore_from_state(&mut self, state: &SocketHandoverState) {
        state.tx.streams.iter().for_each(|s| {
            let stream_id = StreamId(s.id);
            self.streams.insert(
                stream_id,
                SendQueue::make_stream(
                    stream_id,
                    s.priority,
                    self.default_low_buffered_amount_low_threshold,
                    Rc::clone(&self.events),
                ),
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::PpId;
    use crate::events::Events;
    use crate::testing::event_helpers::expect_buffered_amount_low;
    use crate::testing::event_helpers::expect_no_event;
    use crate::testing::event_helpers::expect_on_lifecycle_end;
    use crate::testing::event_helpers::expect_on_lifecycle_message_expired;
    use crate::testing::event_helpers::expect_total_buffered_amount_low;
    use itertools::Itertools;

    const DEFAULT_PRIORITY: u16 = 256;
    const MTU: usize = 1280;
    const PPID: PpId = PpId(53);
    const START_TIME: SocketTime = SocketTime::zero();

    fn make_events() -> Rc<RefCell<Events>> {
        Rc::new(RefCell::new(Events::new()))
    }

    fn next_event(events: &Rc<RefCell<Events>>) -> Option<SocketEvent> {
        events.borrow_mut().next_event()
    }

    fn add(q: &mut SendQueue<'_>, sid: StreamId, ppid: PpId, payload: Vec<u8>) {
        q.add(START_TIME, Message::new(sid, ppid, payload), &SendOptions { ..Default::default() });
    }

    #[test]
    fn empty_buffer() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        assert_eq!(q.total_buffered_amount(), 0);
        assert!(q.produce(START_TIME, MTU).is_none());
    }

    #[test]
    fn add_and_get_single_chunk() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        add(&mut q, StreamId(1), PPID, vec![1, 2, 4, 5, 6]);
        assert!(q.total_buffered_amount() > 0);
        let chunk = q.produce(START_TIME, MTU).unwrap();
        assert!(chunk.data.is_beginning);
        assert!(chunk.data.is_end);
    }

    #[test]
    fn carve_out_beginning_middle_and_end() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        add(&mut q, StreamId(1), PPID, vec![0; 60]);

        let chunk_beg = q.produce(START_TIME, 20).unwrap();
        assert!(chunk_beg.data.is_beginning);
        assert!(!chunk_beg.data.is_end);

        let chunk_mid = q.produce(START_TIME, 20).unwrap();
        assert!(!chunk_mid.data.is_beginning);
        assert!(!chunk_mid.data.is_end);

        let chunk_end = q.produce(START_TIME, 20).unwrap();
        assert!(!chunk_end.data.is_beginning);
        assert!(chunk_end.data.is_end);

        assert!(q.produce(START_TIME, MTU).is_none());
    }

    #[test]
    fn get_chunks_from_two_messages() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        add(&mut q, StreamId(1), PpId(53), vec![0; 60]);
        add(&mut q, StreamId(3), PpId(54), vec![0; 60]);

        let chunk_one = q.produce(START_TIME, MTU).unwrap();
        assert_eq!(chunk_one.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk_one.data.ppid, PpId(53));
        assert!(chunk_one.data.is_beginning);
        assert!(chunk_one.data.is_end);

        let chunk_one = q.produce(START_TIME, MTU).unwrap();
        assert_eq!(chunk_one.data.stream_key, StreamKey::Ordered(StreamId(3)));
        assert_eq!(chunk_one.data.ppid, PpId(54));
        assert!(chunk_one.data.is_beginning);
        assert!(chunk_one.data.is_end);

        assert!(q.produce(START_TIME, MTU).is_none());
    }

    #[test]
    fn buffer_becomes_full_and_emptied() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        assert!(q.total_buffered_amount() < 1000);
        add(&mut q, StreamId(1), PpId(53), vec![0; 600]);
        assert!(q.total_buffered_amount() < 1000);

        add(&mut q, StreamId(3), PpId(53), vec![0; 600]);
        assert!(q.total_buffered_amount() >= 1000);

        // However, it's still possible to add messages. It's a soft limit, and it might be
        // necessary to forcefully add messages due to e.g. external fragmentation.

        add(&mut q, StreamId(5), PpId(54), vec![0; 600]);
        assert!(q.total_buffered_amount() >= 1000);

        let chunk_one = q.produce(START_TIME, 1000).unwrap();
        assert_eq!(chunk_one.data.stream_key, StreamKey::Ordered(StreamId(1)));

        let chunk_two = q.produce(START_TIME, 1000).unwrap();
        assert_eq!(chunk_two.data.stream_key, StreamKey::Ordered(StreamId(3)));

        assert!(q.total_buffered_amount() < 1000);

        let chunk_three = q.produce(START_TIME, 1000).unwrap();
        assert_eq!(chunk_three.data.stream_key, StreamKey::Ordered(StreamId(5)));
        assert_eq!(q.total_buffered_amount(), 00);
    }

    #[test]
    fn lifetime_discarded_messages_decrease_buffered_amount() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());

        let now = START_TIME;
        q.add(
            now,
            Message::new(StreamId(1), PpId(54), vec![0; 100]),
            &SendOptions {
                lifetime: Some(Duration::from_millis(1000)),
                lifecycle_id: LifecycleId::new(1),
                ..Default::default()
            },
        );
        assert_eq!(q.buffered_amount(StreamId(1)), 100);

        let chunk_three = q.produce(now, 20).unwrap();
        assert_eq!(chunk_three.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk_three.data.payload.len(), 20);
        assert_eq!(q.buffered_amount(StreamId(1)), 80);

        assert!(q.produce(now + Duration::from_millis(1001), MTU).is_none());
        assert_eq!(q.buffered_amount(StreamId(1)), 0);
    }

    #[test]
    fn defaults_to_ordered_send() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        add(&mut q, StreamId(1), PpId(53), vec![0; 20]);

        let chunk_one = q.produce(START_TIME, MTU).unwrap();
        assert_eq!(chunk_one.data.ppid, PpId(53));
        assert!(!chunk_one.data.stream_key.is_unordered());

        q.add(
            START_TIME,
            Message::new(StreamId(1), PpId(54), vec![0; 20]),
            &SendOptions { unordered: true, ..Default::default() },
        );

        let chunk_two = q.produce(START_TIME, MTU).unwrap();
        assert_eq!(chunk_two.data.ppid, PpId(54));
        assert!(chunk_two.data.stream_key.is_unordered());

        assert!(q.produce(START_TIME, MTU).is_none());
    }

    #[test]
    fn produce_with_lifetime_expiry() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        let mut now = START_TIME;

        // Default is no expiry
        q.add(
            now,
            Message::new(StreamId(1), PpId(50), vec![0; 20]),
            &SendOptions { ..Default::default() },
        );
        assert!(q.produce(now, 100).is_some());

        // Add and consume within lifetime
        q.add(
            now,
            Message::new(StreamId(1), PpId(50), vec![0; 20]),
            &SendOptions { lifetime: Some(Duration::from_secs(2)), ..Default::default() },
        );
        now = now + Duration::from_secs(2);
        assert!(q.produce(now, 100).is_some());

        // Add and consume just outside lifetime
        q.add(
            now,
            Message::new(StreamId(1), PpId(50), vec![0; 20]),
            &SendOptions { lifetime: Some(Duration::from_secs(2)), ..Default::default() },
        );
        now = now + Duration::from_millis(2001);
        assert!(q.produce(now, 100).is_none());

        // A long time after expiry.
        q.add(
            now,
            Message::new(StreamId(1), PpId(50), vec![0; 20]),
            &SendOptions { lifetime: Some(Duration::from_secs(2)), ..Default::default() },
        );
        now = now + Duration::from_secs(1000);
        assert!(q.produce(now, 100).is_none());

        // Expire one message, but produce the second that is not expired.
        q.add(
            now,
            Message::new(StreamId(1), PpId(50), vec![0; 20]),
            &SendOptions { lifetime: Some(Duration::from_secs(2)), ..Default::default() },
        );
        q.add(
            now,
            Message::new(StreamId(1), PpId(51), vec![0; 20]),
            &SendOptions { lifetime: Some(Duration::from_secs(4)), ..Default::default() },
        );
        now = now + Duration::from_millis(2001);
        assert_eq!(q.produce(now, 100).unwrap().data.ppid, PpId(51));
        assert!(q.produce(now, 100).is_none());
    }

    #[test]
    fn discard_partial_packets() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        add(&mut q, StreamId(1), PpId(50), vec![0; 120]);
        add(&mut q, StreamId(2), PpId(51), vec![0; 120]);

        let chunk1 = q.produce(START_TIME, 100).unwrap();
        assert!(!chunk1.data.is_end);
        assert_eq!(chunk1.data.stream_key, StreamKey::Ordered(StreamId(1)));
        q.discard(StreamId(1), chunk1.message_id);

        let chunk2 = q.produce(START_TIME, 100).unwrap();
        assert!(!chunk2.data.is_end);
        assert_eq!(chunk2.data.stream_key, StreamKey::Ordered(StreamId(2)));

        let chunk3 = q.produce(START_TIME, 100).unwrap();
        assert!(chunk3.data.is_end);
        assert_eq!(chunk3.data.stream_key, StreamKey::Ordered(StreamId(2)));

        // Calling it again shouldn't cause issues.
        q.discard(StreamId(1), chunk1.message_id);
        assert!(q.produce(START_TIME, 100).is_none());
    }

    #[test]
    fn prepare_reset_streams_discards_stream() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        add(&mut q, StreamId(1), PpId(53), vec![1, 2, 3]);
        add(&mut q, StreamId(2), PpId(53), vec![1, 2, 3, 4, 5]);
        assert_eq!(q.total_buffered_amount(), 8);

        q.prepare_reset_stream(StreamId(1));
        assert_eq!(q.total_buffered_amount(), 5);

        assert_eq!(q.get_streams_ready_to_reset(), vec![StreamId(1)]);
        q.commit_reset_streams();
        q.prepare_reset_stream(StreamId(2));
        assert_eq!(q.total_buffered_amount(), 0);
    }

    #[test]
    fn prepare_reset_streams_not_partial_packets() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        add(&mut q, StreamId(1), PpId(53), vec![0; 120]);
        add(&mut q, StreamId(1), PpId(53), vec![0; 120]);
        let chunk_one = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_one.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk_one.data.payload.len(), 50);

        assert_eq!(q.total_buffered_amount(), 2 * 120 - 50);

        q.prepare_reset_stream(StreamId(1));
        assert_eq!(q.total_buffered_amount(), 120 - 50);
    }

    #[test]
    fn enqueued_items_are_paused_during_stream_reset() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        q.prepare_reset_stream(StreamId(1));
        assert_eq!(q.total_buffered_amount(), 0);

        add(&mut q, StreamId(1), PpId(53), vec![0; 50]);
        assert_eq!(q.total_buffered_amount(), 50);

        assert!(q.produce(START_TIME, 50).is_none());
        assert!(q.has_streams_ready_to_be_reset());
        assert_eq!(q.get_streams_ready_to_reset(), vec![StreamId(1)]);

        q.commit_reset_streams();
        assert_eq!(q.total_buffered_amount(), 50);

        let chunk_one = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_one.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk_one.data.payload.len(), 50);

        assert_eq!(q.total_buffered_amount(), 0);
    }

    #[test]
    fn paused_streams_still_send_partial_messages_until_end() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());

        add(&mut q, StreamId(1), PpId(53), vec![0; 100]);
        add(&mut q, StreamId(1), PpId(53), vec![0; 100]);
        assert_eq!(q.total_buffered_amount(), 200);

        let chunk_one = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_one.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk_one.data.payload.len(), 50);
        assert_eq!(q.total_buffered_amount(), 150);

        // This will stop the second message from being sent.
        q.prepare_reset_stream(StreamId(1));
        assert_eq!(q.total_buffered_amount(), 50);

        // Add a new message, added after the stream was paused. It should not be sent.
        add(&mut q, StreamId(1), PpId(53), vec![0; 100]);
        assert_eq!(q.total_buffered_amount(), 150);

        // Should still produce fragments until end of message.
        let chunk_two = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_two.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk_two.data.payload.len(), 50);
        assert_eq!(q.total_buffered_amount(), 100);

        // But shouldn't produce any more messages as the stream is paused.
        assert!(q.produce(START_TIME, 50).is_none());
    }

    #[test]
    fn committing_resets_ssn() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());

        add(&mut q, StreamId(1), PpId(53), vec![0; 50]);
        add(&mut q, StreamId(1), PpId(53), vec![0; 50]);
        assert_eq!(q.total_buffered_amount(), 100);

        let chunk_one = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_one.data.ssn, Ssn(0));

        let chunk_two = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_two.data.ssn, Ssn(1));

        q.prepare_reset_stream(StreamId(1));
        add(&mut q, StreamId(1), PpId(53), vec![0; 50]);
        assert!(q.has_streams_ready_to_be_reset());
        assert_eq!(q.get_streams_ready_to_reset(), [StreamId(1)]);
        q.commit_reset_streams();

        let chunk_three = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_three.data.ssn, Ssn(0));
    }

    #[test]
    fn committing_does_not_reset_message_id() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());

        add(&mut q, StreamId(1), PpId(53), vec![0; 50]);
        add(&mut q, StreamId(1), PpId(53), vec![0; 50]);
        assert_eq!(q.total_buffered_amount(), 100);

        let chunk_one = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_one.message_id, OutgoingMessageId(0));

        let chunk_two = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_two.message_id, OutgoingMessageId(1));

        q.prepare_reset_stream(StreamId(1));
        add(&mut q, StreamId(1), PpId(53), vec![0; 50]);
        assert!(q.has_streams_ready_to_be_reset());
        assert_eq!(q.get_streams_ready_to_reset(), [StreamId(1)]);
        q.commit_reset_streams();

        let chunk_three = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_three.message_id, OutgoingMessageId(2));
    }

    #[test]
    fn committing_resets_ssn_for_paused_streams_only() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());

        add(&mut q, StreamId(1), PpId(53), vec![0; 50]);
        add(&mut q, StreamId(3), PpId(53), vec![0; 50]);
        assert_eq!(q.total_buffered_amount(), 100);

        let chunk_one = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_one.data.ssn, Ssn(0));
        let chunk_two = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_two.data.ssn, Ssn(0));

        q.prepare_reset_stream(StreamId(3));

        // Send two more messages - SID 3 will buffer, SID 1 will send.
        add(&mut q, StreamId(1), PpId(53), vec![0; 50]);
        add(&mut q, StreamId(3), PpId(53), vec![0; 50]);
        assert!(q.has_streams_ready_to_be_reset());
        assert_eq!(q.get_streams_ready_to_reset(), [StreamId(3)]);
        q.commit_reset_streams();

        let chunk_one = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_one.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk_one.data.ssn, Ssn(1));
        let chunk_two = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_two.data.stream_key, StreamKey::Ordered(StreamId(3)));
        assert_eq!(chunk_two.data.ssn, Ssn(0));
    }

    #[test]
    fn roll_back_resumes_ssn() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());

        add(&mut q, StreamId(1), PpId(53), vec![0; 50]);
        add(&mut q, StreamId(1), PpId(53), vec![0; 50]);
        assert_eq!(q.total_buffered_amount(), 100);

        let chunk_one = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_one.data.ssn, Ssn(0));
        let chunk_two = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_two.data.ssn, Ssn(1));

        q.prepare_reset_stream(StreamId(1));

        // Buffered
        add(&mut q, StreamId(1), PpId(53), vec![0; 50]);
        assert!(q.has_streams_ready_to_be_reset());
        assert_eq!(q.get_streams_ready_to_reset(), [StreamId(1)]);
        q.rollback_reset_streams();

        let chunk_one = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_one.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk_one.data.ssn, Ssn(2));
    }

    #[test]
    fn returns_fragments_for_one_message_before_moving_to_next() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        add(&mut q, StreamId(1), PpId(53), vec![0; 200]);
        add(&mut q, StreamId(2), PpId(53), vec![0; 200]);

        let chunk1 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk1.data.stream_key, StreamKey::Ordered(StreamId(1)));

        let chunk2 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk2.data.stream_key, StreamKey::Ordered(StreamId(1)));

        let chunk3 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk3.data.stream_key, StreamKey::Ordered(StreamId(2)));

        let chunk4 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk4.data.stream_key, StreamKey::Ordered(StreamId(2)));

        assert!(q.produce(START_TIME, MTU).is_none());
    }

    #[test]
    fn returns_also_small_fragments_before_moving_to_next() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        add(&mut q, StreamId(1), PpId(53), vec![0; 101]);
        add(&mut q, StreamId(2), PpId(53), vec![0; 101]);

        let chunk1 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk1.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk1.data.payload.len(), 100);

        let chunk2 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk2.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk2.data.payload.len(), 1);

        let chunk3 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk3.data.stream_key, StreamKey::Ordered(StreamId(2)));
        assert_eq!(chunk3.data.payload.len(), 100);

        let chunk4 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk4.data.stream_key, StreamKey::Ordered(StreamId(2)));
        assert_eq!(chunk4.data.payload.len(), 1);

        assert!(q.produce(START_TIME, MTU).is_none());
    }

    #[test]
    fn will_cycle_in_round_robin_fashion_between_streams() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        add(&mut q, StreamId(1), PpId(53), vec![0; 1]);
        add(&mut q, StreamId(1), PpId(53), vec![0; 2]);
        add(&mut q, StreamId(2), PpId(53), vec![0; 3]);
        add(&mut q, StreamId(2), PpId(53), vec![0; 4]);
        add(&mut q, StreamId(3), PpId(53), vec![0; 5]);
        add(&mut q, StreamId(3), PpId(53), vec![0; 6]);
        add(&mut q, StreamId(4), PpId(53), vec![0; 7]);
        add(&mut q, StreamId(4), PpId(53), vec![0; 8]);

        let chunk1 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk1.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk1.data.payload.len(), 1);

        let chunk2 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk2.data.stream_key, StreamKey::Ordered(StreamId(2)));
        assert_eq!(chunk2.data.payload.len(), 3);

        let chunk3 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk3.data.stream_key, StreamKey::Ordered(StreamId(3)));
        assert_eq!(chunk3.data.payload.len(), 5);

        let chunk4 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk4.data.stream_key, StreamKey::Ordered(StreamId(4)));
        assert_eq!(chunk4.data.payload.len(), 7);

        let chunk5 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk5.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk5.data.payload.len(), 2);

        let chunk6 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk6.data.stream_key, StreamKey::Ordered(StreamId(2)));
        assert_eq!(chunk6.data.payload.len(), 4);

        let chunk7 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk7.data.stream_key, StreamKey::Ordered(StreamId(3)));
        assert_eq!(chunk7.data.payload.len(), 6);

        let chunk8 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk8.data.stream_key, StreamKey::Ordered(StreamId(4)));
        assert_eq!(chunk8.data.payload.len(), 8);

        assert!(q.produce(START_TIME, MTU).is_none());
    }

    #[test]
    fn doesnt_trigger_on_buffered_amount_low_when_set_to_zero() {
        let events = make_events();
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;

        let mut q = SendQueue::new(MTU, &Options::default(), events_clone);
        q.set_buffered_amount_low_threshold(StreamId(1), 0);
        expect_no_event!(next_event(&events));
    }

    #[test]
    fn triggers_on_buffered_amount_at_zero_low_when_sent() {
        // Note: Default low threshold on streams is zero.
        let events = make_events();
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;

        let mut q = SendQueue::new(MTU, &Options::default(), events_clone);
        add(&mut q, StreamId(1), PPID, vec![0; 1]);
        assert_eq!(q.buffered_amount(StreamId(1)), 1);

        let chunk1 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk1.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk1.data.payload.len(), 1);

        let stream_id = expect_buffered_amount_low!(next_event(&events));
        assert_eq!(stream_id, StreamId(1));
        expect_no_event!(next_event(&events));
    }

    #[test]
    fn will_retrigger_on_buffered_amount_low_if_adding_more() {
        // Note: Default low threshold on streams is zero.
        let events = make_events();
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut q = SendQueue::new(MTU, &Options::default(), events_clone);

        add(&mut q, StreamId(1), PPID, vec![0; 1]);
        assert_eq!(q.buffered_amount(StreamId(1)), 1);
        let chunk1 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk1.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk1.data.payload.len(), 1);
        let stream_id = expect_buffered_amount_low!(next_event(&events));
        assert_eq!(stream_id, StreamId(1));

        add(&mut q, StreamId(1), PPID, vec![0; 1]);
        assert_eq!(q.buffered_amount(StreamId(1)), 1);
        let chunk1 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk1.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk1.data.payload.len(), 1);
        let stream_id = expect_buffered_amount_low!(next_event(&events));
        assert_eq!(stream_id, StreamId(1));

        expect_no_event!(next_event(&events));
    }

    #[test]
    fn only_triggers_when_transitioning_from_above_to_below_or_equal() {
        let events = make_events();
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;

        let mut q = SendQueue::new(MTU, &Options::default(), events_clone);
        q.set_buffered_amount_low_threshold(StreamId(1), 20);

        add(&mut q, StreamId(1), PPID, vec![0; 10]);
        assert_eq!(q.buffered_amount(StreamId(1)), 10);
        let chunk = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk.data.payload.len(), 10);
        expect_no_event!(next_event(&events));

        add(&mut q, StreamId(1), PPID, vec![0; 20]);
        assert_eq!(q.buffered_amount(StreamId(1)), 20);
        let chunk = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk.data.payload.len(), 20);
        expect_no_event!(next_event(&events));

        add(&mut q, StreamId(1), PPID, vec![0; 21]);
        assert_eq!(q.buffered_amount(StreamId(1)), 21);
        let chunk = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk.data.payload.len(), 21);
        assert_eq!(expect_buffered_amount_low!(next_event(&events)), StreamId(1));
    }

    #[test]
    fn will_trigger_on_buffered_amount_low_set_above_zero() {
        let events = make_events();
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;

        let mut q = SendQueue::new(MTU, &Options::default(), events_clone);
        q.set_buffered_amount_low_threshold(StreamId(1), 700);

        add(&mut q, StreamId(1), PPID, vec![0; 1000]);

        let chunk = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk.data.payload.len(), 100);
        assert_eq!(q.buffered_amount(StreamId(1)), 900);
        expect_no_event!(next_event(&events));

        let chunk = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk.data.payload.len(), 100);
        assert_eq!(q.buffered_amount(StreamId(1)), 800);
        expect_no_event!(next_event(&events));

        let chunk = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk.data.payload.len(), 100);
        assert_eq!(q.buffered_amount(StreamId(1)), 700);
        assert_eq!(expect_buffered_amount_low!(next_event(&events)), StreamId(1));

        // Doesn't trigger when reducing even further.
        let chunk = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk.data.payload.len(), 100);
        assert_eq!(q.buffered_amount(StreamId(1)), 600);
        expect_no_event!(next_event(&events));
    }

    #[test]
    fn will_retrigger_on_buffered_amount_low_set_above_zero() {
        let events = make_events();
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;

        let mut q = SendQueue::new(MTU, &Options::default(), events_clone);
        q.set_buffered_amount_low_threshold(StreamId(1), 700);

        add(&mut q, StreamId(1), PPID, vec![0; 1000]);

        let chunk = q.produce(START_TIME, 400).unwrap();
        assert_eq!(chunk.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk.data.payload.len(), 400);
        assert_eq!(q.buffered_amount(StreamId(1)), 600);
        assert_eq!(expect_buffered_amount_low!(next_event(&events)), StreamId(1));

        add(&mut q, StreamId(1), PPID, vec![0; 200]);
        assert_eq!(q.buffered_amount(StreamId(1)), 800);

        let chunk = q.produce(START_TIME, 200).unwrap();
        assert_eq!(chunk.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk.data.payload.len(), 200);
        assert_eq!(q.buffered_amount(StreamId(1)), 600);
        assert_eq!(expect_buffered_amount_low!(next_event(&events)), StreamId(1));
    }

    #[test]
    fn triggers_on_buffered_amount_low_on_threshold_changed() {
        let events = make_events();
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;

        let mut q = SendQueue::new(MTU, &Options::default(), events_clone);
        add(&mut q, StreamId(1), PPID, vec![0; 100]);

        // Modifying the threshold, still under buffered_amount, should not trigger.
        q.set_buffered_amount_low_threshold(StreamId(1), 50);
        q.set_buffered_amount_low_threshold(StreamId(1), 99);
        expect_no_event!(next_event(&events));

        // When the threshold reaches buffered_amount, it will trigger.
        q.set_buffered_amount_low_threshold(StreamId(1), 100);
        assert_eq!(expect_buffered_amount_low!(next_event(&events)), StreamId(1));

        // But not when it's set low again.
        q.set_buffered_amount_low_threshold(StreamId(1), 50);
        expect_no_event!(next_event(&events));

        // But it will trigger when it overshoots.
        q.set_buffered_amount_low_threshold(StreamId(1), 150);
        assert_eq!(expect_buffered_amount_low!(next_event(&events)), StreamId(1));

        // But not when it's set low again.
        q.set_buffered_amount_low_threshold(StreamId(1), 0);
        expect_no_event!(next_event(&events));
    }

    #[test]
    fn on_total_buffered_amount_low_does_not_trigger_on_buffer_filling_up() {
        let events = make_events();
        let options = Options { total_buffered_amount_low_threshold: 700, ..Options::default() };
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut q = SendQueue::new(MTU, &options, events_clone);
        add(&mut q, StreamId(1), PPID, vec![0; 699]);
        assert_eq!(q.buffered_amount(StreamId(1)), 699);

        // Will not trigger if going above but never below.
        add(&mut q, StreamId(1), PPID, vec![0; 2]);
        assert_eq!(q.buffered_amount(StreamId(1)), 701);
    }

    #[test]
    fn triggers_on_total_buffered_amount_low_when_crossing() {
        let events = make_events();
        let options = Options { total_buffered_amount_low_threshold: 700, ..Options::default() };
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut q = SendQueue::new(MTU, &options, events_clone);
        add(&mut q, StreamId(1), PPID, vec![0; 700]);
        assert_eq!(q.buffered_amount(StreamId(1)), 700);
        expect_no_event!(next_event(&events));

        // Reaches it.
        add(&mut q, StreamId(1), PPID, vec![0; 1]);
        expect_no_event!(next_event(&events));

        // Drain it a bit - will trigger.
        let chunk = q.produce(START_TIME, 200).unwrap();
        assert_eq!(chunk.data.stream_key, StreamKey::Ordered(StreamId(1)));
        expect_total_buffered_amount_low!(next_event(&events));
    }

    #[test]
    fn will_stay_in_a_stream_as_long_as_that_message_is_sending() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        add(&mut q, StreamId(5), PpId(53), vec![0; 1]);

        let chunk1 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk1.data.stream_key, StreamKey::Ordered(StreamId(5)));
        assert_eq!(chunk1.data.payload.len(), 1);

        // Next, it should pick a different stream.
        add(&mut q, StreamId(1), PpId(53), vec![0; 200]);

        let chunk2 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk2.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk2.data.payload.len(), 100);

        // It should still stay on the Stream1 now, even if might be tempted to switch to this
        // stream, as it's the stream following 5.
        add(&mut q, StreamId(6), PpId(53), vec![0; 1]);

        let chunk3 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk3.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk3.data.payload.len(), 100);

        // After stream id 1 is complete, it's time to do stream 6.
        let chunk4 = q.produce(START_TIME, 100).unwrap();
        assert_eq!(chunk4.data.stream_key, StreamKey::Ordered(StreamId(6)));
        assert_eq!(chunk4.data.payload.len(), 1);

        assert!(q.produce(START_TIME, MTU).is_none());
    }

    #[test]
    fn streams_have_initial_priority() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        assert_eq!(q.get_priority(StreamId(1)), DEFAULT_PRIORITY);

        add(&mut q, StreamId(2), PpId(53), vec![0; 1]);
        assert_eq!(q.get_priority(StreamId(2)), DEFAULT_PRIORITY);
    }

    #[test]
    fn can_change_stream_priority() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());

        q.set_priority(StreamId(1), 42);
        assert_eq!(q.get_priority(StreamId(1)), 42);

        add(&mut q, StreamId(2), PpId(53), vec![0; 1]);
        q.set_priority(StreamId(2), 42);
        assert_eq!(q.get_priority(StreamId(2)), 42);
    }

    fn handover_queue(q: SendQueue<'_>, events: Rc<RefCell<dyn EventSink>>) -> SendQueue<'_> {
        assert!(q.get_handover_readiness().is_ready());

        let mut state = SocketHandoverState::default();
        q.add_to_handover_state(&mut state);

        let mut q = SendQueue::new(MTU, &Options::default(), events);
        q.restore_from_state(&state);
        q
    }

    #[test]
    fn will_handover_priority() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());

        q.set_priority(StreamId(1), 42);
        add(&mut q, StreamId(2), PpId(53), vec![0; 1]);
        q.set_priority(StreamId(2), 34);

        let chunk = q.produce(START_TIME, MTU).unwrap();
        assert!(chunk.data.is_beginning);
        assert!(chunk.data.is_end);

        let q = handover_queue(q, make_events());
        assert_eq!(q.get_priority(StreamId(1)), 42);
        assert_eq!(q.get_priority(StreamId(2)), 34);
    }

    #[test]
    fn is_not_handover_ready_with_pending_data() {
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        assert!(q.get_handover_readiness().is_ready());

        add(&mut q, StreamId(2), PpId(53), vec![0; 1]);
        assert_eq!(q.get_handover_readiness(), HandoverReadiness::SEND_QUEUE_NOT_EMPTY);

        q.produce(START_TIME, MTU);
        assert!(q.get_handover_readiness().is_ready());
    }

    #[test]
    fn will_send_messages_by_prio() {
        let now = START_TIME;
        let mut q = SendQueue::new(MTU, &Options::default(), make_events());
        q.enable_message_interleaving(true);

        q.set_priority(StreamId(1), 10);
        q.set_priority(StreamId(2), 20);
        q.set_priority(StreamId(3), 30);

        add(&mut q, StreamId(1), PpId(53), vec![0; 40]);
        add(&mut q, StreamId(2), PpId(53), vec![0; 20]);
        add(&mut q, StreamId(3), PpId(53), vec![0; 10]);

        let streams =
            (0..7).map(|_| q.produce(now, 10).unwrap().data.stream_key.id().0).collect_vec();
        assert!(q.produce(now, 100).is_none());

        assert_eq!(streams, &[3, 2, 2, 1, 1, 1, 1]);
    }

    #[test]
    fn will_send_lifecycle_expire_when_expired_in_send_queue() {
        let events = make_events();
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;

        let mut q = SendQueue::new(MTU, &Options::default(), events_clone);

        let now = START_TIME;
        q.add(
            now,
            Message::new(StreamId(1), PpId(54), vec![0; 20]),
            &SendOptions {
                lifetime: Some(Duration::from_millis(1000)),
                lifecycle_id: LifecycleId::new(1),
                ..Default::default()
            },
        );

        expect_no_event!(next_event(&events));
        assert!(q.produce(now + Duration::from_millis(1001), MTU).is_none());
        assert_eq!(expect_buffered_amount_low!(next_event(&events)), StreamId(1));
        assert_eq!(expect_on_lifecycle_message_expired!(next_event(&events)), LifecycleId::from(1));
        assert_eq!(expect_on_lifecycle_end!(next_event(&events)), LifecycleId::from(1));
        expect_no_event!(next_event(&events));
    }

    #[test]
    fn will_send_lifecycle_expire_when_discarding_during_pause() {
        let events = make_events();
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;

        let mut q = SendQueue::new(MTU, &Options::default(), events_clone);

        let now = START_TIME;
        q.add(
            now,
            Message::new(StreamId(1), PPID, vec![0; 120]),
            &SendOptions { lifecycle_id: LifecycleId::new(1), ..Default::default() },
        );
        q.add(
            now,
            Message::new(StreamId(1), PPID, vec![0; 120]),
            &SendOptions { lifecycle_id: LifecycleId::new(2), ..Default::default() },
        );

        let chunk_one = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_one.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(q.total_buffered_amount(), 240 - 50);
        expect_no_event!(next_event(&events));

        q.prepare_reset_stream(StreamId(1));

        assert_eq!(q.total_buffered_amount(), 120 - 50);
        assert_eq!(expect_on_lifecycle_message_expired!(next_event(&events)), LifecycleId::from(2));
        assert_eq!(expect_on_lifecycle_end!(next_event(&events)), LifecycleId::from(2));
        expect_no_event!(next_event(&events));
    }

    #[test]
    fn will_send_lifecycle_expire_when_discarding_explicitly() {
        let events = make_events();
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;

        let mut q = SendQueue::new(MTU, &Options::default(), events_clone);

        let now = START_TIME;
        q.add(
            now,
            Message::new(StreamId(1), PPID, vec![0; 120]),
            &SendOptions { lifecycle_id: LifecycleId::new(1), ..Default::default() },
        );

        let chunk_one = q.produce(START_TIME, 50).unwrap();
        assert_eq!(chunk_one.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(q.total_buffered_amount(), 120 - 50);
        expect_no_event!(next_event(&events));

        q.discard(StreamId(1), chunk_one.message_id);
        assert_eq!(q.total_buffered_amount(), 0);
        assert_eq!(expect_buffered_amount_low!(next_event(&events)), StreamId(1));
        assert_eq!(expect_on_lifecycle_message_expired!(next_event(&events)), LifecycleId::from(1));
        assert_eq!(expect_on_lifecycle_end!(next_event(&events)), LifecycleId::from(1));
        expect_no_event!(next_event(&events));
    }
}
