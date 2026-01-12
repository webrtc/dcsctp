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

use crate::api::handover::HandoverReadiness;
use crate::api::handover::SocketHandoverState;
use std::fmt;
use std::num::NonZeroU64;
use std::ops::Add;
use std::ops::Sub;
use std::time::Duration;

pub mod handover;

pub use crate::socket::Socket;

/// Represents a point in time relative to the creation of the socket.
///
/// This is an absolute timestamp within the "Socket Epoch".
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SocketTime(Duration);

impl SocketTime {
    /// The moment the socket was created (t=0).
    pub const fn zero() -> SocketTime {
        SocketTime(Duration::ZERO)
    }
    pub const fn infinite_future() -> SocketTime {
        SocketTime(Duration::MAX)
    }
}

impl Add<Duration> for SocketTime {
    type Output = SocketTime;
    fn add(self, rhs: Duration) -> SocketTime {
        SocketTime(self.0 + rhs)
    }
}

impl Sub<Duration> for SocketTime {
    type Output = SocketTime;
    fn sub(self, rhs: Duration) -> SocketTime {
        SocketTime(self.0 - rhs)
    }
}

impl Sub<SocketTime> for SocketTime {
    type Output = Duration;
    fn sub(self, rhs: SocketTime) -> Duration {
        self.0 - rhs.0
    }
}

impl From<Duration> for SocketTime {
    fn from(value: Duration) -> Self {
        SocketTime(value)
    }
}

impl From<SocketTime> for Duration {
    fn from(value: SocketTime) -> Self {
        value.0
    }
}

/// An identifier that can be set on sent messages, and picked by the sending client. If set,
/// lifecycle events will be generated, and eventually [`SocketEvent::OnLifecycleEnd`] will be
/// generated to indicate that the lifecycle isn't tracked any longer. The value zero (0) is not a
/// valid lifecycle identifier, and will be interpreted as not having it set.
#[derive(Clone)]
pub struct LifecycleId(NonZeroU64);

impl PartialEq for LifecycleId {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for LifecycleId {}

impl fmt::Debug for LifecycleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for LifecycleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl LifecycleId {
    /// Creates a new `LifecycleId`.
    ///
    /// Returns `None` if the value is zero, as zero is not a valid lifecycle identifier.
    pub fn new(n: u64) -> Option<LifecycleId> {
        NonZeroU64::new(n).map(LifecycleId)
    }

    /// Creates a new `LifecycleId` from a non-zero value.
    ///
    /// # Panics
    ///
    /// Panics if `n` is zero.
    pub fn from(n: u64) -> LifecycleId {
        debug_assert!(n != 0);
        LifecycleId(NonZeroU64::new(n).unwrap())
    }

    /// Returns the underlying value.
    pub fn value(&self) -> u64 {
        self.0.into()
    }
}

/// Stream Identifier
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StreamId(pub u16);

impl fmt::Debug for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Payload Protocol Identifier (PPID)
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct PpId(pub u32);

impl fmt::Debug for PpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl fmt::Display for PpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Send options for sending messages.
#[derive(Default)]
pub struct SendOptions {
    /// If the message should be sent with unordered message delivery.
    pub unordered: bool,

    /// If set, will discard messages that haven't been correctly sent and received before the
    /// lifetime has expired. This is only available if the peer supports Partial Reliability
    /// Extension (RFC 3758).
    pub lifetime: Option<Duration>,

    /// If set, limits the number of retransmissions. This is only available if the peer supports
    /// Partial Reliability Extension (RFC 3758).
    pub max_retransmissions: Option<u16>,

    /// If set, will generate lifecycle events for this message. See e.g.
    /// [`SocketEvent::OnLifecycleMessageFullySent`]. This value is decided by the client and the
    /// library will provide it to all lifecycle events.
    pub lifecycle_id: Option<LifecycleId>,
}

/// An SCTP message is a group of bytes sent and received as a whole on a specified stream
/// identifier (`stream_id`), and with a payload protocol identifier (`ppid`).
#[derive(Debug)]
pub struct Message {
    /// The stream identifier to which the message is sent.
    pub stream_id: StreamId,

    /// The payload protocol identifier (ppid) associated with the message.
    pub ppid: PpId,

    /// The payload of the message.
    pub payload: Vec<u8>,
}

impl Message {
    /// Creates a new `Message`.
    pub fn new(stream_id: StreamId, ppid: PpId, payload: Vec<u8>) -> Self {
        Message { stream_id, ppid, payload }
    }
}

/// The alternate error detection method to use when zero-checksum is enabled.
/// See <https://datatracker.ietf.org/doc/html/rfc9653.html>.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZeroChecksumAlternateErrorDetectionMethod(pub u32);

/// No alternate error detection method. This is the default.
pub const ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE:
    ZeroChecksumAlternateErrorDetectionMethod = ZeroChecksumAlternateErrorDetectionMethod(0);

/// Use the lower-layer DTLS protocol as the alternate error detection method.
pub const ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_LOWER_LAYER_DTLS:
    ZeroChecksumAlternateErrorDetectionMethod = ZeroChecksumAlternateErrorDetectionMethod(1);

/// Known SCTP implementations.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SctpImplementation {
    /// There is not enough information to determine any SCTP implementation.
    Unknown,

    /// This Rust implementation of dcSCTP.
    DcsctpRs,

    /// C++ implementation of dcSCTP, see
    /// <https://webrtc.googlesource.com/src/+/refs/heads/main/net/dcsctp>.
    DcsctpCc,

    /// Userland SCTP stack, see <https://github.com/sctplab/usrsctp>.
    UsrSctp,

    /// Any other implementation.
    Other,
}

/// Represents the category of an error that has occurred.
///
/// This enum is used in [`SocketEvent::OnError`] and [`SocketEvent::OnAborted`] to provide
/// information about the nature of the error.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ErrorKind {
    /// Indicates that no error has occurred. This will never be the case when
    /// [`SocketEvent::OnError`] or [`SocketEvent::OnAborted`] is called.
    NoError,

    /// The operation could not be completed because of too many retransmissions or timeouts.
    /// This typically indicates a loss of connectivity to the peer.
    TooManyRetries,

    /// A command was received that is only possible to execute when the socket is connected,
    /// but the socket is not in a `Connected` state.
    NotConnected,

    /// Parsing of an incoming SCTP packet or its parameters failed. This can happen if the
    /// packet is malformed.
    ParseFailed,

    /// SCTP chunks were received in an unexpected sequence, which may indicate a
    /// synchronization mismatch between the peers.
    WrongSequence,

    /// The peer has reported an issue by sending an `ERROR` or `ABORT` chunk. The specific
    /// cause is included in the string provided with the event.
    PeerReported,

    /// The peer has performed a protocol violation, such as sending an invalid chunk or
    /// parameter that violates the SCTP specification.
    ProtocolViolation,

    /// The socket's internal send or receive buffers have been exhausted, and no more data
    /// can be queued. This can happen if data is being produced faster than it can be sent
    /// or processed.
    ResourceExhaustion,

    /// The client application has attempted to perform an invalid or unsupported operation on
    /// the socket.
    UnsupportedOperation,
}

/// User configurable options.
#[derive(Clone)]
pub struct Options {
    /// The local port for which the socket is supposed to be bound to. Incoming packets will be
    /// verified that they are sent to this port number and all outgoing packets will have this
    /// port number as source port.
    pub local_port: u16,

    /// The remote port to send packets to. All outgoing packets will have this port number as
    /// destination port.
    pub remote_port: u16,

    /// The announced maximum number of incoming streams. Note that this value is constant and
    /// can't be currently increased in run-time as "Add Incoming Streams Request" in RFC 6525
    /// isn't supported.
    ///
    /// The socket implementation doesn't have any per-stream fixed costs, which is why the default
    /// value is set to be the maximum value.
    pub announced_maximum_incoming_streams: u16,

    /// The announced maximum number of outgoing streams. Note that this value is constant and
    /// can't be currently increased in run-time as "Add Outgoing Streams Request" in RFC 6525
    /// isn't supported.
    ///
    /// The socket implementation doesn't have any per-stream fixed costs, which is why the default
    /// value is set to be the maximum value.
    pub announced_maximum_outgoing_streams: u16,

    /// Maximum SCTP packet size. The library will limit the size of generated packets to be less
    /// than or equal to this number. This does not include any overhead from DTLS, TURN, UDP or IP
    /// headers.
    pub mtu: usize,

    /// The largest allowed message payload to be sent. Messages will be rejected if their payload
    /// is larger than this value. Note that this doesn't affect incoming messages, which may
    /// larger than this value (but smaller than [`Self::max_receiver_window_buffer_size`]).
    pub max_message_size: usize,

    /// The default stream priority. It can be overridden by [`DcSctpSocket::set_stream_priority`].
    /// The default value was selected to be compatible with
    /// <https://www.w3.org/TR/webrtc-priority/>, sections 4.2--4.3.
    pub default_stream_priority: u16,

    /// Maximum received window buffer size. This should be a bit larger than the largest sized
    /// message you want to be able to receive. This essentially limits the memory usage on the
    /// receive side. Note that memory is allocated dynamically, and this represents the maximum
    /// amount of buffered data. The actual memory usage of the library will be smaller in normal
    /// operation, and will be larger than this due to other allocations and overhead if the buffer
    /// is fully utilized.
    pub max_receiver_window_buffer_size: usize,

    /// Send queue total size limit. It will not be possible to queue more data if the queue size
    /// is larger than this number.
    pub max_send_buffer_size: usize,

    /// Per stream send queue size limit. Similar to [`Options::max_send_buffer_size`], but
    /// limiting the size of individual streams.
    pub per_stream_send_queue_limit: usize,

    /// A threshold that, when the amount of data in the send buffer goes below this value, will
    /// trigger [`SocketEvent::OnTotalBufferedAmountLow`].
    pub total_buffered_amount_low_threshold: usize,

    /// The default per-stream buffered_amount_low threshold. In WebRTC it is initially zero, see
    /// <https://w3c.github.io/webrtc-pc/#dom-rtcdatachannel-bufferedamountlowthreshold>.
    pub default_stream_buffered_amount_low_threshold: usize,

    /// Max allowed RTT value. When the RTT is measured and it's found to be larger than this
    /// value, it will be discarded and not used for e.g. any RTO calculation. The default
    /// value is an extreme maximum but can be adapted to better match the environment.
    pub rtt_max: Duration,

    /// Initial RTO value.
    pub rto_initial: Duration,

    /// Maximum RTO value.
    pub rto_max: Duration,

    /// Minimum RTO value. This must be larger than an expected peer delayed ack timeout.
    pub rto_min: Duration,

    /// T1-init timeout.
    pub t1_init_timeout: Duration,

    /// T1-cookie timeout.
    pub t1_cookie_timeout: Duration,

    /// T2-shutdown timeout.
    pub t2_shutdown_timeout: Duration,

    /// For t1-init, t1-cookie, t2-shutdown, t3-rtx, this value, if set, will be the upper bound on
    /// how large the exponentially backed off timeout can become. The lower the duration, the
    /// faster the connection can recover on transient network issues. Setting this value may
    /// require changing [`Self::max_retransmissions`] and [`Self::max_init_retransmits`] to ensure
    /// that the connection is not closed too quickly.
    pub max_timer_backoff_duration: Option<Duration>,

    /// Heartbeat interval (on idle connections only). Set to zero to disable.
    pub heartbeat_interval: Duration,

    /// The maximum time when a SACK will be sent from the arrival of an unacknowledged packet.
    /// Whatever is smallest of RTO/2 and this will be used.
    pub delayed_ack_max_timeout: Duration,

    /// The minimum limit for the measured RTT variance.
    ///
    /// Setting this below the expected delayed ack timeout (+ margin) of the peer might result in
    /// unnecessary retransmissions, as the maximum time it takes to ACK a DATA chunk is typically
    /// RTT + ATO (delayed ack timeout), and when the SCTP channel is quite idle, and heartbeats
    /// dominate the source of RTT measurement, the RTO would converge with the smoothed RTT
    /// (SRTT). The default ATO is 200 ms in usrsctp, and a 20 ms (10 %) margin would include
    /// the processing time of received packets and the clock granularity when setting the
    /// delayed ack timer on the peer.
    ///
    /// This is described for TCP in <https://datatracker.ietf.org/doc/html/rfc6298#section-4>.
    pub min_rtt_variance: Duration,

    /// The initial congestion window size, in number of MTUs. See
    /// <https://datatracker.ietf.org/doc/html/rfc9260#section-7.2.1> which defaults at ~3 and
    /// <https://research.google/pubs/pub36640/> which argues for at least ten segments.
    pub cwnd_mtus_initial: usize,

    /// The minimum congestion window size, in number of MTUs, upon detection of packet loss by
    /// SACK. Note that if the retransmission timer expires, the congestion window will be as small
    /// as one MTU. See <https://datatracker.ietf.org/doc/html/rfc9260#section-7.2.3>.
    pub cwnd_mtus_min: usize,

    /// When the congestion window is at or above this number of MTUs, the congestion control
    /// algorithm will avoid filling the congestion window fully, if that results in fragmenting
    /// large messages into quite small packets. When the congestion window is smaller than this
    /// option, it will aim to fill the congestion window as much as it can, even if it results in
    /// creating small fragmented packets.
    pub avoid_fragmentation_cwnd_mtus: usize,

    /// The number of packets that may be sent at once. This is limited to avoid bursts that too
    /// quickly fill the send buffer. Typically in a a socket in its "slow start" phase (when it
    /// sends as much as it can), it will send up to three packets for every SACK received, so the
    /// default limit is set just above that, and then mostly applicable for (but not limited to)
    /// fast retransmission scenarios.
    pub max_burst: i32,

    /// Maximum Data Retransmit Attempts (per DATA chunk). Set to None for no limit.
    pub max_retransmissions: Option<u32>,

    /// Corresponds to `Max.Init.Retransmits` from
    /// <https://datatracker.ietf.org/doc/html/rfc9260#section-16-2.20.1>. Set to `None` for no
    /// limit.
    pub max_init_retransmits: Option<u32>,

    /// RFC 3758 Partial Reliability Extension
    pub enable_partial_reliability: bool,

    /// RFC 8260 Stream Schedulers and User Message Interleaving
    pub enable_message_interleaving: bool,

    /// If RTO should be added to heartbeat_interval
    pub heartbeat_interval_include_rtt: bool,

    /// RFC 9653 Zero Checksum
    ///
    /// To have this enabled, both peers must be configured to use the same explicit alternate
    /// error detection method; the method cannot be none.
    pub zero_checksum_alternate_error_detection_method: ZeroChecksumAlternateErrorDetectionMethod,

    /// Disables SCTP packet CRC-32 verification. Must only be used by tests.
    pub disable_checksum_verification: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            local_port: 5000,
            remote_port: 5000,
            announced_maximum_incoming_streams: u16::MAX,
            announced_maximum_outgoing_streams: u16::MAX,

            // A safe default SCTP packet size. It is derived from the minimum guaranteed
            // MTU for IPv6 (1280 bytes), which may not support fragmentation, by subtracting
            // conservative estimates for headers and overhead.
            //
            // Calculation:
            //   1280 (IPv6 MTU)
            //    -40 (IPv6 header)
            //     -8 (UDP header)
            //    -24 (GCM AEAD overhead)
            //    -13 (DTLS record header)
            //     -4 (TURN ChannelData header)
            //   = 1191 bytes
            mtu: 1191,

            max_message_size: 256 * 1024,
            default_stream_priority: 256,
            max_receiver_window_buffer_size: 5 * 1024 * 1024,
            max_send_buffer_size: 2_000_000,
            per_stream_send_queue_limit: 2_000_000,
            total_buffered_amount_low_threshold: 1_800_000,
            default_stream_buffered_amount_low_threshold: 0,
            rtt_max: Duration::from_secs(60),
            rto_initial: Duration::from_millis(500),
            rto_max: Duration::from_secs(60),
            rto_min: Duration::from_millis(400),
            t1_init_timeout: Duration::from_secs(1),
            t1_cookie_timeout: Duration::from_secs(1),
            t2_shutdown_timeout: Duration::from_secs(1),
            max_timer_backoff_duration: None,
            heartbeat_interval: Duration::from_secs(30),
            delayed_ack_max_timeout: Duration::from_millis(200),
            min_rtt_variance: Duration::from_millis(220),
            cwnd_mtus_initial: 10,
            cwnd_mtus_min: 4,
            avoid_fragmentation_cwnd_mtus: 6,
            max_burst: 4,
            max_retransmissions: Some(10),
            max_init_retransmits: Some(8),
            enable_partial_reliability: true,
            enable_message_interleaving: false,
            heartbeat_interval_include_rtt: true,
            disable_checksum_verification: false,
            zero_checksum_alternate_error_detection_method:
                ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE,
        }
    }
}

/// Application level events generated by the socket.
#[derive(Debug)]
pub enum SocketEvent {
    /// Generated when the library wants a datagram packet to be sent.
    SendPacket(Vec<u8>),

    /// Generated when calling [`DcSctpSocket::connect`] succeeds, but also for incoming successful
    /// connection attempts.
    OnConnected(),

    /// Generated when the socket is closed in a controlled way. No other event will be generated
    /// after this event, unless reconnecting.
    OnClosed(),

    /// On connection restarted (by peer). This is just a notification, and the association is
    /// expected to work fine after this call, but there could have been packet loss as a result of
    /// restarting the association.
    OnConnectionRestarted(),

    /// Generated when the socket has aborted - either as decided by this socket due to e.g. too
    /// many retransmission attempts, or by the peer when receiving an ABORT command. No other
    /// events will be generated after this event, unless reconnecting.
    OnAborted(ErrorKind, String),

    /// Generated when a non-fatal error is reported by either this library or from the other peer
    /// (by sending an ERROR command). These should be logged, but no other action need to be taken
    /// as the association is still viable.
    OnError(ErrorKind, String),

    /// Generated when the amount of data buffered to be sent falls to or below the threshold set
    /// when calling [`DcSctpSocket::set_buffered_amount_low_threshold`].
    OnBufferedAmountLow(StreamId),

    /// Generated when the total amount of data buffered (in the entire send buffer, for all
    /// streams) falls to or below the threshold specified in
    /// [`Options::total_buffered_amount_low_threshold`].
    OnTotalBufferedAmountLow(),

    /// Indicates that a stream reset request has failed.
    OnStreamsResetFailed(Vec<StreamId>),

    /// Indicates that a stream reset request has been performed.
    OnStreamsResetPerformed(Vec<StreamId>),

    /// When a peer has reset some of its outgoing streams, this will be called. An empty list
    /// indicates that all streams have been reset.
    OnIncomingStreamReset(Vec<StreamId>),

    /// Emitted when a message has been fully sent, meaning that the last fragment has been
    /// produced from the send queue and sent on the network. Note that this will trigger at
    /// most once per message even if the message was retransmitted due to packet loss.
    ///
    /// # Lifecycle events
    ///
    /// If a [`SendOptions::lifecycle_id`] is provided, lifecycle events will be generated as the
    /// message is processed by the library.
    ///
    /// The possible transitions are shown in the graph below:
    ///
    /// ```txt
    ///      DcSctpSocket::Send ───────────────────────────────────────────────────────┐
    ///              │                                                                 │
    ///              │                                                                 │
    ///              v                                                                 v
    /// OnLifecycleMessageFullySent ──> OnLifecycleMessageMaybeExpired     OnLifecycleMessageExpired
    ///              │                                │                                │
    ///              │                                │                                │
    ///              v                                v                                │
    /// OnLifeCycleMessageDelivered ──────────> OnLifecycleEnd <───────────────────────┘
    /// ```
    OnLifecycleMessageFullySent(LifecycleId),

    /// Emitted when it's uncertain whether the message was delivered or expired.
    ///
    /// See [`Self::OnLifecycleMessageFullySent`] for possible transitions to and from this event.
    OnLifecycleMessageMaybeExpired(LifecycleId),

    /// Emitted when a message is expired, for example, if not all fragments has been sent within a
    /// certain timeframe.
    ///
    /// See [`Self::OnLifecycleMessageFullySent`] for possible transitions to and from this event.
    OnLifecycleMessageExpired(LifecycleId),

    /// Emitted when a non-expired message has been acknowledged by the peer as delivered.
    ///
    /// Note that this will trigger only when the peer moves its cumulative TSN ack beyond this
    /// message, and will not fire for messages acked using gap-ack-blocks as those are renegeable.
    /// This means that this may fire a bit later than the message was actually first "acked" by
    /// the peer, as - according to the protocol - those acks may be un-acked later by the
    /// peer.
    ///
    /// See [`Self::OnLifecycleMessageFullySent`] for possible transitions to and from this event.
    OnLifecycleMessageDelivered(LifecycleId),

    /// Emitted when a lifecycle event has reached its end. It will be called when processing of a
    /// message is complete, no matter how it completed. It will be called after all other
    /// lifecycle events, if any.
    ///
    /// Note that it's possible that this event is generated without any other lifecycle events
    /// having been generated in case of errors, such as attempting to send an empty message or
    /// failing to enqueue a message if the send queue is full.
    ///
    /// NOTE: When the socket is dropped, there will be no [`Self::OnLifecycleEnd`] events sent
    /// for messages that were enqueued. But as long as the socket is alive,
    /// [`Self::OnLifecycleEnd`] events are guaranteed to be sent as messages are either expired or
    /// successfully acknowledged.
    ///
    /// See [`Self::OnLifecycleMessageFullySent`] for possible transitions to this event.
    OnLifecycleEnd(LifecycleId),
}

/// The socket/association state
#[derive(Debug, PartialEq)]
pub enum SocketState {
    /// The socket is closed.
    Closed,

    /// The socket has initiated a connection, which is not yet established. Note that for incoming
    /// connections and for reconnections when the socket is already connected, the socket will not
    /// transition to this state.
    Connecting,

    /// The socket is connected, and the connection is established.
    Connected,

    /// The socket is shutting down, and the connection is not yet closed.
    ShuttingDown,
}

/// The result of a `send` operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendStatus {
    /// The message was enqueued successfully. As sending the message is done asynchronously, this
    /// is no guarantee that the message has been actually sent.
    Success,

    /// The message was rejected as the payload was empty (which is not allowed in SCTP).
    ErrorMessageEmpty,

    /// The message was rejected as the payload was larger than what has been set as
    /// [`Options::max_message_size`].
    ErrorMessageTooLarge,

    /// The message could not be enqueued as the socket is out of resources. This mainly indicates
    /// that the send queue is full.
    ErrorResourceExhaustion,

    /// The message could not be sent as the socket is shutting down.
    ErrorShuttingDown,
}

/// The result of a `reset_streams` operation.
#[derive(Debug, PartialEq)]
pub enum ResetStreamsStatus {
    /// If the connection is not yet established, this will be returned.
    NotConnected,

    /// Indicates that ResetStreams operation has been successfully initiated.
    Performed,

    /// Indicates that ResetStreams has failed as it's not supported by the peer.
    NotSupported,
}

/// Tracked metrics, which is the return value of GetMetrics. Optional members will be unset when
/// they are not yet known.
pub struct Metrics {
    /// Number of packets sent.
    pub tx_packets_count: usize,

    /// Number of messages requested to be sent.
    pub tx_messages_count: usize,

    /// Number of packets retransmitted. Since SCTP packets can contain both retransmitted DATA
    /// chunks and DATA chunks that are transmitted for the first time, this represents an upper
    /// bound as it's incremented every time a packet contains a retransmitted DATA chunk.
    pub rtx_packets_count: usize,

    /// Total number of bytes retransmitted. This includes the payload and DATA/I-DATA headers, but
    /// not SCTP packet headers.
    pub rtx_bytes_count: u64,

    /// The current congestion window (cwnd) in bytes, corresponding to spinfo_cwnd defined in RFC
    /// 6458.
    pub cwnd_bytes: usize,

    /// Smoothed round trip time, corresponding to spinfo_srtt defined in RFC 6458.
    pub srtt: Duration,

    /// Number of data items in the retransmission queue that haven’t been acked/nacked yet and are
    /// in-flight. Corresponding to sstat_unackdata defined in RFC 6458. This may be an
    /// approximation when there are messages in the send queue that haven't been
    /// fragmented/packetized yet.
    pub unack_data_count: usize,

    /// Number of packets received.
    pub rx_packets_count: usize,

    /// Number of messages received.
    pub rx_messages_count: usize,

    /// The peer’s last announced receiver window size, corresponding to sstat_rwnd defined in RFC
    /// 6458.
    pub peer_rwnd_bytes: u32,

    /// Returns the detected SCTP implementation of the peer. As this is not explicitly signalled
    /// during the connection establishment, heuristics is used to analyze e.g. the state cookie in
    /// the INIT-ACK chunk.
    pub peer_implementation: SctpImplementation,

    /// Indicates if RFC 8260 User Message Interleaving has been negotiated by both peers.
    pub uses_message_interleaving: bool,

    /// Indicates if RFC 9653 zero checksum has been negotiated by both peers.
    pub uses_zero_checksum: bool,

    /// The number of negotiated incoming streams, which is configured locally as
    /// [`Options::announced_maximum_incoming_streams`] and will be signaled by the peer during
    /// connection.
    pub negotiated_maximum_incoming_streams: u16,

    /// Similar to [`Self::negotiated_maximum_incoming_streams`], but for outgoing streams.
    pub negotiated_maximum_outgoing_streams: u16,
}

/// The dcSCTP Socket implementation implements the following interface.
pub trait DcSctpSocket {
    /// Returns the next generated event, if any.
    fn poll_event(&mut self) -> Option<SocketEvent>;

    /// Retrieves the next received message from the incoming message queue.
    ///
    /// When the socket receives data from the peer, it reassembles it into messages. Once a
    /// message is fully reassembled, it's placed in a queue. This method retrieves the
    /// first message from that queue.
    ///
    /// Returns `Some(Message)` if there is a message available, and `None` otherwise.
    /// It's recommended to check [`DcSctpSocket::messages_ready_count`] before calling this.
    fn get_next_message(&mut self) -> Option<Message>;

    /// To be called when an incoming SCTP packet is to be processed.
    fn handle_input(&mut self, packet: &[u8]);

    /// Advances the internal clock to a specific point in the socket's lifetime.
    ///
    /// The `now` parameter represents the absolute time on the socket's internal timeline
    /// and must be derived from the time elapsed since the socket was created.
    ///
    /// Time should always move forward. If you provide a `now` value that is older than
    /// a previous call (meaning time went backwards), the operation is safe but ignored,
    /// and the internal clock remains unchanged.
    ///
    /// This method triggers any timers scheduled to expire at or before `now`. Even if no
    /// timers expire, calling this method updates the socket's internal current time. This
    /// updated time is used as the start time for any new timers created during subsequent
    /// API calls, such as sending data.
    ///
    /// You should call this method whenever the external system clock advances. Specifically,
    /// it must be called when the system clock reaches the time returned by [`Self::poll_timeout`].
    /// It is also recommended to call it before invoking other methods, like `handle_input` or
    /// `send`, if significant time has passed, ensuring that internal timestamps remain accurate.
    fn advance_time(&mut self, now: SocketTime);

    /// Returns the next absolute time on the socket's timeline when a timer expires.
    ///
    /// This value is monotonic and will never be earlier than the `now` parameter passed to
    /// the last [`Self::advance_time`] call. If a timer is overdue or due immediately, the
    /// current internal socket time is returned to ensure immediate processing.
    ///
    /// The return value can change as a consequence of calling any mutable method on the socket.
    /// For example, receiving a packet might stop a retransmission timer, effectively removing
    /// or pushing back the timeout. Therefore, the driving loop should consider this value
    /// invalidated after performing other operations on the socket.
    ///
    /// Returns `SocketTime::infinite_future()` if there are no active timers.
    fn poll_timeout(&self) -> SocketTime;

    /// Connects the socket. This is an asynchronous operation, and [`SocketEvent::OnConnected`]
    /// will be generated on success.
    fn connect(&mut self);

    /// Puts this socket to the state in which the original socket was when its
    /// [`SocketHandoverState`] was captured by [`Self::get_handover_state_and_close`].
    /// [`Self::restore_from_state`] is allowed only on the closed socket.
    /// [`SocketEvent::OnConnected`] will be called if a connected socket state is restored.
    /// [`SocketEvent::OnError`] will be called on error.
    fn restore_from_state(&mut self, state: &SocketHandoverState);

    /// Gracefully shutdowns the socket and sends all outstanding data. This is an asynchronous
    /// operation and an event will be dispatch on success.
    fn shutdown(&mut self);

    /// Closes the connection non-gracefully. Will send ABORT if the connection is not already
    /// closed. No events will be emitted when this function has returned.
    fn close(&mut self);

    /// The socket state.
    fn state(&self) -> SocketState;

    /// Returns the number of fully reassembled messages waiting in the incoming message queue.
    /// These messages can be retrieved by calling [`DcSctpSocket::get_next_message`].
    fn messages_ready_count(&self) -> usize;

    fn options(&self) -> Options;

    /// Update the options max_message_size.
    fn set_max_message_size(&mut self, max_message_size: usize);

    /// Sets the priority of an outgoing stream. The initial value, when not set, is
    /// [`Options::default_stream_priority`].
    fn set_stream_priority(&mut self, stream_id: StreamId, priority: u16);

    /// Returns the currently set priority for an outgoing stream. The initial value, when not set,
    /// is [`Options::default_stream_priority`].
    fn get_stream_priority(&self, stream_id: StreamId) -> u16;

    /// Sends the message `message` using the provided send options.
    ///
    /// Sending a message is an asynchronous operation, and the [`SocketEvent::OnError`] event may
    /// be generated to indicate any errors in sending the message.
    ///
    /// The association does not have to be established before calling this method. If it's called
    /// before there is an established association, the message will be queued.
    fn send(&mut self, message: Message, send_options: &SendOptions) -> SendStatus;

    /// Sends the messages `messages` using the provided send options.
    ///
    /// Sending messages is an asynchronous operation, and the [`SocketEvent::OnError`] event may
    /// be generated to indicate any errors in sending the message.
    ///
    /// This has identical semantics to [`DcSctpSocket::send`], except that it may coalesce many
    /// messages into a single SCTP packet if they would fit.
    fn send_many(&mut self, messages: Vec<Message>, send_options: &SendOptions) -> Vec<SendStatus>;

    /// Resets outgoing streams.
    ///
    /// This is an asynchronous operation, and the results will be notified using
    /// [`SocketEvent::OnStreamsResetPerformed`] on success and
    /// [`SocketEvent::OnStreamsResetFailed`] on failure. Note that only outgoing streams can be
    /// reset.
    ///
    /// When it's known that the peer has reset its own outgoing streams,
    /// [`SocketEvent::OnIncomingStreamReset`] is called.
    ///
    /// Note that resetting a stream will also remove all queued messages on those streams, but will
    /// ensure that the currently transmitted message (if any) is fully sent before closing the
    /// stream.
    ///
    /// Resetting streams can only be done on an established association that supports stream
    /// resetting.
    fn reset_streams(&mut self, outgoing_streams: &[StreamId]) -> ResetStreamsStatus;

    /// Returns the number of bytes of data currently queued to be sent on a given stream.
    fn buffered_amount(&self, stream_id: StreamId) -> usize;

    /// Returns the number of buffered outgoing bytes that is considered "low" for a given stream.
    /// Also see [`Self::set_buffered_amount_low_threshold`].
    fn buffered_amount_low_threshold(&self, stream_id: StreamId) -> usize;

    /// Specifies the number of bytes of buffered outgoing data that is considered "low" for a given
    /// stream, which will trigger an [`SocketEvent::OnBufferedAmountLow`] event. The default value
    /// is zero.
    fn set_buffered_amount_low_threshold(&mut self, stream_id: StreamId, bytes: usize);

    /// Retrieves the latest metrics.
    ///
    /// Returns `None` if the socket is not fully connected. Note that metrics are not guaranteed
    /// to be carried over if this socket is handed over by calling
    /// [`Self::get_handover_state_and_close`].
    fn get_metrics(&self) -> Option<Metrics>;

    /// Indicates if the component can be snapshotted by calling
    /// [`Self::get_handover_state_and_close`]. The return value is invalidated by a call to any
    /// method that mutates the component.
    fn get_handover_readiness(&self) -> HandoverReadiness;

    /// Collects a snapshot of the socket state that can be used to reconstruct this socket in
    /// another process.
    ///
    /// On success, this socket object is closed synchronously, and no more events will be emitted
    /// after this method has returned. [`SocketEvent::OnClosed`] will be called on success.
    ///
    /// Returns `None` if the socket is not in a state ready for handover.
    fn get_handover_state_and_close(&mut self) -> Option<SocketHandoverState>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options() {
        let options: Options = Options::default();
        assert_eq!(options.local_port, 5000);
        assert_eq!(options.remote_port, 5000);
    }
}
