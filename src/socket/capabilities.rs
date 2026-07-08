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

use crate::api::Options;
use crate::api::ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE;
use crate::api::ZeroChecksumAlternateErrorDetectionMethod;
use crate::packet::forward_tsn_chunk;
use crate::packet::idata_chunk;
use crate::packet::parameter::Parameter;
use crate::packet::re_config_chunk;
use crate::packet::supported_extensions_parameter::SupportedExtensionsParameter;
use crate::packet::zero_checksum_acceptable_parameter::ZeroChecksumAcceptableParameter;
use std::collections::HashSet;

/// Indicates what the association supports, meaning that both parties support it and that feature
/// can be used.
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    /// RFC 3758 Partial Reliability Extension
    pub partial_reliability: bool,

    /// RFC 8260 Stream Schedulers and User Message Interleaving
    pub message_interleaving: bool,

    /// RFC 6525 Stream Reconfiguration
    pub reconfig: bool,

    /// RFC 9653 Zero Checksum Alternate Error Detection Method
    pub zero_checksum_method: ZeroChecksumAlternateErrorDetectionMethod,

    /// Negotiated maximum incoming stream count.
    pub negotiated_maximum_incoming_streams: u16,

    /// Negotiated maximum outgoing stream count.
    pub negotiated_maximum_outgoing_streams: u16,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            partial_reliability: false,
            message_interleaving: false,
            reconfig: false,
            zero_checksum_method: ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE,
            negotiated_maximum_incoming_streams: 0,
            negotiated_maximum_outgoing_streams: 0,
        }
    }
}

impl Capabilities {
    /// Extracts capabilities from a list of parameters received from the peer.
    ///
    /// This parses the parameters (typically from an INIT or INIT ACK chunk)
    /// to determine what features the peer supports and what limits it imposes.
    pub fn from_parameters(
        nbr_outbound_streams: u16,
        nbr_inbound_streams: u16,
        parameters: &[Parameter],
    ) -> Self {
        let supported: HashSet<u8> = parameters
            .iter()
            .find_map(|e| match e {
                Parameter::SupportedExtensions(SupportedExtensionsParameter { chunk_types }) => {
                    Some(chunk_types)
                }
                _ => None,
            })
            .unwrap_or(&vec![])
            .iter()
            .cloned()
            .collect();

        let partial_reliability =
            parameters.iter().any(|e| matches!(e, Parameter::ForwardTsnSupported(_)))
                || supported.contains(&forward_tsn_chunk::CHUNK_TYPE);

        let message_interleaving = supported.contains(&idata_chunk::CHUNK_TYPE);

        let reconfig = supported.contains(&re_config_chunk::CHUNK_TYPE);

        let zero_checksum_method = *parameters
            .iter()
            .find_map(|e| match e {
                Parameter::ZeroChecksumAcceptable(ZeroChecksumAcceptableParameter { method }) => {
                    Some(method)
                }
                _ => None,
            })
            .unwrap_or(&ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE);

        Self {
            partial_reliability,
            message_interleaving,
            reconfig,
            zero_checksum_method,
            negotiated_maximum_incoming_streams: nbr_outbound_streams,
            negotiated_maximum_outgoing_streams: nbr_inbound_streams,
        }
    }

    /// Negotiates the capabilities of the association.
    ///
    /// When this struct represents the capabilities supported by the peer, and the local socket
    /// options are passed in, this returns the mutually supported and negotiated capabilities.
    pub fn negotiate(&self, options: &Options) -> Capabilities {
        let partial_reliability = options.enable_partial_reliability && self.partial_reliability;
        let message_interleaving = options.enable_message_interleaving && self.message_interleaving;
        let zero_checksum_method = if options.zero_checksum_alternate_error_detection_method
            == self.zero_checksum_method
        {
            self.zero_checksum_method
        } else {
            ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE
        };

        Capabilities {
            partial_reliability,
            message_interleaving,
            reconfig: self.reconfig,
            zero_checksum_method,
            negotiated_maximum_incoming_streams: std::cmp::min(
                options.announced_maximum_incoming_streams,
                self.negotiated_maximum_incoming_streams,
            ),
            negotiated_maximum_outgoing_streams: std::cmp::min(
                options.announced_maximum_outgoing_streams,
                self.negotiated_maximum_outgoing_streams,
            ),
        }
    }

    /// Indicates if the RFC 9653 Zero Checksum is enabled.
    pub fn zero_checksum_enabled(&self) -> bool {
        self.zero_checksum_method != ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE
    }
}
