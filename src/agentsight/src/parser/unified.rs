//! Unified Parser - high-level entry point for protocol parsing
//
//! This module provides a unified interface for parsing SSL events and process events.
//! It combines HTTP Parser, SSE Parser, and ProcTrace Parser, but does NOT include aggregation logic.
//
//! For aggregation, use:
//! - `HttpConnectionAggregator` for HTTP/SSE events
//! - `ProcessEventAggregator` for process events

use super::{ParseResult, ParsedMessage};
use crate::event::Event;
use crate::parser::http::{HttpParser, ParsedHttpMessage};
use crate::parser::http2::Http2Parser;
use crate::parser::proctrace::ProcTraceParser;
use crate::parser::sse::{ParsedSseEvent, SseParser};
use crate::probes::proctrace::VariableEvent;
use crate::probes::sslsniff::SslEvent;
use crate::runtime_metrics::StageTimer;
use std::rc::Rc;

/// Unified parser for SSL and process events
///
/// This parser provides a unified entry point for parsing but does NOT
/// aggregate or correlate messages. Use aggregators for that.
pub struct Parser {
    http_parser: HttpParser,
    http2_parser: Http2Parser,
    sse_parser: SseParser,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    /// Create new parser
    pub fn new() -> Self {
        Parser {
            http_parser: HttpParser::new(),
            http2_parser: Http2Parser::new(),
            sse_parser: SseParser::new(),
        }
    }

    /// Parse SSL event into messages
    //
    /// Returns parsed HTTP Request/Response or SSE Events.
    /// Does NOT aggregate or correlate - use `HttpConnectionAggregator` for that.
    pub fn parse_ssl_event(&self, ssl_event: Rc<SslEvent>) -> ParseResult {
        log::debug!("parse_ssl_event: length={}", ssl_event.buf_size());

        let _comm = ssl_event.comm.trim_end_matches('\0');

        // 0. Connections already being reassembled as HTTP/2 route by state
        // before any stateless heuristic: a read that continues a frame split
        // across TLS records starts inside a payload and can look like
        // anything, so it would never match the frame detection below.
        let mut already_parsed_as_http2 = false;
        if self.http2_parser.is_tracking(&ssl_event) {
            let frames = self.http2_parser.parse(ssl_event.clone());
            already_parsed_as_http2 = true;
            if !frames.is_empty() {
                return ParseResult {
                    messages: vec![ParsedMessage::Http2Frames(frames)],
                };
            }
        }

        // 1. HTTP/1.x detection (text-based protocols)
        if ssl_event.is_http() {
            match self.http_parser.parse(ssl_event.clone()) {
                Ok(msg) => {
                    let message = match msg {
                        ParsedHttpMessage::Request(req) => ParsedMessage::Request(req),
                        ParsedHttpMessage::Response(resp) => ParsedMessage::Response(resp),
                    };
                    return ParseResult {
                        messages: vec![message],
                    };
                }
                Err(e) => {
                    log::debug!("Failed to parse HTTP/1.x event: {e}");
                }
            }
        }

        // 2. HTTP/2 detection (binary frame protocol). A read already consumed
        // by the state-routed parse above must not be parsed a second time:
        // `Http2Parser::parse` folds the read's bytes into the per-connection
        // reassembly buffer, so a second call would duplicate them — a payload
        // fragment whose leading bytes happen to look like a frame header was
        // then emitted as a bogus frame and the true split frame reassembled
        // from duplicated bytes.
        if !already_parsed_as_http2 && ssl_event.is_http2() {
            let frames = self.http2_parser.parse(ssl_event.clone());
            if !frames.is_empty() {
                return ParseResult {
                    messages: vec![ParsedMessage::Http2Frames(frames)],
                };
            }
        }

        // 2.5. Detect HTTP chunked transfer encoding end marker "0\r\n\r\n".
        // This signals end of a chunked SSE stream (e.g., OpenAI Responses API).
        // The terminator is often appended to the end of the last SSE data
        // chunk rather than arriving as a standalone 5-byte read, so we check
        // whether the buffer ends with (or equals) `0\r\n\r\n`.
        //
        // When found, strip the terminator bytes, parse any remaining SSE data
        // from the prefix, and synthesize a [DONE] event so the aggregator can
        // complete the stream.
        {
            let buf_size = ssl_event.buf_size() as usize;
            let buf = &ssl_event.buf[..buf_size];
            const TERMINATOR: &[u8] = b"0\r\n\r\n";

            // The terminator belongs to the read direction only. A chunked
            // *request* body's final write also ends with `0\r\n\r\n`; cutting
            // it here and synthesizing a done event made the aggregator (still
            // in RequestBodyPending, which drops SSE events) lose those bytes,
            // so the request body was captured truncated and
            // `chunked_stream_complete` never fired. Write-direction buffers
            // must flow through as RawData so the framing completes.
            let terminator_pos = if ssl_event.rw == 0
                && buf.len() >= TERMINATOR.len()
                && buf.ends_with(TERMINATOR)
            {
                Some(buf.len() - TERMINATOR.len())
            } else {
                None
            };

            if let Some(prefix_len) = terminator_pos {
                let prefix = &buf[..prefix_len];
                let mut messages = Vec::new();

                // Parse SSE events from the data before the terminator
                if !prefix.is_empty() {
                    let trimmed = SslEvent {
                        source: ssl_event.source,
                        timestamp_ns: ssl_event.timestamp_ns,
                        delta_ns: ssl_event.delta_ns,
                        pid: ssl_event.pid,
                        tid: ssl_event.tid,
                        uid: ssl_event.uid,
                        len: prefix_len as u32,
                        rw: ssl_event.rw,
                        comm: ssl_event.comm.clone(),
                        buf: ssl_event.buf[..prefix_len].to_vec(),
                        is_handshake: ssl_event.is_handshake,
                        ssl_ptr: ssl_event.ssl_ptr,
                    };
                    let trimmed = Rc::new(trimmed);
                    let prefix_events = self.sse_parser.parse(Rc::clone(&trimmed));
                    if prefix_events.is_empty() {
                        // Not SSE text: for a compressed body these are the
                        // last compressed bytes, which only the aggregator's
                        // compressed-buffer state can decode. Dropping them
                        // truncated the frame, so `dechunk_body` +
                        // `decompress_body` failed and the whole response
                        // decoded to zero events. Forward them as a body
                        // continuation instead.
                        messages.push(ParsedMessage::RawData(Rc::clone(&trimmed)));
                    } else {
                        for ev in prefix_events {
                            messages.push(ParsedMessage::SseEvent(ev));
                        }
                    }
                }

                // Always append a synthetic done marker
                messages.push(ParsedMessage::SseEvent(ParsedSseEvent::new_done_marker(
                    Rc::clone(&ssl_event),
                )));

                return ParseResult { messages };
            }
        }

        // 3. Write-direction data that failed all protocol detection → RawData
        // This is likely a body continuation for an in-progress HTTP/1.1 request
        if ssl_event.rw == 1 {
            log::debug!(
                "parse_ssl_event: unrecognized write-direction data (len={}), emitting RawData",
                ssl_event.buf_size()
            );
            return ParseResult {
                messages: vec![ParsedMessage::RawData(ssl_event)],
            };
        }

        // 4. Fallback: SSE data (read-direction only)
        let sse_events = self.sse_parser.parse(ssl_event.clone());
        if sse_events.is_empty() {
            // No SSE events could be parsed from this read-direction chunk.
            // This happens when the SSE stream is compressed (gzip/zstd/br):
            // the bytes are not text and yield no `data:`/`event:` lines.
            // Forward the raw event so the aggregator — which knows the
            // connection's Content-Encoding — can buffer and later decompress
            // it. For non-SSE connections the aggregator simply ignores it.
            return ParseResult {
                messages: vec![ParsedMessage::RawData(ssl_event)],
            };
        }
        let messages = sse_events
            .into_iter()
            .map(ParsedMessage::SseEvent)
            .collect();
        ParseResult { messages }
    }

    /// Parse process event into messages
    ///
    /// Returns parsed process event (Exec/Stdout/Exit).
    /// Does NOT aggregate - use `ProcessEventAggregator` for that.
    pub fn parse_proc_event(&self, event: &VariableEvent) -> ParseResult {
        match ProcTraceParser::parse_variable(event) {
            Some(parsed) => ParseResult {
                messages: vec![ParsedMessage::ProcEvent(parsed)],
            },
            None => ParseResult {
                messages: Vec::new(),
            },
        }
    }

    /// Parse unified Event
    pub fn parse_event(&self, event: Event) -> ParseResult {
        let timer = StageTimer::start("parser");
        log::trace!("Parsing event({:?})", event.event_type());
        let result = match event {
            Event::Ssl(ssl_event) => self.parse_ssl_event(Rc::new(ssl_event)),
            Event::Proc(proc_event) => self.parse_proc_event(&proc_event),
            Event::ProcMon(_) => ParseResult {
                messages: Vec::new(),
            },
            Event::FileWatch(_) => ParseResult {
                messages: Vec::new(),
            },
            Event::FileWrite(_) => ParseResult {
                messages: Vec::new(),
            },
            Event::UdpDns(_) => ParseResult {
                messages: Vec::new(),
            },
        };
        timer.record_outputs(result.messages.len());
        result
    }

    /// Get reference to HTTP parser
    pub fn http_parser(&self) -> &HttpParser {
        &self.http_parser
    }

    /// Get reference to SSE parser
    pub fn sse_parser(&self) -> &SseParser {
        &self.sse_parser
    }

    /// Get reference to HTTP/2 parser
    pub fn http2_parser(&self) -> &Http2Parser {
        &self.http2_parser
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ssl_event_with_rw(data: Vec<u8>, rw: i32) -> Rc<SslEvent> {
        let len = data.len();
        Rc::new(SslEvent {
            source: 0,
            timestamp_ns: 0,
            delta_ns: 0,
            pid: 1,
            tid: 1,
            uid: 0,
            len: len as u32,
            rw,
            comm: String::new(),
            buf: data,
            is_handshake: false,
            ssl_ptr: 0x1000,
        })
    }

    fn make_ssl_event(data: Vec<u8>) -> Rc<SslEvent> {
        make_ssl_event_with_rw(data, 0)
    }

    #[test]
    fn test_chunked_terminator_standalone() {
        let parser = Parser::new();
        let event = make_ssl_event(b"0\r\n\r\n".to_vec());
        let result = parser.parse_ssl_event(event);
        assert_eq!(result.messages.len(), 1);
        assert!(matches!(
            result.messages[0],
            ParsedMessage::SseEvent(ref e) if e.is_done()
        ));
    }

    #[test]
    fn test_chunked_terminator_appended_to_sse_data() {
        let parser = Parser::new();
        let data = b"data: {\"type\":\"response.output_text.delta\"}\n\n0\r\n\r\n".to_vec();
        let event = make_ssl_event(data);
        let result = parser.parse_ssl_event(event);
        // Should produce: 1 SSE event from the data + 1 done marker
        assert_eq!(result.messages.len(), 2);
        assert!(matches!(
            result.messages[0],
            ParsedMessage::SseEvent(ref e) if !e.is_done()
        ));
        assert!(matches!(
            result.messages[1],
            ParsedMessage::SseEvent(ref e) if e.is_done()
        ));
    }

    #[test]
    fn test_no_chunked_terminator_normal_sse() {
        let parser = Parser::new();
        let data = b"data: hello\n\n".to_vec();
        let event = make_ssl_event(data);
        let result = parser.parse_ssl_event(event);
        assert_eq!(result.messages.len(), 1);
        assert!(matches!(
            result.messages[0],
            ParsedMessage::SseEvent(ref e) if !e.is_done()
        ));
    }

    /// `0\r\n\r\n` is a chunked-SSE terminator only on the read direction. On
    /// the write direction it is the final zero-size chunk of a chunked
    /// request body: cutting it here and synthesizing a done marker made the
    /// aggregator (in RequestBodyPending, where SSE events are dropped) lose
    /// those bytes, so the request body was captured truncated and
    /// `chunked_stream_complete` never fired.
    #[test]
    fn test_write_direction_terminator_stays_raw_data() {
        let parser = Parser::new();
        let data = b"a\r\n{\"x\":1}\r\n0\r\n\r\n".to_vec();
        // rw == 1 is the write direction (see `parse_ssl_event` step 3).
        let event = make_ssl_event_with_rw(data.clone(), 1);
        let result = parser.parse_ssl_event(event);

        assert_eq!(result.messages.len(), 1);
        match &result.messages[0] {
            ParsedMessage::RawData(raw) => assert_eq!(
                &raw.buf[..raw.buf_size() as usize],
                data.as_slice(),
                "write-direction buffer must reach the aggregator intact"
            ),
            other => panic!("write-direction buffer must be emitted as RawData, got {other:?}"),
        }
    }

    /// Raw HTTP/2 frame: 3-byte length, type, flags, 4-byte stream id, payload.
    fn h2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut buf = vec![
            ((len >> 16) & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
            frame_type,
            flags,
            ((stream_id >> 24) & 0x7F) as u8,
            ((stream_id >> 16) & 0xFF) as u8,
            ((stream_id >> 8) & 0xFF) as u8,
            (stream_id & 0xFF) as u8,
        ];
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn test_split_http2_frame_continuation_is_routed_by_state() {
        let parser = Parser::new();
        let payload = br#"{"model":"gpt-4","messages":[{"role":"user"}]}"#;
        let data = h2_frame(0, 0x01, 3, payload);
        let split = 9 + payload.len() / 2;

        // The first read carries a complete SETTINGS frame (so the stateless
        // frame detection succeeds) followed by a truncated DATA frame.
        let mut first = h2_frame(4, 0x00, 0, &[]);
        first.extend_from_slice(&data[..split]);
        let first = parser.parse_ssl_event(make_ssl_event(first));
        assert!(
            matches!(
                first.messages.as_slice(),
                [ParsedMessage::Http2Frames(frames)] if frames.len() == 1 && frames[0].is_settings()
            ),
            "first read must emit only the complete SETTINGS frame, got {:?}",
            first.messages
        );

        // The continuation starts inside the DATA payload; without state
        // routing it would not reach the HTTP/2 parser at all.
        let second = parser.parse_ssl_event(make_ssl_event(data[split..].to_vec()));
        let [ParsedMessage::Http2Frames(frames)] = second.messages.as_slice() else {
            panic!(
                "continuation must be routed to the HTTP/2 parser, got {:?}",
                second.messages
            );
        };
        assert_eq!(frames.len(), 1);
        assert!(frames[0].is_data());
        assert_eq!(frames[0].stream_id, 3);
        assert_eq!(frames[0].payload(), payload);
    }

    #[test]
    fn tracked_continuation_is_not_parsed_twice() {
        // A continuation read on a tracked HTTP/2 connection that still yields
        // no complete frame falls through to the stateless detection below.
        // That second `parse` call folds the same read's bytes into the
        // reassembly buffer a second time, so a payload fragment whose leading
        // bytes happen to look like a small frame header was emitted as a
        // bogus frame — and the true split frame then reassembled from the
        // duplicated bytes, corrupting the call's body.
        let parser = Parser::new();
        let payload: Vec<u8> = (0u8..40).collect();
        // A DATA frame header declaring 40 payload bytes, plus the first 8
        // payload bytes: the frame is still incomplete after this read.
        let mut partial_data = vec![0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03];
        partial_data.extend_from_slice(&payload[..8]);
        let mut first = h2_frame(4, 0x00, 0, &[]);
        first.extend_from_slice(&partial_data);

        let first = parser.parse_ssl_event(make_ssl_event(first));
        assert!(
            matches!(
                &first.messages[..],
                [ParsedMessage::Http2Frames(frames)] if frames.len() == 1 && frames[0].is_settings()
            ),
            "first read must emit only the SETTINGS frame, got {:?}",
            first.messages
        );

        // The continuation starts inside the payload. Its first nine bytes are
        // payload bytes that look like a small frame header (type <= 9, high
        // stream-id bit clear, 9 + length <= buffer), so the stateless gate
        // fires — while the merged buffer is still short of the declared 40
        // payload bytes, so the state-routed parse yields no frame.
        let mut second = vec![0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03];
        second.extend_from_slice(&payload[8..23]);

        let second_read = second.clone();
        let second = parser.parse_ssl_event(make_ssl_event(second));
        assert!(
            !second
                .messages
                .iter()
                .any(|m| matches!(m, ParsedMessage::Http2Frames(_))),
            "a read already consumed by the state-routed parse must not be re-parsed as HTTP/2, got {:?}",
            second.messages
        );

        // The final fragment must complete the frame from the wire bytes: the
        // true payload is whatever followed the header on the wire, exactly
        // once each — not the duplicated bytes the second parse produced.
        let mut expected_payload = payload[..8].to_vec();
        expected_payload.extend_from_slice(&second_read);
        expected_payload.extend_from_slice(&payload[23..31]);
        let third = parser.parse_ssl_event(make_ssl_event(payload[23..].to_vec()));
        assert!(
            third.messages.iter().any(|m| matches!(
                m,
                ParsedMessage::Http2Frames(frames)
                    if frames.iter().any(|f| f.is_data() && f.payload() == expected_payload)
            )),
            "the split frame must complete with its wire payload, got {:?}",
            third.messages
        );
    }
}
