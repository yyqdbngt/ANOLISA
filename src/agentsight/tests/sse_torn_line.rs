//! A `data:` line torn by a TLS record boundary must not lose its event.
mod common;

use agentsight::aggregator::{AggregatedResult, Aggregator};
use agentsight::event::Event;
use agentsight::parser::Parser;

/// A three-event OpenAI-style SSE stream with a usage-bearing terminal event.
fn sse_stream() -> Vec<u8> {
    [
        "data: {\"choices\":[{\"delta\":{\"content\":\"one\"}}]}",
        "",
        "data: {\"choices\":[{\"delta\":{\"content\":\"two\"}}]}",
        "",
        "data: {\"choices\":[{\"delta\":{\"content\":\"three\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":3,\"total_tokens\":12}}",
        "",
        "data: [DONE]",
        "",
    ]
    .iter()
    .map(|line| format!("{line}\n"))
    .collect::<Vec<_>>()
    .join("")
    .into_bytes()
}

fn feed(
    parser: &Parser,
    aggregator: &mut Aggregator,
    rw: i32,
    bytes: &[u8],
    time: u64,
) -> Vec<AggregatedResult> {
    let mut event = common::make_ssl_event(4321, 0x777, rw, bytes.to_vec(), "fixture");
    event.timestamp_ns = time;
    aggregator.process_result(parser.parse_event(Event::Ssl(event)))
}

/// Feed the stream split at `split`, with the response headers leading the
/// first fragment, and return the completed pair's concatenated event data.
fn complete_from_split(split: usize) -> String {
    let stream = sse_stream();
    let parser = Parser::new();
    let mut aggregator = Aggregator::new();
    assert!(
        feed(
            &parser,
            &mut aggregator,
            1,
            &common::make_openai_request_bytes("test-model", "hello", true),
            1
        )
        .is_empty()
    );

    let headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n";
    let mut first = headers.to_vec();
    first.extend_from_slice(&stream[..split]);
    let first_results = feed(&parser, &mut aggregator, 0, &first, 10);
    let rest_results = feed(&parser, &mut aggregator, 0, &stream[split..], 20);
    // A split inside the final blank line leaves the whole stream (done
    // marker included) in the first read, which legitimately completes it.
    let completed: Vec<&AggregatedResult> = first_results
        .iter()
        .chain(rest_results.iter())
        .collect();
    let pair = match completed.as_slice() {
        [AggregatedResult::SseComplete(pair)] => pair,
        other => panic!("split {split}: expected one completion, got {} results", other.len()),
    };
    pair.response
        .sse_events
        .iter()
        .filter(|event| !event.is_done())
        .map(|event| String::from_utf8_lossy(event.data()).into_owned())
        .collect()
}

/// Every split of a plain SSE stream keeps every event.
///
/// `SseParser` is stateless per read and yields nothing for a line without
/// its terminating newline, so a `data:` line torn by a TLS record boundary
/// used to lose its whole event: the continuation read started mid-line,
/// parsed only the following complete lines, and the torn event's text, tool
/// deltas or usage silently vanished while the stream looked healthy. The
/// sweep pins every split point of the fixture — inside any data line, the
/// blank separators, or the done marker.
#[test]
fn every_split_point_keeps_every_event() {
    let stream = sse_stream();
    for split in 1..stream.len() {
        let text = complete_from_split(split);
        for needle in ["one", "two", "three", "usage"] {
            assert!(
                text.contains(needle),
                "split {split}: lost {needle} from the stream, events: {text}"
            );
        }
    }
}

/// The same tear through a chunked, compressed body.
///
/// The read direction's terminator path (`0\r\n\r\n` appended to the last
/// chunk) strips the terminator before parsing, so a line torn ahead of it
/// must be joined there too or the compressed frame is truncated and the
/// whole stream decodes to zero events.
#[test]
fn every_split_point_of_a_chunked_compressed_stream_keeps_every_event() {
    let compressed =
        zstd::encode_all(&sse_stream()[..], 3).expect("fixture compresses");
    let mut framed = Vec::new();
    framed.extend_from_slice(format!("{:x}\r\n", compressed.len()).as_bytes());
    framed.extend_from_slice(&compressed);
    framed.extend_from_slice(b"\r\n0\r\n\r\n");
    let headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: zstd\r\nTransfer-Encoding: chunked\r\n\r\n";

    for split in 1..framed.len() {
        let parser = Parser::new();
        let mut aggregator = Aggregator::new();
        assert!(
            feed(
                &parser,
                &mut aggregator,
                1,
                &common::make_openai_request_bytes("test-model", "hello", true),
                1
            )
            .is_empty()
        );
        let mut first = headers.to_vec();
        first.extend_from_slice(&framed[..split]);
        let first_results = feed(&parser, &mut aggregator, 0, &first, 10);
        let rest_results = feed(&parser, &mut aggregator, 0, &framed[split..], 20);
        let completed: Vec<&AggregatedResult> = first_results
            .iter()
            .chain(rest_results.iter())
            .collect();
        let pair = match completed.as_slice() {
            [AggregatedResult::SseComplete(pair)] | [AggregatedResult::HttpComplete(pair)] => pair,
            other => panic!("split {split}: expected one completion, got {} results", other.len()),
        };
        let text = pair.response.body_string();
        for needle in ["one", "two", "three"] {
            assert!(
                text.contains(needle),
                "split {split}: compressed stream lost {needle}"
            );
        }
    }
}
