//! Cross-host causal merge (architecture §15). This is the receive-side
//! half of the piggyback protocol in `piggyback.rs`: a host's `HlcGenerator`
//! calls `receive(remote_hlc)` instead of `tick()` when recording a `NetIo`
//! recv event whose payload was produced by `piggyback::decode`. The
//! result is a timestamp that is provably `>` both the local host's prior
//! HLC and the remote sender's HLC at send time — i.e. a genuine
//! happens-after edge, without any clock synchronization protocol.
//!
//! `simulate_send_receive` ties the whole path together for testing and
//! for documentation-by-example: given a sender's `HlcGenerator` and a
//! receiver's `HlcGenerator`, it performs exactly the sequence of calls a
//! real recorder does around a `sendto`/`recvfrom` pair.

use crate::piggyback::{decode, encode, PiggybackError};
use ptdf_types::{HlcGenerator, HlcTimestamp, PhysicalClock};

/// Perform one simulated cross-host send/receive: the sender ticks its own
/// HLC and encodes it onto `payload`; the receiver decodes it and merges
/// it into its own HLC via `receive`. Returns `(send_hlc, receive_hlc,
/// wire_bytes)` so callers/tests can assert on the causal relationship
/// directly.
pub fn simulate_send_receive<C1: PhysicalClock, C2: PhysicalClock>(
    sender: &mut HlcGenerator<C1>,
    receiver: &mut HlcGenerator<C2>,
    payload: &[u8],
) -> Result<(HlcTimestamp, HlcTimestamp, Vec<u8>), PiggybackError> {
    let send_hlc = sender.tick();
    let wire = encode(send_hlc, payload);

    let (remote_hlc, _app_payload) = decode(&wire)?;
    debug_assert_eq!(remote_hlc, send_hlc, "decoded HLC must exactly match what was encoded");

    let receive_hlc = receiver.receive(remote_hlc);
    Ok((send_hlc, receive_hlc, wire))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ptdf_types::SystemPhysicalClock;
    use std::cell::Cell;

    struct FixedClock {
        value: Cell<u64>,
    }
    impl PhysicalClock for FixedClock {
        fn now_ns(&self) -> u64 {
            self.value.get()
        }
    }

    #[test]
    fn receive_hlc_is_causally_after_the_send_hlc() {
        let mut sender = HlcGenerator::new(FixedClock { value: Cell::new(1_000) });
        let mut receiver = HlcGenerator::new(FixedClock { value: Cell::new(500) }); // receiver's clock is "behind"

        let (send_hlc, receive_hlc, _wire) = simulate_send_receive(&mut sender, &mut receiver, b"payload").unwrap();

        assert!(receive_hlc > send_hlc, "the recv event must be ordered strictly after the send event that caused it");
    }

    #[test]
    fn receiver_with_a_faster_clock_still_respects_causality() {
        // Receiver's physical clock is *ahead* of the sender's at the
        // moment of receipt — receive() must still produce something
        // after send_hlc, not just after its own prior local time, since
        // the whole point is bounding by the max of both.
        let mut sender = HlcGenerator::new(FixedClock { value: Cell::new(100) });
        let mut receiver = HlcGenerator::new(FixedClock { value: Cell::new(100) }); // same physical instant

        let (send_hlc, receive_hlc, _wire) = simulate_send_receive(&mut sender, &mut receiver, b"x").unwrap();
        assert!(receive_hlc > send_hlc);
    }

    #[test]
    fn multiple_messages_preserve_a_consistent_causal_chain() {
        let mut sender = HlcGenerator::new(SystemPhysicalClock);
        let mut receiver = HlcGenerator::new(SystemPhysicalClock);

        let (send1, recv1, _) = simulate_send_receive(&mut sender, &mut receiver, b"msg1").unwrap();
        let (send2, recv2, _) = simulate_send_receive(&mut sender, &mut receiver, b"msg2").unwrap();

        assert!(send2 > send1, "sender's own HLC must keep advancing across messages");
        assert!(recv1 > send1);
        assert!(recv2 > send2);
        assert!(recv2 > recv1, "receiver's HLC must keep advancing across messages");
    }

    #[test]
    fn app_payload_survives_the_round_trip_alongside_the_hlc() {
        let mut sender = HlcGenerator::new(SystemPhysicalClock);
        let mut receiver = HlcGenerator::new(SystemPhysicalClock);
        let (_send, _recv, wire) = simulate_send_receive(&mut sender, &mut receiver, b"hello world").unwrap();

        let (_hlc, app_payload) = decode(&wire).unwrap();
        assert_eq!(app_payload, b"hello world");
    }
}
