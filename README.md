# TCP over UDP in Julia

Building TCP on top of UDP because why not. This implements the core TCP features (handshakes, retransmission, ordering) using Julia's socket library.

## What it does

- Three-way handshake to establish connections
- Sequence numbers and ACKs for reliable delivery
- Buffers out-of-order packets and reassembles them
- Retransmits dropped packets after timeout
- Four-way close to terminate cleanly
- Can simulate packet loss for testing

## Packet Format

```
| seq_num (4 bytes) | ack_num (4 bytes) | flags (1 byte) | payload (variable) |
```

Flags:
- `SYN` (0x01) - Synchronize sequence numbers
- `ACK` (0x02) - Acknowledgment
- `FIN` (0x04) - Finish/close connection

## How to run

Server:
```bash
julia server.jl
```

Client:
```bash
julia client.jl
```

## Tweaking settings

Check `client.jl` for these:

```julia
const TIMEOUT_MS = 500       # How long to wait before retransmitting
const MAX_RETRIES = 5        # Give up after this many tries
const PACKET_SIZE = 100      # Bytes per packet
const SIMULATE_LOSS = true   # Drop packets randomly for testing
const LOSS_RATE = 0.3        # Drop 30% of packets
```

## What you'll see

Client side:
```
[CLIENT] === STARTING THREE-WAY HANDSHAKE ===
[CLIENT] Sent: seq=812, ack=0, flags=SYN, payload_len=0
[CLIENT] State: CLOSED -> SYN_SENT
[CLIENT] Recv: seq=859, ack=813, flags=SYN+ACK
[CLIENT] State: SYN_SENT -> ESTABLISHED (handshake complete)

[CLIENT] === SENDING DATA ===
[CLIENT] (SIMULATED DROP) seq=813, flags=NONE
[CLIENT] Timeout - checking for retransmissions
[CLIENT] Retransmitting seq=813 (attempt 1)
[CLIENT] Recv ACK: ack_num=1108
[CLIENT] === ALL DATA ACKNOWLEDGED ===
```

Server side:
```
[SERVER] Listening on port 9000
[SERVER] State: LISTEN -> SYN_RECEIVED (received SYN)
[SERVER] State: SYN_RECEIVED -> ESTABLISHED (handshake complete)
[SERVER] Buffered out-of-order packet seq=913
[SERVER] Received in-order data: 100 bytes

[SERVER] ========== RECEIVED MESSAGE ==========
Hello from TCP-over-UDP client!
This is a multi-packet message to demonstrate reliable delivery.
[SERVER] ==========================================
```

## State flow

Client goes through:
```
CLOSED → SYN_SENT → ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED
```

Server goes through:
```
LISTEN → SYN_RECEIVED → ESTABLISHED → CLOSE_WAIT → LAST_ACK → CLOSED
```

## Requirements

Julia 1.6 or newer. Uses only the standard `Sockets` library.
