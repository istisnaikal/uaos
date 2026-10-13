# Spike WP3.0b: passthrough overhead, results (2026-10-13)

**Question (plan v2 §10.2 item 4, H2):** does a byte-exact passthrough proxy in the ADR-0013
shape cost at most **12.5 ms at p95**? That is half of the 25 ms local-overhead SLO, which leaves
the other half for the pipeline stages.

**Setup:** everything on 127.0.0.1.
- A mock provider streams 200 SSE `content_block_delta` events.
- Requests carry a 1.7 MB JSON body (about a 400k-token history).
- The proxy collects the body under a limit, forwards it through a pooled hyper client without
  hop-by-hop headers, and relays response frames without buffering.
- Overhead = proxy quantile − direct quantile.
- CI rows: run [38431616204](https://github.com/istisnaikal/uaos/actions/runs/38431616204).

## Overhead p95

| Machine | Sequential TTFB | Sequential last byte | 8 concurrent TTFB | 8 concurrent last byte |
|---|---|---|---|---|
| Local Windows 10 (Ryzen 5600X) | 1.53 ms | 2.16 ms | 4.57 ms | 5.81 ms |
| CI ubuntu-latest | 0.91 ms | 0.75 ms | 2.34 ms | 5.25 ms |
| CI macos-latest | 0.98 ms | 1.29 ms | 3.10 ms | 7.82 ms |
| CI windows-latest | 1.49 ms | 1.43 ms | 3.49 ms | 8.15 ms |

## Verdict

- **Passes on all three OSes.** The worst p95 overhead is 8.15 ms (Windows runner, 8 concurrent
  clients, last byte), under the 12.5 ms budget. Sequential overhead is 1–2 ms.
- **Concurrency is the driver.** With 8 parallel clients each 1.7 MB body is copied in and out
  of the proxy under contention. The full pipeline (detection on new chunks, final scan about
  4.7 ms on this body size, journal and chunk writes) sits on top of this, so the per-stage
  budget in plan v2 §2.4 stays tight under parallel subagents. The P3 overhead bench must
  include a concurrent scenario.
- **Method limitation:** quantile differencing can read 0 at p99 when the direct path's own tail
  is noisier than the proxy's; several p99 cells did. p95 is the reliable comparison here, and
  the P3 harness should use paired measurements or many more samples for p99.
- **Not covered:** TLS toward the upstream (the real provider leg). That cost belongs to the
  provider/network side the SLO excludes, but the handshake is reused through pooling and
  should be confirmed in WP3.2.
