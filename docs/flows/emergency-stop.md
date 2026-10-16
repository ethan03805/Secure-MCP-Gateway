# Emergency stop

How an operator stops all tool execution (FR-4.14, SR-7.6-1, SR-7.6-2, SR-1.16-1; ARCH §18.7). Stop is serialized through the coordinator's gate, so every launch and release is ordered entirely before or after it.

```mermaid
sequenceDiagram
  autonumber
  participant O as Operator
  participant E24 as E-24 Control API (G-01 or smcpctl stop)
  participant E12 as E-12 Coordinator gate
  participant E21 as E-21 Journal
  participant E04 as E-04 Sessions
  participant E10 as E-10 Dispatcher
  participant E15 as E-15 Runtime
  participant E20 as E-20 Secret Broker
  participant H as Harness

  O->>E24: stop (Operator or Administrator)
  E24->>E12: stop request
  E12->>E12: take the gate, advance stop epoch
  E12->>E21: emergency_stop event, flushed
  par fan-out over I-20
    E12->>E10: cancel in-flight calls (cancellation is not proof of rollback)
    E12->>E15: tear down instances
    E12->>E20: withdraw secret grants
    E12->>E04: end affected sessions
  end
  E12-->>E24: stopped
  H->>E12: new launch or pending release
  E12-->>H: -31004 EMERGENCY_STOP
  O->>E24: resume (Administrator only)
  E24->>E12: resume, new epoch
  E12->>E21: resume event
```

The CP-16 propagation bound and FR-11.10 stop latency apply.

## Implementation as of commit a3193a5

`internal/edge` has `Gateway.Stop` and `Gateway.Resume`, which set a flag checked before the decision, at launch authorization and at release authorization; `/healthz` reports `fail-closed` with cause `emergency_stop`. There is no control API or `smcpctl stop`, so the stop can only be invoked from code and tests. In-flight calls are not cancelled, instances are not torn down and no stop event is journaled.
