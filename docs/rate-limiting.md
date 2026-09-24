# Connection start rate limit

`--max-rate N` is a process-local cap on connection attempts started per
second. A value of zero disables the cap. Retries are new attempts and consume
rate-limit slots; service banner reads do not.

The Python `RateLimiter` grants starts at intervals of `1 / N` seconds using
the monotonic clock. Its lock remains held during the wait so delayed event
loop wakeups do not cause queued workers to receive back-to-back grants. The
Go gate applies the same interval rule with a monotonic `time.Time` clock.

Rate and concurrency are separate controls. The rate cap controls how often
new connects begin; concurrency controls how many jobs can be in flight. The
cap applies to one process, so two scanner processes each configured at 100
starts per second can together exceed 100 starts per second.

Python and Go test the same rate, target, and port fixture at
`tests/fixtures/engine_inputs.json`. Update that fixture and both suites when
the contract changes.
