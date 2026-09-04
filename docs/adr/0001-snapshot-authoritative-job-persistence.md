# Use snapshots as the authoritative Job state

Job persistence uses the `jobs` snapshot as authoritative state, while `job_events` is an append-only audit and observation stream updated in the same transaction. We deliberately do not rebuild Jobs by replaying events: SSE resumption and auditability need ordered events, but Milestone 1 does not justify the projection, replay, and event-versioning complexity of event sourcing.
