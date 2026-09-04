# Treat v1 as one laboratory trust domain

All authenticated read-only and operator principals may observe every Job and download every Artifact; roles distinguish reading from control, not tenancy. The submitting principal is still audited, but v1 deliberately avoids per-owner authorization because tenant isolation would also require ownership-aware queries, retention, scheduling, and Artifact policy.
