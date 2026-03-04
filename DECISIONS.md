# DECISIONS.md

Five implementation decisions made during this security review, with rationale for each,
and one alternative approach that was considered and rejected.

---

## Decision 1 — Use `crypto.randomBytes(32)` for Share Tokens

**What:** Replaced `Math.random().toString(36).slice(2, 8)` with
`randomBytes(32).toString("hex")` in `recordRepository.ts:100`.

**Why:**

`Math.random()` is a pseudo-random number generator seeded deterministically by the
JavaScript engine. It is not designed for cryptographic use and can be predicted or
reproduced given knowledge of the seed state. The old token had only ~2.1 billion
possible values (36^6 ≈ 2.18×10^9), which is feasible to brute-force offline.

`randomBytes(32)` draws from the operating system's CSPRNG (`/dev/urandom` on Linux,
`BCryptGenRandom` on Windows). It produces 32 bytes = 256 bits of entropy. The token
space is 2^256 — computationally infeasible to brute-force at any realistic scale.

`.toString("hex")` produces a 64-character lowercase string with no structure, no
embedded metadata, and no information about the record it references. This also fixes
the secondary issue of the old token embedding `recordId` in plaintext in every URL.

**Tradeoff accepted:** The token is longer in URLs (64 chars vs ~12). For a healthcare
share link this is acceptable — URL length is not a constraint, and the security gain
is the entire point of the token.

---

## Decision 2 — Set Redis TTL to 24 Hours (86400 seconds)

**What:** Added `{ EX: 86400 }` to `client.set()` in `RedisShareTokenStore.saveShare`
(`recordRepository.ts:58`).

**Why:**

A share token without a TTL is a permanent credential. If an attacker intercepts a token
(via URL history, referrer headers, log access, or MITM), they have indefinite access to
the shared record. This violates the principle of credential lifecycle management and is
incompatible with HIPAA's requirement to limit access to the minimum necessary duration.

24 hours was chosen as the TTL because:
- It gives recipients enough time to act on a shared link (open email, navigate on
  mobile, hand off to a colleague)
- It limits the attacker's window to 86,400 seconds if a token is intercepted
- Combined with one-time-use (Decision 3), the effective window after first use is zero

**Tradeoff accepted:** Links expire. A user who receives a share link and doesn't open it
within 24 hours will get a dead link. This is intentional — in a healthcare context,
expired credentials are preferable to permanent access grants. The 24h value is
configurable via code if a different product requirement emerges.

---

## Decision 3 — One-Time-Use via GET + DEL Rather Than a Revocation List

**What:** Added `redeemShare(token)` to `ShareTokenStore` (interface + both
implementations). The method performs a GET to retrieve the share, then immediately
DELetes the key, making the token invalid for any subsequent attempt.

**Why:**

A share token should be used once. After the intended recipient accesses the resource,
the token should stop working — both as a security control (prevent replay) and as a
natural extension of the "share with one person" use case.

**Alternatives considered:**
- A server-side revocation list (a separate Redis set of revoked tokens) was rejected
  because it requires active management, grows unboundedly, and must be checked on every
  lookup — the same cost as GET + DEL without the automatic cleanup benefit
- Keeping the token and marking it "used" in the stored value was rejected because
  it requires a GET + SET (more complex), and the "used" flag must be checked on every
  redemption path

GET + DEL is simple, stateless, and self-cleaning. The Redis key is its own revocation
record — if it exists, the token is valid; if it doesn't, the token has been used or
expired.

**Tradeoff accepted:** GET + DEL is not atomic. In a highly concurrent scenario, two
simultaneous requests with the same token could both GET a value before either DELetes
it, resulting in the token being redeemed twice. In production, this is addressed by
using Redis `GETDEL` (available since Redis 6.2) or a Lua script for atomicity. For
this codebase, the race window is acceptable given the expected workload, and the
improvement path is clear and documented.

---

## Decision 4 — Non-Overwritable GCS Object Names via `timestamp + randomUUID`

**What:** Changed the GCS audit object name from the static
`audit-${event.action}-${event.targetId}.json` to the unique
`` `audit/${event.action}/${event.targetId}/${Date.now()}-${randomUUID()}.json` ``
in `audit.ts:25`.

**Why:**

The static name meant that every `record_read` on `rec-100` wrote to the exact same GCS
path. The second write silently replaced the first. In a forensic investigation, this
allows an attacker who can trigger repeated accesses to erase earlier evidence of their
own activity.

The new name has three components:
- **`Date.now()`** — millisecond timestamp, gives natural chronological sort order when
  listing objects, and makes the collision window 1 millisecond per action+target pair
- **`randomUUID()`** — eliminates the 1-millisecond collision window; two events at the
  same millisecond still get different names
- **Hierarchical path** (`audit/action/targetId/...`) — makes it practical to list all
  audit events for a specific record or action type using GCS prefix queries, supporting
  forensic investigation without scanning the entire bucket

`randomUUID` is imported from `node:crypto` (built-in, no new dependency). The UUID is
v4 (random), produced by the OS CSPRNG, sufficient for this use case.

**Tradeoff accepted:** Object names are longer and GCS storage grows linearly with
audit volume. This is the correct behavior for an audit trail — storage cost is the
price of immutability. GCS Lifecycle policies can archive or delete objects after the
HIPAA retention period expires.

---

## Decision 5 — Audit Write Failure Falls Back to Stderr; Does Not Fail the Request

**What:** Wrapped the GCS `.save()` call in a `try/catch` block. On failure, emits a
structured `AUDIT_WRITE_FAILED` log to `console.error` and returns without re-throwing,
allowing the request to complete with HTTP 200.

**Why:**

The alternative (re-throwing the error → HTTP 500) would mean that a GCS outage, quota
exhaustion, or transient network error denies every user access to their own records.
In a healthcare setting, a clinician denied access to a patient record because an audit
bucket is temporarily unavailable is a patient safety risk that outweighs the audit
compliance risk.

The `AUDIT_WRITE_FAILED` structured log is observable by any monitoring system (e.g.,
Cloud Monitoring, Datadog, PagerDuty) via log-based alerting. An on-call engineer is
notified immediately and can investigate the audit pipeline failure without patients
being locked out of their records.

**Tradeoff explicitly accepted:** If GCS is consistently unavailable, audit records are
lost until the pipeline recovers. This is a conscious operational tradeoff — the system
prioritizes availability over audit completeness during infrastructure failures. In
environments with stricter compliance postures (e.g., where audit-or-fail is required),
this catch block should instead re-throw the error to block the request, and the
infrastructure team should provide a highly available audit sink.

---

## Rejected Alternative — JWT-Based Share Tokens

**What was considered:** Using signed JSON Web Tokens (JWTs) as share tokens instead of
opaque random credentials stored in Redis.

**How it would have worked:**
- On share creation, sign a JWT containing `{ recordId, createdBy, exp: now + 86400 }`
  with an HS256 or RS256 key
- On redemption, verify the signature and check `exp` — no Redis lookup required
- Revocation would require a separate denylist (a Redis set of revoked JTIs)

**Why it was rejected:**

1. **Signing key lifecycle**: JWTs require a signing key. That key must be generated,
   stored securely (e.g., in GCP Secret Manager), rotated on a schedule, and versioned
   so old tokens can still be verified. This is operational complexity that adds risk —
   a leaked signing key allows forging share tokens for any record indefinitely.

2. **Revocation requires a denylist anyway**: One-time-use JWTs still need a denylist
   to prevent replay. A denylist is Redis with more complexity — we end up needing Redis
   regardless, and now we also need a signing key.

3. **Token payload is not secret**: JWTs are base64-encoded, not encrypted. The
   `recordId` in the payload is readable by anyone who intercepts the URL without any
   cryptographic attack. The opaque random token leaks nothing about the resource it
   references.

4. **No benefit for this use case**: The stateless verification benefit of JWTs is
   valuable at scale when avoiding database lookups is a bottleneck. For a share token
   that is redeemed once, the Redis GET is a single cheap O(1) operation. There is no
   performance problem to solve.

**Conclusion:** The opaque random token in Redis is simpler, safer (no key management),
leaks no information, and supports revocation natively via key deletion. JWT complexity
is justified in session management or multi-service authentication contexts — not here.
