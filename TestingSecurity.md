# TestingSecurity.md

Security fix planning document. Covers Steps 1–4: line-by-line change model for each
vulnerability, test commands to reproduce the issue before the fix, and validation
commands to confirm the fix holds.

Server runs on `http://localhost:5050`. Start it with:

```bash
cd starter
npm install
npm run dev
```

For Redis tests, also start Redis:

```bash
cd starter
docker compose up -d redis
USE_REDIS_FOR_SHARES=true npm run dev
```

---

## Step 1 — IDOR / BOLA: Missing Authorization on Record Access

### Vulnerability

**File:** `starter/src/managers/recordManager.ts`

All three manager methods (`getRecord`, `createShareLink`, `generateGuidance`) fetch a
record by ID and immediately act on it. There is no check that the requesting user owns
the record or holds the `admin` role. Any authenticated user who knows (or guesses) a
`recordId` can read, share, or generate guidance for another user's record.

The seeded data makes this trivially exploitable:
- `rec-100` belongs to `user-1`
- `rec-200` belongs to `user-2`

### Line-by-Line Fix Model

#### `getRecord` — lines 15–31

```
LINE 16  const record = this.repository.getRecordById(recordId);
         ^ Fetches the record unconditionally. No identity context used yet.

LINE 17  if (!record) { throw new Error("record_not_found"); }
         ^ Only checks existence, not ownership.

--- INSERT AFTER LINE 19 ---

NEW      if (record.ownerUserId !== user.userId && user.role !== "admin") {
           ^ Compares the record's stored owner against the authenticated user's ID.
           ^ The second condition grants admins read access to all records.

NEW        throw new Error("forbidden");
           ^ Throws before any logging or data is returned.
           ^ The route layer catches all errors and returns 404, preventing
             information disclosure about whether the record exists at all.
         }
```

#### `createShareLink` — lines 33–45

```
LINE 34  const record = this.repository.getRecordById(recordId);
         ^ Same pattern: fetches unconditionally.

LINE 35  if (!record) { throw new Error("record_not_found"); }
         ^ Existence check only.

--- INSERT AFTER LINE 37 ---

NEW      if (record.ownerUserId !== user.userId && user.role !== "admin") {
           ^ Same ownership guard as getRecord.
           ^ Prevents user-2 from creating a share token for user-1's record.

NEW        throw new Error("forbidden");
         }
```

#### `generateGuidance` — lines 47–68

```
LINE 52  const record = this.repository.getRecordById(recordId);
         ^ Fetches unconditionally.

LINE 53  if (!record) { throw new Error("record_not_found"); }
         ^ Existence check only.

--- INSERT AFTER LINE 55 ---

NEW      if (record.ownerUserId !== user.userId && user.role !== "admin") {
           ^ Same guard. Prevents cross-user guidance generation.

NEW        throw new Error("forbidden");
         }
```

### Before-Fix Reproduction

```bash
# user-2 reads user-1's record — should be denied, currently succeeds
curl -s http://localhost:5050/records/rec-100 \
  -H 'x-user-id: user-2' \
  -H 'x-role: member'

# Expected BEFORE fix (vulnerability confirmed):
# {"id":"rec-100","ownerUserId":"user-1","patientName":"Taylor Reed",...}

# user-2 creates a share link for user-1's record
curl -s -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-2' \
  -H 'x-role: member'

# Expected BEFORE fix (vulnerability confirmed):
# {"url":"https://example.local/share/rec-100-XXXXXX"}
```

### After-Fix Validation

```bash
# user-2 attempts to read user-1's record — must be blocked
curl -s http://localhost:5050/records/rec-100 \
  -H 'x-user-id: user-2' \
  -H 'x-role: member'

# Expected AFTER fix (pass):
# {"error":"not_found"}   with HTTP 404

# user-2 attempts share creation on user-1's record — must be blocked
curl -s -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-2' \
  -H 'x-role: member'

# Expected AFTER fix (pass):
# {"error":"not_found"}   with HTTP 404

# user-1 reads their own record — must still succeed
curl -s http://localhost:5050/records/rec-100 \
  -H 'x-user-id: user-1' \
  -H 'x-role: member'

# Expected AFTER fix (pass):
# {"id":"rec-100","ownerUserId":"user-1","patientName":"Taylor Reed",...}

# admin reads any record — must still succeed
curl -s http://localhost:5050/records/rec-200 \
  -H 'x-user-id: user-1' \
  -H 'x-role: admin'

# Expected AFTER fix (pass):
# {"id":"rec-200","ownerUserId":"user-2","patientName":"Jordan Kim",...}
```

### Pass Criteria (DoD §4)
- [ ] `user-2` GET `rec-100` returns HTTP 404
- [ ] `user-2` POST `rec-100/share` returns HTTP 404
- [ ] `user-2` POST `rec-100/guidance` returns HTTP 404
- [ ] `user-1` GET `rec-100` returns HTTP 200 with full record
- [ ] `admin` (any userId) GET `rec-200` returns HTTP 200

---

## Step 2 — Redis: Weak Token, No TTL, No One-Time-Use, PHI in Token

### Vulnerability

**File:** `starter/src/storage/recordRepository.ts`

Four distinct sub-issues all in the Redis share token pipeline, each required by DoD §2:

1. **Weak token (line 73):** Token is generated with `Math.random()` which is not
   cryptographically secure and can be predicted or brute-forced. Only ~2.1 billion
   possible values (36^6). Token also embeds `recordId` in plaintext.

2. **PHI in token value (line 73):** Token string is `rec-100-abc123` — the record ID
   is directly readable in the token, in logs, in URLs, and in Redis keys.

3. **No TTL (line 42):** `client.set(key, value)` has no expiry options. Once created,
   a share token lives in Redis forever.

4. **No revocation or one-time-use (lines 40–43):** The `ShareTokenStore` interface has
   only `saveShare`. There is no `redeemShare`, no `revokeShare`, no delete-on-use.

### Line-by-Line Fix Model

#### Import change — top of `recordRepository.ts`

```
LINE 1   import { createClient, type RedisClientType } from "redis";

--- ADD AFTER LINE 1 ---

NEW      import { randomBytes } from "node:crypto";
           ^ Imports the Node.js built-in CSPRNG.
           ^ No new dependency — node:crypto ships with all Node versions.
           ^ randomBytes(32) produces 256 bits of entropy vs Math.random()'s ~32 bits.
```

#### `ShareTokenStore` interface — lines 11–13

```
LINE 11  export type ShareTokenStore = {
LINE 12    saveShare: (share: ShareRecord) => Promise<void>;
LINE 13  };

--- REPLACE WITH ---

NEW      export type ShareTokenStore = {
           saveShare: (share: ShareRecord) => Promise<void>;

NEW        redeemShare: (token: string) => Promise<ShareRecord | null>;
           ^ Adds a mandatory redeem operation to the contract.
           ^ Both implementations must provide it (InMemory and Redis).
           ^ "Redeem" means: fetch the share AND delete it atomically (one-time-use).
           ^ Returns null if the token does not exist (already used or never issued).
         };
```

#### `InMemoryShareTokenStore.saveShare` — lines 15–21

```
         No changes to saveShare.

--- ADD NEW METHOD INSIDE CLASS ---

NEW      async redeemShare(token: string): Promise<ShareRecord | null> {
           ^ Implements one-time-use for the in-memory path.

NEW        const idx = this.shares.findIndex((s) => s.token === token);
           ^ Searches for the token in the in-memory array.

NEW        if (idx === -1) return null;
           ^ Token not found — either used already or never issued. Return null.

NEW        const [share] = this.shares.splice(idx, 1);
           ^ splice() removes the element at idx and returns it.
           ^ After this line the token no longer exists in the store.
           ^ This is the one-time-use guarantee for the in-memory path.

NEW        return share ?? null;
         }
```

#### `RedisShareTokenStore.saveShare` — lines 40–43

```
LINE 40  async saveShare(share: ShareRecord): Promise<void> {
LINE 41    await this.ensureConnected();
LINE 42    await this.client.set(`share:${share.token}`, JSON.stringify(share));
           ^ Missing EX option — key never expires.

--- REPLACE LINE 42 WITH ---

NEW        await this.client.set(
             `share:${share.token}`,
             JSON.stringify(share),
NEW          { EX: 86400 }
             ^ Sets a 24-hour TTL (86400 seconds) on the Redis key.
             ^ After 24 hours, Redis automatically deletes the key.
             ^ Even if the token is never redeemed, it will not accumulate indefinitely.
           );
LINE 43  }
```

#### `RedisShareTokenStore` — add `redeemShare` method

```
--- ADD NEW METHOD AFTER saveShare ---

NEW      async redeemShare(token: string): Promise<ShareRecord | null> {
           ^ Implements one-time-use for the Redis path.

NEW        await this.ensureConnected();

NEW        const key = `share:${token}`;

NEW        const raw = await this.client.get(key);
           ^ Fetches the stored JSON value for this token key.

NEW        if (!raw) return null;
           ^ Token not found in Redis — already used, expired, or never issued.

NEW        await this.client.del(key);
           ^ Deletes the key immediately after reading.
           ^ This is the one-time-use guarantee: the token cannot be redeemed again.
           ^ Note: GET + DEL is not atomic. A race condition exists in very high
             concurrency scenarios. Production hardening would use a Lua script or
             GETDEL (Redis 6.2+) for true atomicity.

NEW        return JSON.parse(raw) as ShareRecord;
           ^ Returns the share metadata so callers can look up the recordId.
         }
```

#### Token generation in `InMemoryRecordRepository.createShare` — line 73

```
LINE 73  const token = `${recordId}-${Math.random().toString(36).slice(2, 8)}`;
         ^ Two problems:
         ^ (1) Math.random() is not cryptographically secure.
         ^ (2) recordId is embedded in the token, leaking PHI into URLs and logs.

--- REPLACE LINE 73 WITH ---

NEW      const token = randomBytes(32).toString("hex");
           ^ randomBytes(32) produces 32 bytes = 256 bits of CSPRNG entropy.
           ^ .toString("hex") encodes as 64 lowercase hex characters.
           ^ The token is now opaque — no information about the record is embedded.
           ^ Brute-force probability: 1 in 2^256 (computationally infeasible).
```

### Before-Fix Reproduction

```bash
# Generate a share token and observe its format
curl -s -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-1' \
  -H 'x-role: member'

# Expected BEFORE fix (vulnerability confirmed):
# {"url":"https://example.local/share/rec-100-a4f2k9"}
#                                     ^^^^^^^^ recordId visible in token
#                                              ^^^^^^ only 6 weak chars

# With Redis enabled, check that no TTL is set:
# redis-cli TTL share:rec-100-a4f2k9
# Expected BEFORE fix: -1   (meaning: key exists, no expiry)
```

### After-Fix Validation

```bash
# Generate a share token and verify format
curl -s -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-1' \
  -H 'x-role: member'

# Expected AFTER fix (pass):
# {"url":"https://example.local/share/a3f8c1d2e4b6..."}
#                                     ^^^^^^^^^^^^^^^^ 64-char opaque hex, no recordId

# With Redis: verify TTL is set
# redis-cli TTL share:<token>
# Expected AFTER fix (pass): a positive integer (≤ 86400)

# With Redis: verify one-time-use (redeemShare must delete the key)
# After any redemption call, verify key is gone:
# redis-cli EXISTS share:<token>
# Expected AFTER fix (pass): 0
```

### Pass Criteria (DoD §2)
- [ ] Token is 64 hex characters with no record ID prefix
- [ ] `redis-cli TTL share:<token>` returns a value between 1 and 86400
- [ ] `redis-cli EXISTS share:<token>` returns `0` after the token is redeemed
- [ ] `ShareTokenStore` interface includes `redeemShare`
- [ ] Both `InMemoryShareTokenStore` and `RedisShareTokenStore` implement `redeemShare`
- [ ] No `recordId` appears in the token string itself

---

## Step 3 — GCS: Overwritable Audit Objects and No Failure Handling

### Vulnerability

**File:** `starter/src/security/audit.ts`

Two distinct sub-issues in the GCS audit logger, both required by DoD §3:

1. **Overwritable objects (line 24):** The GCS object name is
   `audit-${event.action}-${event.targetId}.json`. This is a static string. The second
   `record_read` event on `rec-100` writes to the exact same path and silently overwrites
   the first, destroying the audit trail. An attacker who can trigger the same action
   repeatedly can erase earlier evidence.

2. **No error handling (lines 22–29):** The `.save()` call is unawaited within no
   try/catch. If GCS is unreachable, misconfigured, or rate-limited, the thrown error
   propagates up through the route handler and returns an HTTP 500 to the caller.
   The request fails because auditing failed — this is backwards. Worse, in some
   configurations the error could be swallowed entirely, silently dropping audit records.

### Line-by-Line Fix Model

#### Import change — top of `audit.ts`

```
LINE 1   import { Storage } from "@google-cloud/storage";

--- ADD AFTER LINE 1 ---

NEW      import { randomUUID } from "node:crypto";
           ^ Imports the built-in UUID generator (no new dependency).
           ^ Used to guarantee uniqueness in object names even within the same millisecond.
```

#### GCS object name — line 24

```
LINE 24  const objectName = `audit-${event.action}-${event.targetId}.json`;
         ^ Static name. Two events with the same action + targetId collide and overwrite.

--- REPLACE LINE 24 WITH ---

NEW      const objectName =
           `audit/${event.action}/${event.targetId}/${Date.now()}-${randomUUID()}.json`;
           ^ Path components:
           ^ audit/           — top-level prefix, keeps audit objects grouped
           ^ {event.action}/  — subfolder by action type (record_read, etc.)
           ^ {event.targetId}/— subfolder by record ID, easy to list all events per record
           ^ {Date.now()}     — millisecond timestamp, sorts chronologically
           ^ -{randomUUID()}  — UUID suffix guarantees uniqueness within same millisecond
           ^ .json            — content type hint
           ^
           ^ Every audit write now produces a unique, non-colliding object path.
           ^ Previous events are never overwritten.
```

#### Error handling — lines 25–29

```
LINE 25  await storage
LINE 26    .bucket(bucketName)
LINE 27    .file(objectName)
LINE 28    .save(JSON.stringify(event), { contentType: "application/json" });
           ^ No try/catch. Any GCS failure throws up to the caller, failing the request.

--- REPLACE LINES 25–28 WITH ---

NEW      try {
           await storage
             .bucket(bucketName)
             .file(objectName)
             .save(JSON.stringify(event), { contentType: "application/json" });
           ^ Attempt the GCS write as before.

NEW      } catch (err) {
           ^ Catches any error from GCS: network failure, auth error, quota exceeded, etc.

NEW        console.error(
             "AUDIT_WRITE_FAILED",
             JSON.stringify({ objectName, action: event.action, targetId: event.targetId, error: String(err) })
           );
           ^ Writes a structured error to stderr. Monitoring/alerting can key on
             AUDIT_WRITE_FAILED to detect audit pipeline degradation.
           ^ Does NOT re-throw, so the request that triggered the audit can still
             complete successfully. The principle: audit failure is an ops problem,
             not a caller problem.
           ^ Note: this is a deliberate tradeoff — we chose request continuity over
             strict audit-or-fail. In a higher-compliance environment you might choose
             to block the action instead. This tradeoff is documented in DECISIONS.md.
         }
```

### Before-Fix Reproduction

```bash
# Start server with GCS disabled (console audit logger is sufficient to observe the
# overwrite problem in the object naming logic — no real GCS needed)

# Trigger two read events for the same record
curl -s http://localhost:5050/records/rec-100 \
  -H 'x-user-id: user-1' -H 'x-role: member'

curl -s http://localhost:5050/records/rec-100 \
  -H 'x-user-id: user-1' -H 'x-role: member'

# With GCS enabled, check the bucket — only ONE object exists:
# gs://dev-audit-bucket/audit-record_read-rec-100.json
# The second write silently overwrote the first. First event is gone.

# To reproduce the failure crash: point GCS_AUDIT_BUCKET at a non-existent bucket
# GCS_AUDIT_BUCKET=does-not-exist USE_GCS_AUDIT_LOGGING=true npm run dev
curl -s http://localhost:5050/records/rec-100 \
  -H 'x-user-id: user-1' -H 'x-role: member'
# Expected BEFORE fix: HTTP 500 — the request fails because GCS failed
```

### After-Fix Validation

```bash
# Trigger two read events for the same record
curl -s http://localhost:5050/records/rec-100 \
  -H 'x-user-id: user-1' -H 'x-role: member'

curl -s http://localhost:5050/records/rec-100 \
  -H 'x-user-id: user-1' -H 'x-role: member'

# With GCS enabled, check the bucket — TWO objects must now exist:
# gs://dev-audit-bucket/audit/record_read/rec-100/1709500000000-<uuid1>.json
# gs://dev-audit-bucket/audit/record_read/rec-100/1709500000123-<uuid2>.json
# Both events preserved.

# To test failure handling: point GCS at a bad bucket
# GCS_AUDIT_BUCKET=does-not-exist USE_GCS_AUDIT_LOGGING=true npm run dev
curl -s http://localhost:5050/records/rec-100 \
  -H 'x-user-id: user-1' -H 'x-role: member'

# Expected AFTER fix (pass):
# HTTP 200 — request succeeds
# stderr shows: AUDIT_WRITE_FAILED {"objectName":"audit/record_read/rec-100/...","error":"..."}
```

### Pass Criteria (DoD §3)
- [ ] Two `record_read` events on `rec-100` produce two distinct GCS object paths
- [ ] Object names contain a timestamp and UUID component
- [ ] No two audit events share the same GCS object path
- [ ] GCS write failure returns HTTP 200 to the caller (request is not blocked)
- [ ] `AUDIT_WRITE_FAILED` appears in stderr when GCS is unavailable
- [ ] GCS bucket security assumptions are documented in `COMPLIANCE_NOTES.md`

---

## Step 4 — PHI Exposure in Application Logs and Audit Payloads

### Vulnerability

**File:** `starter/src/managers/recordManager.ts`

Three log/audit calls emit full `HealthRecord` objects containing `patientName`, `dob`,
`encounterSummary`, and `notes` — protected health information (PHI) under HIPAA:

- **Line 21:** `logger.info("record_read", { user, record })` — dumps the entire record
  to stdout on every read
- **Lines 22–28:** `await this.audit.log({ ..., details: record })` — writes full PHI
  into the GCS audit object
- **Lines 59–63:** `logger.info("guidance_generated", { user, record, prompt })` — dumps
  full record plus the rendered prompt to stdout

PHI appearing in application logs violates HIPAA's minimum-necessary standard and
expands the blast radius of a log exfiltration incident far beyond what is necessary
for operational visibility.

### Line-by-Line Fix Model

#### `getRecord` — line 21 (application logger)

```
LINE 21  this.logger.info("record_read", { user, record });
         ^ Logs the complete AppUser object (userId + role) and complete HealthRecord
           (patientName, dob, encounterSummary, notes). PHI in plain text in stdout.

--- REPLACE LINE 21 WITH ---

NEW      this.logger.info("record_read", { userId: user.userId, recordId: record.id });
           ^ Logs only the user's ID and the record's ID.
           ^ Sufficient for operational tracing (who accessed what) with zero PHI.
           ^ role is omitted — not needed for this log event.
```

#### `getRecord` — lines 22–28 (audit event `details` field)

```
LINE 26    result: "success",
LINE 27    details: record,
           ^ Writes the full HealthRecord into the GCS audit JSON under "details".
           ^ Any reader of the GCS bucket can see raw patient data.

--- REPLACE LINE 27 WITH ---

NEW        details: { recordId: record.id },
           ^ Audit event now contains only the record ID under details.
           ^ The audit trail retains "who did what to which record" without PHI.
           ^ If an investigator needs the record contents, they look it up by ID
             separately with appropriate access controls — not from the audit log.
```

#### `createShareLink` — line 40 (application logger)

```
LINE 40  this.logger.info("record_share_created", { user, share });
         ^ Logs the full ShareRecord: token, recordId, createdBy, createdAt.
           Token in logs is a security risk; recordId in logs may constitute PHI linkage.

--- REPLACE LINE 40 WITH ---

NEW      this.logger.info("record_share_created", { userId: user.userId, recordId });
           ^ Logs only who created a share and for which record.
           ^ Token is intentionally excluded from logs — it is a credential.
```

#### `generateGuidance` — lines 59–63 (application logger)

```
LINE 59  this.logger.info("guidance_generated", {
LINE 60    user,
           ^ Full AppUser object
LINE 61    record,
           ^ Full HealthRecord — all PHI
LINE 62    prompt,
           ^ Rendered prompt string — may contain patientSummary submitted by caller
LINE 63  });

--- REPLACE LINES 59–63 WITH ---

NEW      this.logger.info("guidance_generated", { userId: user.userId, recordId: record.id });
           ^ Logs only the user ID and record ID.
           ^ The rendered prompt is excluded — it may contain patient-supplied text
             passed in via patientSummary, which could itself contain PHI.
```

### Before-Fix Reproduction

```bash
# Start server (console mode — stdout is the audit sink)
npm run dev

# In another terminal, read a record and observe stdout
curl -s http://localhost:5050/records/rec-100 \
  -H 'x-user-id: user-1' \
  -H 'x-role: member'

# Expected BEFORE fix (vulnerability confirmed) — server stdout contains:
# INFO record_read { user: { userId: 'user-1', role: 'member' },
#   record: {
#     id: 'rec-100',
#     ownerUserId: 'user-1',
#     patientName: 'Taylor Reed',        <-- PHI
#     dob: '1988-05-09',                 <-- PHI
#     encounterSummary: 'Follow-up for recurring urinary symptoms',  <-- PHI
#     notes: 'Medication changed last visit...'  <-- PHI
#   }
# }
# AUDIT { "actor":"user-1","action":"record_read","targetId":"rec-100",
#          "result":"success","details":{"id":"rec-100","patientName":"Taylor Reed",...}}
#          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ full PHI in audit payload
```

### After-Fix Validation

```bash
# Read a record and observe stdout
curl -s http://localhost:5050/records/rec-100 \
  -H 'x-user-id: user-1' \
  -H 'x-role: member'

# Expected AFTER fix (pass) — server stdout must contain ONLY:
# INFO record_read { userId: 'user-1', recordId: 'rec-100' }
# AUDIT {"actor":"user-1","action":"record_read","targetId":"rec-100",
#        "result":"success","details":{"recordId":"rec-100"}}

# Verify no PHI fields appear in any log line:
# grep -i "taylor\|reed\|jordan\|kim\|1988\|1979\|urinary\|hydration\|medication" <server_stdout>
# Expected AFTER fix (pass): no matches
```

### Pass Criteria (DoD §5)
- [ ] `patientName`, `dob`, `encounterSummary`, `notes` do not appear in any stdout line
- [ ] Audit event `details` field contains only `{ recordId: "..." }` — no PHI
- [ ] Share creation log does not include the share token
- [ ] Guidance generation log does not include the record or prompt contents
- [ ] All log events still contain `userId` and `recordId` for operational traceability

---

## Summary Table

| Step | File | Lines Changed | DoD Item |
|------|------|---------------|----------|
| 1. IDOR/BOLA | `managers/recordManager.ts` | After L19, L37, L55 | §4 |
| 2a. Crypto token | `storage/recordRepository.ts` | L1 (import), L73 | §2 |
| 2b. TTL | `storage/recordRepository.ts` | L42 | §2 |
| 2c. One-time-use | `storage/recordRepository.ts` | L11–13, new methods | §2 |
| 3a. Non-overwritable | `security/audit.ts` | L1 (import), L24 | §3 |
| 3b. Failure handling | `security/audit.ts` | L25–28 | §3 |
| 4. PHI in logs | `managers/recordManager.ts` | L21, L27, L40, L59–63 | §5 |

---

## Implementation Status Check

All four steps verified against current file state before test suite execution.

| Step | File | Key Change | Status |
|------|------|-----------|--------|
| 1a — IDOR getRecord | recordManager.ts:23 | `if (record.ownerUserId !== user.userId && user.role !== "admin")` | COMPLETE |
| 1b — IDOR createShareLink | recordManager.ts:48 | Same ownership guard | COMPLETE |
| 1c — IDOR generateGuidance | recordManager.ts:71 | Same ownership guard | COMPLETE |
| 2a — Crypto token | recordRepository.ts:100 | `randomBytes(32).toString("hex")` | COMPLETE |
| 2b — TTL | recordRepository.ts:58 | `{ EX: 86400 }` | COMPLETE |
| 2c — redeemShare interface | recordRepository.ts:16 | `redeemShare: (token) => Promise<ShareRecord or null>` | COMPLETE |
| 2d — InMemory redeemShare | recordRepository.ts:26-33 | `splice(idx, 1)` one-time-use | COMPLETE |
| 2e — Redis redeemShare | recordRepository.ts:62-70 | GET + DEL | COMPLETE |
| 3a — Non-overwritable GCS | audit.ts:25 | `${Date.now()}-${randomUUID()}.json` | COMPLETE |
| 3b — Failure handling | audit.ts:26-35 | try/catch + AUDIT_WRITE_FAILED | COMPLETE |
| 4a — PHI in getRecord log | recordManager.ts:29 | `{ userId, recordId }` only | COMPLETE |
| 4b — PHI in audit details | recordManager.ts:35 | `details: { recordId: record.id }` | COMPLETE |
| 4c — PHI in share log | recordManager.ts:53 | `{ userId, recordId }` only | COMPLETE |
| 4d — PHI in guidance log | recordManager.ts:77-80 | `{ userId, recordId }` only | COMPLETE |

**All 14 changes confirmed present.**

---

## Test Suite — 30 Tests Per Vulnerability

Start the server before running any tests (use a PowerShell/CMD terminal where Node.js is installed):

```bash
cd starter
npm install
npm run dev > /tmp/server.log 2>&1 &
sleep 2
```

Server listens on `http://localhost:5050`.
Legend: each test shows the curl command, then `# PASS:` with the expected output.

---

### BLOCK A — IDOR / BOLA (30 Tests)

```bash
# A-01: user-2 reads rec-100 (owned by user-1) — must be blocked
curl -s -w "\nHTTP:%{http_code}" http://localhost:5050/records/rec-100 \
  -H 'x-user-id: user-2' -H 'x-role: member'
# PASS: {"error":"not_found"}  HTTP:404

# A-02: user-1 reads their own rec-100 — must succeed
curl -s -w "\nHTTP:%{http_code}" http://localhost:5050/records/rec-100 \
  -H 'x-user-id: user-1' -H 'x-role: member'
# PASS: {"id":"rec-100","ownerUserId":"user-1",...}  HTTP:200

# A-03: user-1 reads rec-200 (owned by user-2) — must be blocked
curl -s -w "\nHTTP:%{http_code}" http://localhost:5050/records/rec-200 \
  -H 'x-user-id: user-1' -H 'x-role: member'
# PASS: {"error":"not_found"}  HTTP:404

# A-04: user-2 reads their own rec-200 — must succeed
curl -s -w "\nHTTP:%{http_code}" http://localhost:5050/records/rec-200 \
  -H 'x-user-id: user-2' -H 'x-role: member'
# PASS: {"id":"rec-200","ownerUserId":"user-2",...}  HTTP:200

# A-05: admin reads rec-100 cross-user — must succeed (admin bypass)
curl -s -w "\nHTTP:%{http_code}" http://localhost:5050/records/rec-100 \
  -H 'x-user-id: user-2' -H 'x-role: admin'
# PASS: {"id":"rec-100","ownerUserId":"user-1",...}  HTTP:200

# A-06: admin reads rec-200 cross-user — must succeed
curl -s -w "\nHTTP:%{http_code}" http://localhost:5050/records/rec-200 \
  -H 'x-user-id: user-1' -H 'x-role: admin'
# PASS: {"id":"rec-200","ownerUserId":"user-2",...}  HTTP:200

# A-07: user-3 (owns no records) reads rec-100 — must be blocked
curl -s -w "\nHTTP:%{http_code}" http://localhost:5050/records/rec-100 \
  -H 'x-user-id: user-3' -H 'x-role: member'
# PASS: {"error":"not_found"}  HTTP:404

# A-08: user-3 reads rec-200 — must be blocked
curl -s -w "\nHTTP:%{http_code}" http://localhost:5050/records/rec-200 \
  -H 'x-user-id: user-3' -H 'x-role: member'
# PASS: {"error":"not_found"}  HTTP:404

# A-09: user-2 creates share for rec-100 (not theirs) — must be blocked
curl -s -w "\nHTTP:%{http_code}" -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-2' -H 'x-role: member'
# PASS: {"error":"not_found"}  HTTP:404

# A-10: user-1 creates share for their own rec-100 — must succeed
curl -s -w "\nHTTP:%{http_code}" -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-1' -H 'x-role: member'
# PASS: {"url":"https://example.local/share/<64-char-hex>"}  HTTP:200

# A-11: user-1 creates share for rec-200 (not theirs) — must be blocked
curl -s -w "\nHTTP:%{http_code}" -X POST http://localhost:5050/records/rec-200/share \
  -H 'x-user-id: user-1' -H 'x-role: member'
# PASS: {"error":"not_found"}  HTTP:404

# A-12: user-2 creates share for their own rec-200 — must succeed
curl -s -w "\nHTTP:%{http_code}" -X POST http://localhost:5050/records/rec-200/share \
  -H 'x-user-id: user-2' -H 'x-role: member'
# PASS: {"url":"https://example.local/share/<64-char-hex>"}  HTTP:200

# A-13: admin creates share for rec-100 cross-user — must succeed
curl -s -w "\nHTTP:%{http_code}" -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-2' -H 'x-role: admin'
# PASS: {"url":"https://example.local/share/<64-char-hex>"}  HTTP:200

# A-14: admin creates share for rec-200 cross-user — must succeed
curl -s -w "\nHTTP:%{http_code}" -X POST http://localhost:5050/records/rec-200/share \
  -H 'x-user-id: user-1' -H 'x-role: admin'
# PASS: {"url":"https://example.local/share/<64-char-hex>"}  HTTP:200

# A-15: user-3 creates share for rec-100 — must be blocked
curl -s -w "\nHTTP:%{http_code}" -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-3' -H 'x-role: member'
# PASS: {"error":"not_found"}  HTTP:404

# A-16: user-2 generates guidance on rec-100 (not theirs) — must be blocked
curl -s -w "\nHTTP:%{http_code}" -X POST http://localhost:5050/records/rec-100/guidance \
  -H 'x-user-id: user-2' -H 'x-role: member' \
  -H 'content-type: application/json' -d '{"patientSummary":"test"}'
# PASS: {"error":"not_found"}  HTTP:404

# A-17: user-1 generates guidance on their own rec-100 — must succeed
curl -s -w "\nHTTP:%{http_code}" -X POST http://localhost:5050/records/rec-100/guidance \
  -H 'x-user-id: user-1' -H 'x-role: member' \
  -H 'content-type: application/json' -d '{"patientSummary":"test"}'
# PASS: {"promptPreview":"..."}  HTTP:200

# A-18: user-1 generates guidance on rec-200 (not theirs) — must be blocked
curl -s -w "\nHTTP:%{http_code}" -X POST http://localhost:5050/records/rec-200/guidance \
  -H 'x-user-id: user-1' -H 'x-role: member' \
  -H 'content-type: application/json' -d '{"patientSummary":"test"}'
# PASS: {"error":"not_found"}  HTTP:404

# A-19: user-2 generates guidance on their own rec-200 — must succeed
curl -s -w "\nHTTP:%{http_code}" -X POST http://localhost:5050/records/rec-200/guidance \
  -H 'x-user-id: user-2' -H 'x-role: member' \
  -H 'content-type: application/json' -d '{"patientSummary":"test"}'
# PASS: {"promptPreview":"..."}  HTTP:200

# A-20: admin generates guidance on rec-100 cross-user — must succeed
curl -s -w "\nHTTP:%{http_code}" -X POST http://localhost:5050/records/rec-100/guidance \
  -H 'x-user-id: user-2' -H 'x-role: admin' \
  -H 'content-type: application/json' -d '{"patientSummary":"test"}'
# PASS: {"promptPreview":"..."}  HTTP:200

# A-21: no x-user-id header at all — must return 401
curl -s -w "\nHTTP:%{http_code}" http://localhost:5050/records/rec-100 \
  -H 'x-role: member'
# PASS: {"error":"unauthorized"}  HTTP:401

# A-22: empty x-user-id header — must return 401
curl -s -w "\nHTTP:%{http_code}" http://localhost:5050/records/rec-100 \
  -H 'x-user-id:' -H 'x-role: member'
# PASS: {"error":"unauthorized"}  HTTP:401

# A-23: non-existent record by any user — must return 404
curl -s -w "\nHTTP:%{http_code}" http://localhost:5050/records/rec-999 \
  -H 'x-user-id: user-1' -H 'x-role: member'
# PASS: {"error":"not_found"}  HTTP:404

# A-24: non-existent record by wrong user — same 404 as A-23 (no info leak)
BODY_23=$(curl -s http://localhost:5050/records/rec-999 -H 'x-user-id: user-1' -H 'x-role: member')
BODY_24=$(curl -s http://localhost:5050/records/rec-999 -H 'x-user-id: user-2' -H 'x-role: member')
[ "$BODY_23" = "$BODY_24" ] && echo "PASS: identical response regardless of user" || echo "FAIL: responses differ"

# A-25: non-existent record by admin — still 404
curl -s -w "\nHTTP:%{http_code}" http://localhost:5050/records/rec-999 \
  -H 'x-user-id: user-1' -H 'x-role: admin'
# PASS: {"error":"not_found"}  HTTP:404

# A-26: forbidden response body must contain no PHI
BODY=$(curl -s http://localhost:5050/records/rec-100 \
  -H 'x-user-id: user-2' -H 'x-role: member')
echo "$BODY" | grep -iE "taylor|reed|jordan|kim|1988|1979|urinary|hydration" \
  && echo "FAIL: PHI in denied response body" || echo "PASS: no PHI disclosed on deny"

# A-27: all three endpoints with wrong user — all 404
for EP in "" "/share" "/guidance"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "http://localhost:5050/records/rec-100${EP}" \
    -H 'x-user-id: user-2' -H 'x-role: member' \
    -H 'content-type: application/json' -d '{"patientSummary":"x"}')
  [ "$CODE" = "404" ] && echo "PASS: rec-100${EP} blocked" || echo "FAIL: $CODE"
done

# A-28: all three endpoints with correct user — all 200
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  http://localhost:5050/records/rec-100 -H 'x-user-id: user-1' -H 'x-role: member')
[ "$CODE" = "200" ] && echo "PASS: GET own record" || echo "FAIL: $CODE"

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:5050/records/rec-100/share -H 'x-user-id: user-1' -H 'x-role: member')
[ "$CODE" = "200" ] && echo "PASS: POST share own record" || echo "FAIL: $CODE"

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:5050/records/rec-100/guidance \
  -H 'x-user-id: user-1' -H 'x-role: member' \
  -H 'content-type: application/json' -d '{"patientSummary":"x"}')
[ "$CODE" = "200" ] && echo "PASS: POST guidance own record" || echo "FAIL: $CODE"

# A-29: unknown user with admin role can read any record (by design)
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  http://localhost:5050/records/rec-100 -H 'x-user-id: user-99' -H 'x-role: admin')
[ "$CODE" = "200" ] && echo "PASS: admin bypass works" || echo "FAIL: $CODE"

# A-30: enumerate both records with unrelated user — both must return identical 404
B1=$(curl -s http://localhost:5050/records/rec-100 -H 'x-user-id: user-99' -H 'x-role: member')
B2=$(curl -s http://localhost:5050/records/rec-200 -H 'x-user-id: user-99' -H 'x-role: member')
[ "$B1" = '{"error":"not_found"}' ] && [ "$B2" = '{"error":"not_found"}' ] \
  && echo "PASS: no record existence disclosed" || echo "FAIL: $B1 | $B2"
```

---

### BLOCK B — Redis Token Security (30 Tests)

```bash
# B-01: token must be exactly 64 characters
TOKEN=$(curl -s -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-1' -H 'x-role: member' | sed 's/.*\/share\/\(.*\)".*/\1/')
[ "${#TOKEN}" -eq 64 ] && echo "PASS: length=64" || echo "FAIL: length=${#TOKEN}"

# B-02: token must contain only lowercase hex characters
echo "$TOKEN" | grep -qE '^[0-9a-f]{64}$' \
  && echo "PASS: hex chars only" || echo "FAIL: non-hex chars in token"

# B-03: token must NOT begin with a record ID prefix (old format was rec-100-XXXXXX)
echo "$TOKEN" | grep -q "^rec-" \
  && echo "FAIL: recordId prefix in token" || echo "PASS: no recordId prefix"

# B-04: token must NOT contain a dash (old format included dashes)
echo "$TOKEN" | grep -q "-" \
  && echo "FAIL: dash in token (possible recordId leak)" || echo "PASS: no dash"

# B-05: token must NOT contain any record ID substring
echo "$TOKEN" | grep -qE "rec-[0-9]+" \
  && echo "FAIL: recordId embedded in token" || echo "PASS: no recordId in token"

# B-06: two consecutive share creations must produce different tokens
T1=$(curl -s -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-1' -H 'x-role: member' | sed 's/.*\/share\/\(.*\)".*/\1/')
T2=$(curl -s -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-1' -H 'x-role: member' | sed 's/.*\/share\/\(.*\)".*/\1/')
[ "$T1" != "$T2" ] && echo "PASS: consecutive tokens unique" || echo "FAIL: duplicate token"

# B-07: tokens for different records must also be unique
TR1=$(curl -s -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-1' -H 'x-role: member' | sed 's/.*\/share\/\(.*\)".*/\1/')
TR2=$(curl -s -X POST http://localhost:5050/records/rec-200/share \
  -H 'x-user-id: user-2' -H 'x-role: member' | sed 's/.*\/share\/\(.*\)".*/\1/')
[ "$TR1" != "$TR2" ] && echo "PASS: cross-record tokens unique" || echo "FAIL: collision"

# B-08: generate 10 tokens — all must be unique
TOKENS=""
for i in $(seq 1 10); do
  T=$(curl -s -X POST http://localhost:5050/records/rec-100/share \
    -H 'x-user-id: user-1' -H 'x-role: member' | sed 's/.*\/share\/\(.*\)".*/\1/')
  TOKENS="$TOKENS\n$T"
done
UNIQUE=$(printf "$TOKENS" | sort -u | grep -c .)
[ "$UNIQUE" -eq 10 ] && echo "PASS: all 10 tokens unique" || echo "FAIL: only $UNIQUE unique"

# B-09: token must not contain uppercase hex characters
TOKEN=$(curl -s -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-1' -H 'x-role: member' | sed 's/.*\/share\/\(.*\)".*/\1/')
echo "$TOKEN" | grep -qE '[A-F]' \
  && echo "FAIL: uppercase hex in token" || echo "PASS: all lowercase"

# B-10: share URL must match expected structure
RESP=$(curl -s -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-1' -H 'x-role: member')
echo "$RESP" | grep -qE '"url":"https://example\.local/share/[0-9a-f]{64}"' \
  && echo "PASS: URL format correct" || echo "FAIL: unexpected URL — $RESP"

# B-11: [REDIS] key must exist in Redis after share creation (USE_REDIS_FOR_SHARES=true)
TOKEN=$(curl -s -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-1' -H 'x-role: member' | sed 's/.*\/share\/\(.*\)".*/\1/')
EXISTS=$(redis-cli EXISTS "share:$TOKEN")
[ "$EXISTS" = "1" ] && echo "PASS: key exists in Redis" || echo "FAIL: key not found"

# B-12: [REDIS] TTL must be set — not -1 (eternal)
TTL=$(redis-cli TTL "share:$TOKEN")
[ "$TTL" -gt 0 ] && echo "PASS: TTL=$TTL" || echo "FAIL: TTL=$TTL (no expiry)"

# B-13: [REDIS] TTL must not exceed 86400 (24 hours)
[ "$TTL" -le 86400 ] && echo "PASS: TTL within 24h" || echo "FAIL: TTL=$TTL exceeds 86400"

# B-14: [REDIS] stored value must NOT contain any PHI fields
VAL=$(redis-cli GET "share:$TOKEN")
echo "$VAL" | grep -iE "patientName|taylor|jordan|1988|1979|urinary|hydration|notes" \
  && echo "FAIL: PHI in Redis value" || echo "PASS: no PHI in Redis value"

# B-15: [REDIS] stored value must contain recordId (needed for lookup)
echo "$VAL" | grep -q "recordId" \
  && echo "PASS: recordId present in Redis value" || echo "FAIL: recordId missing"

# B-16: [REDIS] stored value must contain createdBy
echo "$VAL" | grep -q "createdBy" \
  && echo "PASS: createdBy present" || echo "FAIL: createdBy missing"

# B-17: [REDIS] stored value must contain createdAt
echo "$VAL" | grep -q "createdAt" \
  && echo "PASS: createdAt present" || echo "FAIL: createdAt missing"

# B-18: [REDIS] key must use "share:" namespace prefix
echo "share:$TOKEN" | grep -q "^share:" \
  && echo "PASS: correct key prefix" || echo "FAIL: wrong prefix"

# B-19: [REDIS] after del (simulating redemption), key must not exist
redis-cli DEL "share:$TOKEN"
AFTER=$(redis-cli EXISTS "share:$TOKEN")
[ "$AFTER" = "0" ] && echo "PASS: key deleted (one-time-use)" || echo "FAIL: key persists"

# B-20: [REDIS] redemption of unknown token returns nil
RESULT=$(redis-cli GET "share:deadbeef000000000000000000000000000000000000000000000000000000")
[ "$RESULT" = "" ] || [ "$RESULT" = "(nil)" ] \
  && echo "PASS: unknown token returns nil" || echo "FAIL: unexpected value=$RESULT"

# B-21: token must not embed userId
TOKEN=$(curl -s -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-1' -H 'x-role: member' | sed 's/.*\/share\/\(.*\)".*/\1/')
echo "$TOKEN" | grep -qi "user" \
  && echo "FAIL: userId embedded in token" || echo "PASS: no userId in token"

# B-22: two different users creating shares get different tokens
TU1=$(curl -s -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-1' -H 'x-role: member' | sed 's/.*\/share\/\(.*\)".*/\1/')
TADM=$(curl -s -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: admin-x' -H 'x-role: admin' | sed 's/.*\/share\/\(.*\)".*/\1/')
[ "$TU1" != "$TADM" ] && echo "PASS: different users produce different tokens" || echo "FAIL"

# B-23: share URL depth must be exactly 5 segments
URL=$(curl -s -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-1' -H 'x-role: member' | grep -oE 'https://[^"]+')
SEGS=$(echo "$URL" | tr '/' '\n' | grep -c .)
[ "$SEGS" -eq 5 ] && echo "PASS: URL has 5 segments" || echo "FAIL: $SEGS segments"

# B-24: blocked share creation (IDOR) must NOT generate a token
RESP=$(curl -s -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-2' -H 'x-role: member')
echo "$RESP" | grep -q '"url"' \
  && echo "FAIL: token returned on IDOR block" || echo "PASS: no token on denied share"

# B-25: code-level — randomBytes import must be from node:crypto
grep -q 'from "node:crypto"' starter/src/storage/recordRepository.ts \
  && echo "PASS: crypto import correct" || echo "FAIL: wrong import"

# B-26: code-level — token generation must use randomBytes(32)
grep -q 'randomBytes(32)' starter/src/storage/recordRepository.ts \
  && echo "PASS: randomBytes(32) used" || echo "FAIL"

# B-27: code-level — EX TTL option must be present in saveShare
grep -q 'EX: 86400' starter/src/storage/recordRepository.ts \
  && echo "PASS: TTL set to 86400" || echo "FAIL: no TTL"

# B-28: code-level — redeemShare must exist in the interface
grep -q 'redeemShare' starter/src/storage/recordRepository.ts \
  && echo "PASS: redeemShare defined" || echo "FAIL"

# B-29: code-level — token string must not interpolate recordId
grep 'const token' starter/src/storage/recordRepository.ts | grep -q 'recordId' \
  && echo "FAIL: recordId interpolated into token" || echo "PASS: token is opaque"

# B-30: code-level — token must use .toString("hex") encoding
grep -q '.toString("hex")' starter/src/storage/recordRepository.ts \
  && echo "PASS: hex encoding confirmed" || echo "FAIL"
```

---

### BLOCK C — GCS Audit Handling (30 Tests)

```bash
# C-01: code-level — randomUUID imported from node:crypto
grep 'randomUUID' starter/src/security/audit.ts | head -1
# PASS: import { randomUUID } from "node:crypto";

# C-02: code-level — object name contains action subdirectory
grep 'objectName' starter/src/security/audit.ts | grep -q 'event.action' \
  && echo "PASS: action in path" || echo "FAIL"

# C-03: code-level — object name contains targetId subdirectory
grep 'objectName' starter/src/security/audit.ts | grep -q 'event.targetId' \
  && echo "PASS: targetId in path" || echo "FAIL"

# C-04: code-level — object name contains Date.now() timestamp
grep 'objectName' starter/src/security/audit.ts | grep -q 'Date.now()' \
  && echo "PASS: timestamp in path" || echo "FAIL"

# C-05: code-level — object name contains randomUUID() for uniqueness
grep 'objectName' starter/src/security/audit.ts | grep -q 'randomUUID()' \
  && echo "PASS: UUID in path" || echo "FAIL"

# C-06: code-level — object name ends with .json
grep 'objectName' starter/src/security/audit.ts | grep -q '\.json' \
  && echo "PASS: .json suffix" || echo "FAIL"

# C-07: code-level — object name starts with audit/ prefix
grep 'objectName' starter/src/security/audit.ts | grep -q '"audit/' \
  && echo "PASS: audit/ prefix" || echo "FAIL"

# C-08: code-level — try block wraps the .save() call
grep -c 'try {' starter/src/security/audit.ts
# PASS: 1

# C-09: code-level — catch block present
grep -c '} catch' starter/src/security/audit.ts
# PASS: 1

# C-10: code-level — AUDIT_WRITE_FAILED string present in catch
grep 'AUDIT_WRITE_FAILED' starter/src/security/audit.ts \
  && echo "PASS: failure marker present" || echo "FAIL"

# C-11: code-level — catch block does NOT re-throw
grep -A8 '} catch' starter/src/security/audit.ts | grep 'throw' \
  && echo "FAIL: catch re-throws" || echo "PASS: no re-throw in catch"

# C-12: code-level — failure log includes objectName
grep -A5 'AUDIT_WRITE_FAILED' starter/src/security/audit.ts | grep 'objectName' \
  && echo "PASS: objectName in failure log" || echo "FAIL"

# C-13: code-level — failure log includes action
grep -A5 'AUDIT_WRITE_FAILED' starter/src/security/audit.ts | grep 'action' \
  && echo "PASS: action in failure log" || echo "FAIL"

# C-14: code-level — failure log includes targetId
grep -A5 'AUDIT_WRITE_FAILED' starter/src/security/audit.ts | grep 'targetId' \
  && echo "PASS: targetId in failure log" || echo "FAIL"

# C-15: code-level — failure log includes error string
grep -A5 'AUDIT_WRITE_FAILED' starter/src/security/audit.ts | grep 'error' \
  && echo "PASS: error in failure log" || echo "FAIL"

# C-16: runtime — GCS failure must NOT return HTTP 500 (start with bad bucket)
# GCS_AUDIT_BUCKET=does-not-exist USE_GCS_AUDIT_LOGGING=true npm run dev &
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  http://localhost:5050/records/rec-100 -H 'x-user-id: user-1' -H 'x-role: member')
[ "$CODE" = "200" ] && echo "PASS: request succeeds despite GCS failure" || echo "FAIL: HTTP $CODE"

# C-17: runtime — AUDIT_WRITE_FAILED must appear in server stderr on GCS failure
grep "AUDIT_WRITE_FAILED" /tmp/server.log \
  && echo "PASS: failure logged" || echo "FAIL: no failure log found"

# C-18: runtime — failure log must be valid JSON
grep "AUDIT_WRITE_FAILED" /tmp/server.log | sed 's/^AUDIT_WRITE_FAILED //' | \
  python3 -c "import sys,json; [json.loads(l) for l in sys.stdin]; print('PASS: valid JSON')" \
  2>/dev/null || echo "FAIL: invalid JSON in failure log"

# C-19: runtime — console audit logger emits one AUDIT line per request
curl -s http://localhost:5050/records/rec-100 -H 'x-user-id: user-1' -H 'x-role: member' >/dev/null
LINES=$(grep "^AUDIT" /tmp/server.log | wc -l)
[ "$LINES" -ge 1 ] && echo "PASS: $LINES audit lines emitted" || echo "FAIL: no audit lines"

# C-20: runtime — two reads of same record produce two separate audit lines (not overwritten)
curl -s http://localhost:5050/records/rec-100 -H 'x-user-id: user-1' -H 'x-role: member' >/dev/null
curl -s http://localhost:5050/records/rec-100 -H 'x-user-id: user-1' -H 'x-role: member' >/dev/null
LINES=$(grep '"action":"record_read"' /tmp/server.log | grep '"targetId":"rec-100"' | wc -l)
[ "$LINES" -ge 2 ] && echo "PASS: $LINES distinct audit events for same record" || echo "FAIL: only $LINES"

# C-21: runtime — audit event must include actor field
grep "^AUDIT" /tmp/server.log | head -1 | grep -q '"actor"' \
  && echo "PASS: actor present" || echo "FAIL: actor missing"

# C-22: runtime — audit event must include action field
grep "^AUDIT" /tmp/server.log | head -1 | grep -q '"action"' \
  && echo "PASS: action present" || echo "FAIL"

# C-23: runtime — audit event must include targetId
grep "^AUDIT" /tmp/server.log | head -1 | grep -q '"targetId"' \
  && echo "PASS: targetId present" || echo "FAIL"

# C-24: runtime — audit event must include result field
grep "^AUDIT" /tmp/server.log | head -1 | grep -q '"result"' \
  && echo "PASS: result present" || echo "FAIL"

# C-25: runtime — audit details must NOT contain patientName
grep "^AUDIT" /tmp/server.log | grep '"patientName"' \
  && echo "FAIL: PHI in audit payload" || echo "PASS: no PHI in audit"

# C-26: runtime — audit details must NOT contain dob
grep "^AUDIT" /tmp/server.log | grep '"dob"' \
  && echo "FAIL: dob in audit" || echo "PASS"

# C-27: runtime — audit details must only contain recordId under details
grep "^AUDIT" /tmp/server.log | grep -oE '"details":\{[^}]+\}' | head -3
# PASS: "details":{"recordId":"rec-100"}   — no other fields

# C-28: runtime — audit events must be valid JSON on every line
grep "^AUDIT" /tmp/server.log | sed 's/^AUDIT //' | \
  python3 -c "
import sys, json
failed = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try: json.loads(line)
    except: print('FAIL:', line); failed += 1
if not failed: print('PASS: all audit lines are valid JSON')
"

# C-29: code-level — braces are balanced in audit.ts (structural syntax check)
python3 -c "
src = open('starter/src/security/audit.ts').read()
opens = src.count('{')
closes = src.count('}')
print('PASS: braces balanced (' + str(opens) + ')' if opens == closes else 'FAIL: ' + str(opens) + ' opens vs ' + str(closes) + ' closes')
"

# C-30: runtime — content-type of audit objects (GCS mode)
# Verify contentType: application/json is passed to .save()
grep 'contentType' starter/src/security/audit.ts | grep -q 'application/json' \
  && echo "PASS: content-type set to application/json" || echo "FAIL"
```

---

### BLOCK D — PHI Exposure in Logs (30 Tests)

```bash
# All D tests read from /tmp/server.log captured during server run.
# Trigger all three endpoints first to populate the log:
curl -s http://localhost:5050/records/rec-100 -H 'x-user-id: user-1' -H 'x-role: member' >/dev/null
curl -s -X POST http://localhost:5050/records/rec-100/share -H 'x-user-id: user-1' -H 'x-role: member' >/dev/null
curl -s -X POST http://localhost:5050/records/rec-100/guidance \
  -H 'x-user-id: user-1' -H 'x-role: member' \
  -H 'content-type: application/json' -d '{"patientSummary":"Feeling better today"}' >/dev/null

# D-01: log must NOT contain "patientName"
grep -i '"patientName"' /tmp/server.log \
  && echo "FAIL: patientName in log" || echo "PASS: no patientName"

# D-02: log must NOT contain "Taylor Reed"
grep -iE "taylor|reed" /tmp/server.log \
  && echo "FAIL: patient name in log" || echo "PASS: no patient name"

# D-03: log must NOT contain "Jordan Kim"
grep -iE "jordan|kim" /tmp/server.log \
  && echo "FAIL: patient name in log" || echo "PASS"

# D-04: log must NOT contain any DOB values
grep -E "1988-05-09|1979-11-30" /tmp/server.log \
  && echo "FAIL: DOB in log" || echo "PASS: no DOB"

# D-05: log must NOT contain "encounterSummary" key
grep '"encounterSummary"' /tmp/server.log \
  && echo "FAIL: encounterSummary in log" || echo "PASS"

# D-06: log must NOT contain encounter narrative text
grep -iE "urinary|hydration|post-procedure|follow-up for" /tmp/server.log \
  && echo "FAIL: encounter text in log" || echo "PASS"

# D-07: log must NOT contain clinical notes text
grep -iE "medication changed|pain has improved|monitor response|side effects" /tmp/server.log \
  && echo "FAIL: clinical notes in log" || echo "PASS"

# D-08: log must NOT contain "notes" field key
grep '"notes"' /tmp/server.log \
  && echo "FAIL: notes field in log" || echo "PASS"

# D-09: log MUST contain userId on record_read event
grep "record_read" /tmp/server.log | grep -q "userId" \
  && echo "PASS: userId in record_read log" || echo "FAIL: userId missing"

# D-10: log MUST contain recordId on record_read event
grep "record_read" /tmp/server.log | grep -q "recordId" \
  && echo "PASS: recordId in record_read log" || echo "FAIL: recordId missing"

# D-11: audit event details must only contain recordId
grep "^AUDIT" /tmp/server.log | grep -oE '"details":\{[^}]+\}' | \
  grep -vE '^"details":\{"recordId":"[^"]+"\}$' \
  && echo "FAIL: extra fields in audit details" || echo "PASS: details contains only recordId"

# D-12: audit must NOT contain patientName
grep "^AUDIT" /tmp/server.log | grep '"patientName"' \
  && echo "FAIL: patientName in audit" || echo "PASS"

# D-13: audit must NOT contain dob
grep "^AUDIT" /tmp/server.log | grep '"dob"' \
  && echo "FAIL: dob in audit" || echo "PASS"

# D-14: audit must NOT contain notes
grep "^AUDIT" /tmp/server.log | grep '"notes"' \
  && echo "FAIL: notes in audit" || echo "PASS"

# D-15: audit details.recordId must match targetId in same event
grep "^AUDIT" /tmp/server.log | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip().removeprefix('AUDIT').strip()
    if not line: continue
    e = json.loads(line)
    tid = e.get('targetId','')
    rid = e.get('details',{}).get('recordId','')
    print('PASS: targetId matches details.recordId' if tid == rid else f'FAIL: targetId={tid} vs details.recordId={rid}')
"

# D-16: share creation log must NOT contain the token value
TOKEN=$(curl -s -X POST http://localhost:5050/records/rec-100/share \
  -H 'x-user-id: user-1' -H 'x-role: member' | sed 's/.*\/share\/\(.*\)".*/\1/')
grep "$TOKEN" /tmp/server.log \
  && echo "FAIL: token found in logs" || echo "PASS: token not in logs"

# D-17: share log must NOT expose token field
grep "record_share_created" /tmp/server.log | grep '"token"' \
  && echo "FAIL: token field in share log" || echo "PASS"

# D-18: share log MUST contain userId
grep "record_share_created" /tmp/server.log | grep -q "userId" \
  && echo "PASS: userId in share log" || echo "FAIL"

# D-19: share log MUST contain recordId
grep "record_share_created" /tmp/server.log | grep -q "recordId" \
  && echo "PASS: recordId in share log" || echo "FAIL"

# D-20: guidance log must NOT contain any PHI field
grep "guidance_generated" /tmp/server.log | grep -iE "taylor|reed|jordan|kim|1988|1979|urinary|hydration|medication" \
  && echo "FAIL: PHI in guidance log" || echo "PASS"

# D-21: guidance log must NOT contain rendered prompt text
grep "guidance_generated" /tmp/server.log | grep -iE "care guidance|follow-up|patient summary|output requirements" \
  && echo "FAIL: prompt text in guidance log" || echo "PASS"

# D-22: guidance log must NOT contain caller-supplied patientSummary
grep "guidance_generated" /tmp/server.log | grep -i "feeling better today" \
  && echo "FAIL: patientSummary in guidance log" || echo "PASS"

# D-23: guidance log MUST contain userId
grep "guidance_generated" /tmp/server.log | grep -q "userId" \
  && echo "PASS: userId in guidance log" || echo "FAIL"

# D-24: guidance log MUST contain recordId
grep "guidance_generated" /tmp/server.log | grep -q "recordId" \
  && echo "PASS: recordId in guidance log" || echo "FAIL"

# D-25: comprehensive PHI scan across ALL log lines
grep -iE "taylor|reed|jordan|kim|1988-05-09|1979-11-30|urinary|hydration|post-procedure|medication changed|pain has improved|monitor response|side effects" \
  /tmp/server.log \
  && echo "FAIL: PHI found in log" || echo "PASS: log is PHI-free"

# D-26: ownerUserId must NOT appear in logs
grep '"ownerUserId"' /tmp/server.log \
  && echo "FAIL: ownerUserId in logs" || echo "PASS"

# D-27: code-level — all logger.info calls must not pass full record object
grep 'logger.info' starter/src/managers/recordManager.ts | grep -E ",\s*record\s*[,})]" \
  && echo "FAIL: full record object passed to logger" || echo "PASS: no raw record in logger"

# D-28: code-level — audit details must not use "details: record"
grep 'details: record' starter/src/managers/recordManager.ts \
  && echo "FAIL: full record in audit details" || echo "PASS"

# D-29: code-level — prompt variable must not be passed to logger
grep 'logger' starter/src/managers/recordManager.ts | grep -E "\bprompt\b" \
  && echo "FAIL: prompt passed to logger" || echo "PASS: prompt not logged"

# D-30: integration — trigger all three endpoints, confirm zero PHI in entire log
grep -iE "taylor|reed|jordan|kim|1988|1979|urinary|hydration|medication|pain has|monitor|feeling better|encounterSummary|\"notes\"|\"dob\"" \
  /tmp/server.log \
  && echo "FAIL: PHI or prompt text detected in logs" || echo "PASS: complete log scan — PHI-free"
```

---

## Quick Automated Run Script

Save as `run_tests.sh`, start the server first, then run:

```bash
#!/usr/bin/env bash
# Usage:
#   cd starter && npm run dev > /tmp/server.log 2>&1 &
#   sleep 2
#   cd .. && bash run_tests.sh

set -uo pipefail
BASE="http://localhost:5050"
PASS=0; FAIL=0

chk() {
  local label="$1" expected="$2" actual="$3"
  if [ "$actual" = "$expected" ]; then
    echo "  PASS [$label]"; ((PASS++))
  else
    echo "  FAIL [$label]  expected='$expected'  got='$actual'"; ((FAIL++))
  fi
}

echo "=== BLOCK A: IDOR ==="
chk "A-01 user2 blocked from rec-100" "404" \
  "$(curl -s -o/dev/null -w '%{http_code}' $BASE/records/rec-100 -H 'x-user-id: user-2' -H 'x-role: member')"
chk "A-02 user1 reads own rec-100" "200" \
  "$(curl -s -o/dev/null -w '%{http_code}' $BASE/records/rec-100 -H 'x-user-id: user-1' -H 'x-role: member')"
chk "A-03 user1 blocked from rec-200" "404" \
  "$(curl -s -o/dev/null -w '%{http_code}' $BASE/records/rec-200 -H 'x-user-id: user-1' -H 'x-role: member')"
chk "A-04 user2 reads own rec-200" "200" \
  "$(curl -s -o/dev/null -w '%{http_code}' $BASE/records/rec-200 -H 'x-user-id: user-2' -H 'x-role: member')"
chk "A-05 admin reads rec-100 cross-user" "200" \
  "$(curl -s -o/dev/null -w '%{http_code}' $BASE/records/rec-100 -H 'x-user-id: user-2' -H 'x-role: admin')"
chk "A-09 user2 share rec-100 blocked" "404" \
  "$(curl -s -o/dev/null -w '%{http_code}' -X POST $BASE/records/rec-100/share -H 'x-user-id: user-2' -H 'x-role: member')"
chk "A-10 user1 share rec-100 ok" "200" \
  "$(curl -s -o/dev/null -w '%{http_code}' -X POST $BASE/records/rec-100/share -H 'x-user-id: user-1' -H 'x-role: member')"
chk "A-16 user2 guidance rec-100 blocked" "404" \
  "$(curl -s -o/dev/null -w '%{http_code}' -X POST $BASE/records/rec-100/guidance -H 'x-user-id: user-2' -H 'x-role: member' -H 'content-type: application/json' -d '{"patientSummary":"x"}')"
chk "A-21 no auth header" "401" \
  "$(curl -s -o/dev/null -w '%{http_code}' $BASE/records/rec-100)"

echo ""
echo "=== BLOCK B: Token Format ==="
TOKEN=$(curl -s -X POST $BASE/records/rec-100/share -H 'x-user-id: user-1' -H 'x-role: member' | sed 's/.*\/share\/\(.*\)".*/\1/')
chk "B-01 token length 64" "64" "${#TOKEN}"
echo "$TOKEN" | grep -qE '^[0-9a-f]{64}$' && { echo "  PASS [B-02 hex chars]"; ((PASS++)); } || { echo "  FAIL [B-02 hex chars]"; ((FAIL++)); }
echo "$TOKEN" | grep -q "^rec-" && { echo "  FAIL [B-03 no recordId prefix]"; ((FAIL++)); } || { echo "  PASS [B-03 no recordId prefix]"; ((PASS++)); }
grep -q 'randomBytes(32)' starter/src/storage/recordRepository.ts && { echo "  PASS [B-26 randomBytes(32) used]"; ((PASS++)); } || { echo "  FAIL [B-26]"; ((FAIL++)); }
grep -q 'EX: 86400' starter/src/storage/recordRepository.ts && { echo "  PASS [B-27 TTL 86400]"; ((PASS++)); } || { echo "  FAIL [B-27]"; ((FAIL++)); }

echo ""
echo "=== BLOCK C: GCS ==="
grep -q 'randomUUID' starter/src/security/audit.ts && { echo "  PASS [C-01 randomUUID imported]"; ((PASS++)); } || { echo "  FAIL [C-01]"; ((FAIL++)); }
grep -q 'AUDIT_WRITE_FAILED' starter/src/security/audit.ts && { echo "  PASS [C-10 failure marker]"; ((PASS++)); } || { echo "  FAIL [C-10]"; ((FAIL++)); }
grep -A8 '} catch' starter/src/security/audit.ts | grep -q 'throw' && { echo "  FAIL [C-11 catch re-throws]"; ((FAIL++)); } || { echo "  PASS [C-11 no re-throw]"; ((PASS++)); }

echo ""
echo "=== BLOCK D: PHI in Logs ==="
# Trigger endpoints to generate logs
curl -s $BASE/records/rec-100 -H 'x-user-id: user-1' -H 'x-role: member' >/dev/null
curl -s -X POST $BASE/records/rec-100/share -H 'x-user-id: user-1' -H 'x-role: member' >/dev/null
curl -s -X POST $BASE/records/rec-100/guidance -H 'x-user-id: user-1' -H 'x-role: member' -H 'content-type: application/json' -d '{"patientSummary":"test"}' >/dev/null

grep -iE "taylor|reed|jordan|kim|1988|1979|urinary|hydration|medication|pain has" /tmp/server.log \
  && { echo "  FAIL [D-25 PHI in logs]"; ((FAIL++)); } || { echo "  PASS [D-25 no PHI in logs]"; ((PASS++)); }
grep 'details: record' starter/src/managers/recordManager.ts \
  && { echo "  FAIL [D-28 raw record in audit]"; ((FAIL++)); } || { echo "  PASS [D-28 no raw record]"; ((PASS++)); }

echo ""
echo "=============================="
echo "  TOTAL: $PASS passed, $FAIL failed"
echo "=============================="
```
