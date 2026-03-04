# COMPLIANCE_NOTES.md

Maps each security fix to SOC 2 Type II trust service criteria and HIPAA technical and
administrative safeguards. Also documents the GCS bucket security assumptions required
for the audit pipeline to satisfy DoD §3.

---

## SOC 2 Type II Mapping

| Fix | SOC 2 Control | Criterion Description | How the Fix Satisfies It |
|-----|--------------|----------------------|--------------------------|
| IDOR ownership check (all 3 endpoints) | CC6.1 | Logical and physical access controls | Enforces that only the record owner or an authorized admin role can read, share, or generate guidance for a record. Prevents unauthorized logical access to PHI. |
| IDOR ownership check (all 3 endpoints) | CC6.3 | Access enforcement based on authorization | The ownership guard is evaluated on every request before any data is returned or any side effect is triggered, ensuring access decisions are consistently enforced. |
| Cryptographic token (randomBytes 32) | CC6.7 | Transmission and storage of sensitive information | Share tokens used as bearer credentials are generated with 256 bits of CSPRNG entropy, eliminating predictability and brute-force risk for shared links. |
| Redis TTL (EX: 86400) | CC6.7 | Transmission and storage of sensitive information | Share tokens expire automatically after 24 hours, limiting the window during which an intercepted or leaked token remains valid. |
| One-time-use token (redeemShare GET+DEL) | CC6.1, CC6.7 | Access controls; credential lifecycle | Tokens are invalidated immediately upon first use, preventing replay attacks and ensuring a shared link cannot be reused after the intended access. |
| GCS non-overwritable object names | CC7.2 | System monitoring and anomaly detection | Each audit event is written to a unique, timestamped, UUID-suffixed object path. No prior audit record can be overwritten, preserving the integrity of the audit trail. |
| GCS failure fallback (AUDIT_WRITE_FAILED) | CC7.2, CC9.1 | Monitoring; risk mitigation | Audit pipeline failures are captured as structured log events (AUDIT_WRITE_FAILED) observable by monitoring systems, enabling detection and remediation without blocking healthcare operations. |
| PHI stripped from logs and audit payloads | CC6.1, CC6.7 | Access controls; data minimization | Application logs and audit records contain only correlation identifiers (userId, recordId). PHI is not replicated into secondary systems that may have broader access or longer retention. |

---

## HIPAA Safeguards Mapping

### Technical Safeguards — 45 CFR § 164.312

| Fix | HIPAA Reference | Safeguard Type | How the Fix Satisfies It |
|-----|----------------|---------------|--------------------------|
| IDOR ownership check | § 164.312(a)(1) — Access Control | Technical | Implements a unique user identification and access control mechanism: only the record's `ownerUserId` or an admin-role user may access the record. Satisfies the requirement for technical policies that allow access only to authorized persons. |
| IDOR ownership check | § 164.312(a)(2)(i) — Unique User Identification | Technical | Each request is associated with a `userId` that is compared against the record's stored owner, creating an effective unique-user-to-record authorization link. |
| Cryptographic token + TTL + OTU | § 164.312(d) — Person or Entity Authentication | Technical | Share tokens are generated with CSPRNG entropy, expire after 24 hours, and are invalidated after a single use. This satisfies the requirement to implement procedures to verify that a person seeking access is the one claimed. |
| Cryptographic token + TTL + OTU | § 164.312(e)(2)(ii) — Encryption and Decryption | Technical | While the token is not encrypted (it is a random credential), the fix ensures the credential is computationally unguessable (256-bit entropy) and time-bounded, providing equivalent protection for the share link access path. |
| GCS non-overwritable objects | § 164.312(b) — Audit Controls | Technical | Hardware, software, and procedural mechanisms must record and examine activity. Non-overwritable audit objects ensure that every access event to ePHI is permanently recorded and cannot be retroactively erased. |
| GCS failure fallback | § 164.312(b) — Audit Controls | Technical | The AUDIT_WRITE_FAILED fallback ensures that audit pipeline failures are themselves logged and visible, preventing silent loss of audit records without operational notification. |
| PHI stripped from logs | § 164.312(b) — Audit Controls | Technical | Audit records capture who accessed what record (actor, targetId, timestamp) without duplicating the ePHI content itself. This is consistent with the audit control requirement while limiting secondary PHI exposure. |
| PHI stripped from application logs | § 164.312(c)(1) — Integrity | Technical | Application logs no longer contain raw ePHI, reducing the risk of unauthorized PHI modification or disclosure via log access. |

### Administrative Safeguards — 45 CFR § 164.308

| Fix | HIPAA Reference | Safeguard Type | How the Fix Satisfies It |
|-----|----------------|---------------|--------------------------|
| IDOR + token fixes together | § 164.308(a)(1) — Risk Analysis | Administrative | These fixes directly address risks identified in a reasonable risk analysis: unauthorized record access (high likelihood × critical impact) and weak credential security (high likelihood × high impact). |
| PHI in logs | § 164.308(a)(1) — Risk Analysis | Administrative | Logging PHI unnecessarily to stdout and audit sinks represents an identified risk of secondary PHI disclosure. Stripping PHI from logs reduces this risk to acceptable residual levels. |
| GCS audit trail | § 164.308(a)(1)(ii)(D) — Information System Activity Review | Administrative | Non-overwritable, timestamped GCS audit objects support the required periodic review of information system activity (audit logs, access reports). |

---

## GCS Bucket Security Assumptions

The following infrastructure controls are assumed to be in place for the GCS audit
bucket. Without these controls, the audit trail cannot be considered tamper-resistant or
HIPAA-compliant regardless of the application-level fixes. These are documented here to
satisfy DoD §3 (bucket security assumptions).

### IAM (Identity and Access Management)

- The service writes to the GCS bucket using a dedicated GCP service account
- That service account is granted **`roles/storage.objectCreator` only** — it can create
  new objects but cannot list, read, update, or delete existing objects
- No delete permissions (`roles/storage.objectAdmin`, `roles/storage.legacyBucketOwner`)
  are granted to the service account
- Uniform Bucket-Level Access (UBA) is enabled — per-object ACLs are disabled so IAM
  is the single source of truth for access control
- Human access to audit objects is restricted to a dedicated security/audit team role
  with read-only access (`roles/storage.objectViewer`)

### Retention Policy

- A GCS Retention Policy is set on the bucket with a minimum retention period aligned
  to HIPAA requirements (minimum 6 years; recommended 7 years for safe harbor)
- The retention policy is **locked** — it cannot be reduced or removed until the
  retention period expires, even by bucket owners
- Under an active retention policy, GCS prevents deletion and overwriting of objects
  before their retention period ends, providing immutability at the storage layer

### Object Versioning

- Object versioning is enabled on the bucket as a compensating control
- Even if a write reaches the same object path (which the unique naming strategy
  prevents), versioning preserves all historical versions of each object
- Versioning also provides a recovery path if objects are accidentally soft-deleted

### Encryption

- All objects are encrypted at rest using Google-managed encryption keys by default
- For HIPAA-covered workloads, Customer-Managed Encryption Keys (CMEK) via Cloud KMS
  are recommended so that key access can be audited and revoked independently of GCS
- Keys must be rotated on a schedule consistent with HIPAA technical safeguard expectations

### Public Access Prevention

- `publicAccessPrevention` is set to `enforced` on the bucket — no public object ACLs
  or allUsers/allAuthenticatedUsers bindings are permitted
- The bucket is not configured as a static website host

### Audit Logging of the Audit Bucket

- GCS Data Access audit logs (DATA_READ, DATA_WRITE) are enabled for the audit bucket
  in Cloud Audit Logs — this creates an audit trail of the audit trail itself
- Cloud Audit Logs are exported to a separate, restricted log sink for long-term
  retention and tamper detection

### Application-Level Assumption

- The application never deletes or updates GCS audit objects after writing them
- The `createGcsAuditLogger` function uses `.save()` (which creates or overwrites),
  but the unique `timestamp-UUID` naming strategy ensures no two writes share a path
- In production, deny the service account `storage.objects.delete` permission to enforce
  this assumption at the IAM layer

---

## Outstanding Compliance Gaps

| Gap | Risk | Recommended Remediation |
|-----|------|------------------------|
| Prompt injection in guidance endpoint | Medium — attacker-controlled text inserted into LLM prompt | Sanitize or reject patientSummary containing prompt-injection patterns; consider input length cap |
| Trust-header authentication | Critical (architectural) | Gateway must strip and re-set `x-user-id`/`x-role` on every request; service must not be directly routable |
| No rate limiting on share token creation | Medium | Apply rate limiting per userId to prevent token flooding |
| Share token stored in Redis with recordId | Low | recordId is necessary for token lookup; consider encrypting the stored value at the application layer |
| No secrets rotation policy documented | Medium | `REDIS_URL` and `GOOGLE_APPLICATION_CREDENTIALS` must be rotated on a defined schedule per § 164.308(a)(5) |
