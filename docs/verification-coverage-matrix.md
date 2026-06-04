# cis-postgresql — verification coverage matrix

Phase C (sparc-validate verification-rigor sweep). Principle: **verify the
technical state wherever the platform can answer it; never accept a human
attestation as proof of a checkable fact.** Attestation is the last resort —
reserved for facts the platform genuinely cannot expose — and even then carries
a `document_attestation` freshness floor. This matrix makes the trust boundary
auditable: for every non-`implemented` control, *what* we do and *why*.

## Disposition summary

| Disposition | Count | Meaning |
|---|---|---|
| `implemented` | 29 | Direct API/SQL assertion of the actual state |
| `inherited` (→ `:leveraged` evidence) | 34 | AWS-managed; AWS's authorization is freshness-checked (not assumed) |
| verify-when-declared (dual-mode) | 5 | Verifies actual values when the consumer declares the policy; attests otherwise |
| attestation (genuinely unverifiable) | 3 | Justified below |
| not-applicable | 1 | — |

## Dual-mode VERIFY (Phase C — promoted from attestation)

| Control | Was | Now |
|---|---|---|
| C-6.2 backend runtime params | attestation | **VERIFY** actual parameter-group values vs `cis_6_2_expected_params` when declared; attest otherwise |
| C-6.3 postmaster runtime params | attestation | **VERIFY** vs `cis_6_3_expected_params` |
| C-6.4 SIGHUP runtime params | attestation | **VERIFY** vs `cis_6_4_expected_params` |
| C-6.5 superuser runtime params | attestation | **VERIFY** vs `cis_6_5_expected_params` |
| C-6.6 user runtime params | attestation | **VERIFY** vs `cis_6_6_expected_params` |

Rationale: there is no universal CIS-mandated value for a runtime-parameter
*category* — the security-relevant params + values are consumer-policy. So the
consumer declares them (a `{param => value}` hash) and the control reads the
**actual** parameter-group values via the same mechanism the §3 controls use
(`parameter_value(...)` + `cmp_pg_param`). The human no longer attests "we
reviewed it"; the engine confirms the values. Undeclared → attestation floor.

## Remaining attestation — justified (genuinely unverifiable)

| Control | Why the platform can't verify it |
|---|---|
| **C-4.9** make use of predefined roles | The DB exposes which roles use `pg_*` predefined roles (`pg_auth_members`), but **not whether an application role *should*** — that's a role-design judgment recorded off-platform. We can evidence usage, not intent. |
| **C-5.6** password complexity | Under the consumer's IAM-DB-auth posture (verified by C-4.10) stored-role passwords are moot; Aurora ships no `passwordcheck` module, and `pg_authid.rolpassword` is off-limits to the scanner — the complexity policy for any password roles is not queryable. |
| **C-6.1** understanding attack vectors | An awareness/education control with no asserted state. |

Each retains a `document_attestation(:boundary)` freshness floor so the
attestation document itself is existence/recency-checked.

## Inherited (34) → `:leveraged` evidence

The 34 AWS-shared-responsibility controls resolve `attestation_uri(:leveraged, …)`
against the consumer's pulled AWS authorization manifest (existence + freshness),
rather than the previous `expect(true)` stub — so "AWS handles this" is evidenced.
