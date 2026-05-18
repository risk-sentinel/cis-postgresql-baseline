# PostgreSQL CIS Baseline

InSpec / CINC Auditor profile validating a PostgreSQL deployment against **CIS PostgreSQL Benchmark v1.0.0** (shared surface across PostgreSQL majors 14–18). Engine-portable across three deployment shapes — standalone RDS, Aurora cluster, or self-managed.

## Scope

- **PostgreSQL versions 14, 15, 16, 17, 18.** Version 13 is excluded: AWS-deprecated as of 2026; CIS coverage is the same shared 14–18 surface.
- **Deployment shapes** (selected via the `engine_deployment` input):
  - `rds_instance` (default) — standalone Amazon RDS PostgreSQL.
  - `aurora_cluster` — Amazon Aurora-PostgreSQL.
  - `self_managed` — PostgreSQL on EC2 / on-prem / other.
- **Host-OS controls** (umask, bash profile, sudo, systemd) carry per-deployment rationale: on managed RDS/Aurora they're inherited from AWS under shared-responsibility; on self-managed they require host-transport InSpec, not psql.

Per-control partition applicability lives in `partition_applicability.yml`. Per-control version applicability lives in each control's `tag postgresql_versions:`.

## Portability

The profile is consumer-portable across deployment shapes via declared inputs — never fork the profile.

| Input | Default | Purpose |
|---|---|---|
| `aws_partition` | `aws` | AWS partition (Commercial / GovCloud). |
| `engine_deployment` | `rds_instance` | One of `rds_instance`, `aurora_cluster`, `self_managed`. Selects parameter-group lookup strategy. |
| `postgresql_version` | `'15'` | Major PostgreSQL version. Controls not in scope for the version auto-skip via the `tag postgresql_versions:` guard. |
| `postgresql_instance_identifiers` | `[]` (auto-discover) | Optional explicit RDS instance allowlist (when `engine_deployment == 'rds_instance'`). Empty = iterate all visible PostgreSQL instances. |
| `postgresql_cluster_identifiers` | `[]` (auto-discover) | Optional explicit Aurora cluster allowlist (when `engine_deployment == 'aurora_cluster'`). |
| `postgresql_endpoint` | `''` | DB-connection endpoint (RDS instance / Aurora reader / self-managed host). Empty → auto-detect, then N/A if no PostgreSQL is in scope. |
| `postgresql_database_name` | `'postgres'` | Database name the scanner connects to. |
| `postgresql_scanner_dbuser` | `'inspec_scanner'` | DB user with `rds_iam` role (managed) or password (self-managed) and read-only grants on `pg_catalog` + `information_schema`. |
| `postgresql_port` | `5432` | TCP port. |
| `aurora_*` | (deprecated aliases) | `aurora_cluster_endpoint` / `aurora_database_name` / `aurora_scanner_dbuser` / `aurora_port` are deprecated aliases of the `postgresql_*` inputs above; honored for backward compatibility. New deployments should use the `postgresql_*` names. |

### Example: standalone RDS PostgreSQL consumer

```yaml
aws_partition: aws
engine_deployment: rds_instance
postgresql_version: '15'
postgresql_endpoint: my-app-pg.abc123.us-east-1.rds.amazonaws.com
```

### Example: multi-cluster Aurora consumer

```yaml
aws_partition: aws
engine_deployment: aurora_cluster
postgresql_version: '16'
postgresql_cluster_identifiers:
  - my-app-aurora-primary
  - my-app-aurora-reports
postgresql_endpoint: my-app-aurora-primary.cluster-ro-us-east-1.rds.amazonaws.com
```

### Example: self-managed PostgreSQL

```yaml
aws_partition: aws
engine_deployment: self_managed
postgresql_version: '15'
postgresql_endpoint: 10.0.4.21
postgresql_scanner_dbuser: inspec_scanner
```

## Coverage distribution (phase B + #31 reclassification + Phase C)

Phase B automates what can be checked via RDS cluster-parameter-group lookups and classifies the rest across four skip buckets per the [Control Classification Guide](../../docs/dev/Control_Classification_Guide.md). Phase C (#29) flips 6 of the 17 `pending-db-connection` controls to `implemented` via direct psql queries (CIS 4.3, 4.5, 4.6, 4.7, 5.5, 6.11) and reclassifies the rest across the existing buckets — see the per-control split below. Each control carries a `tag implementation_status: '<oscal-value>'` mapped to OSCAL's native vocabulary.

| Bucket | `implementation_status` | Count | Meaning |
|---|---|---|---|
| **Automated** | `implemented` | 27 | Real describes against either the local parameter-group resource (21 controls — `log_connections`, `log_line_prefix`, `rds.force_ssl`, `shared_preload_libraries`, etc. across §3.1/§3.2/§6.8–§6.10; uses `aws_db_parameter_group` for `rds_instance` deployment, `aws_rds_cluster_parameter_group` for `aurora_cluster`) or the local `aws_rds_aurora_psql_query` resource (6 controls — direct psql queries against `pg_roles` / `pg_settings` / `pg_extension`: §4.3, §4.5, §4.6, §4.7, §5.5, §6.11). |
| **Attestation** | `alternative` | 10 | `skip 'Requires manual review and attestation provided for this control'` — controls where the technical bar is set by an organizational policy review, not a runtime configuration check (e.g., §4.4 password-policy, §4.9/§4.10 OS-account separation, §6.2–§6.6 dynamic-runtime-parameter review windows). Includes the original §6.1 explanatory control. |
| **Inherited from AWS** | `inherited` | 21 | `skip 'inherited-from-aws: …'` — AWS satisfies these controls under the shared-responsibility model. Inheritance evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate+High, AWS ISO 27001 (citations via `tag attestation_references:`). Covers CIS sections 1 (package/init/patch mgmt), 2.1/2.2 (host file perms), 3.1 OS-bound logging, 4.1/4.2 (shell access, sudo), 5.2–5.4 (listen addr, sockets, pg_hba), 6.7 (FIPS), 7.3/7.4 (base backups, WAL archiving), 8.1/8.3 (subdirectory layout, OS file perms). |
| **Not applicable** | `not-applicable` | 14 | `skip 'Not applicable: …'` — controls that don't apply to the deployment shape (e.g., client-side `PGPASSWORD` framing on AWS-managed RDS, PostgreSQL streaming replication vs Aurora's distributed storage layer, pgBackRest tool mismatch on managed engines, the §4.8 `set_user` extension which Aurora doesn't ship). Distinct from inherited: inherited = AWS satisfies; not-applicable = control doesn't apply regardless of who's responsible. |
| **Planned** | `planned` | 0 | All `pending-db-connection` controls are now classified — Phase C (#29) reached zero `planned` controls. |

Total: **72 controls.**

### Inheritance tags on the 21 inherited controls

Each inherited control additionally carries:

```ruby
tag inherited_from:         'aws-shared-responsibility'
tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
```

A downstream HDF→OSCAL converter that understands the inheritance triplet emits OSCAL `implementation-status: inherited` with `responsible-roles` + `by-component.attestations` populated. The reference SAF CLI `inspec_tools` chain is one option; consumers running their own emitter need a mapping table for these tags.

Every control in phase B carries `tag exec_validated: false` — describe logic hasn't been validated against a live database yet. The first post-merge `cinc-auditor exec` run against a configured PostgreSQL deployment will exercise the ~25 automated parameter-group describes.

## DB-connection prerequisite

Eight controls (§4.3, §4.4, §4.5, §4.6, §4.7, §4.10, §5.5, §6.11) issue psql queries against PostgreSQL system catalogs via the local `aws_rds_aurora_psql_query` resource (`libraries/aws_rds_aurora_psql_query.rb` — named for historical reasons; works against both standalone RDS instances and Aurora clusters via IAM-DB-auth). The resource connects to the DB using RDS IAM-DB-auth — no stored password.

When the endpoint input is not set and no PostgreSQL deployment is auto-detected, the dependent controls go N/A (impact 0.0). When the endpoint is set but the connection fails (DNS, network, perms, auth), the precheck Skips with the specific failure verbatim.

To run these controls successfully, a consumer needs:

### 1. A read-only DB user with `rds_iam` role

In the target Postgres database, run as admin:

```sql
-- Create the scanner user. No password — IAM auth only.
CREATE ROLE inspec_scanner WITH LOGIN;

-- Grant IAM-DB-auth membership. Without this, IAM tokens are rejected
-- with "password authentication failed" regardless of IAM-side perms.
GRANT rds_iam TO inspec_scanner;

-- Read-only grants on the schemas the profile needs:
GRANT USAGE   ON SCHEMA pg_catalog          TO inspec_scanner;
GRANT USAGE   ON SCHEMA information_schema  TO inspec_scanner;
GRANT SELECT  ON ALL TABLES IN SCHEMA pg_catalog          TO inspec_scanner;
GRANT SELECT  ON ALL TABLES IN SCHEMA information_schema  TO inspec_scanner;

-- IMPORTANT: do NOT grant anything on pg_authid (password hashes off-limits).
```

Verify after provisioning:

```sql
SELECT rolname FROM pg_roles WHERE rolname = 'inspec_scanner';   -- expect: 1 row

SELECT g.rolname AS granted_role
FROM pg_auth_members am
JOIN pg_roles g ON g.oid = am.roleid
JOIN pg_roles r ON r.oid = am.member
WHERE r.rolname = 'inspec_scanner';                              -- expect: rds_iam
```

### 2. An IAM role with `rds-db:connect` on the **resource-ID-based** ARN

The runner assumes this role (in CI via OIDC; locally via your preferred mechanism). The IAM policy MUST grant `rds-db:connect` on the resource-ID-based ARN — using the *instance identifier* in place of the resource ID is the most common misconfiguration and fails silently as "password authentication failed":

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowRdsIamDbConnect",
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:<region>:<account-id>:dbuser:<DbiResourceId>/inspec_scanner"
    }
  ]
}
```

Replace `<DbiResourceId>` with the value from:

```bash
aws rds describe-db-instances \
  --db-instance-identifier <your-db-instance> \
  --query 'DBInstances[0].DbiResourceId' \
  --output text
```

The resource ID looks like `db-XXXXXXXXXXXXXXXXXXXX` (uppercase + digits, prefixed `db-`). It is NOT the same as the instance identifier you see in the console. The ID changes if the instance is rebuilt (point-in-time restore, etc.). For long-lived deployments where DB rebuilds happen, wildcard the resource ID portion:

```
"Resource": "arn:aws:rds-db:<region>:<account-id>:dbuser:*/inspec_scanner"
```

### 3. A network path

From the InSpec runner to the cluster's reader endpoint. For VPC-internal clusters this means a self-hosted runner inside the VPC, VPC peering, or Transit Gateway reach. Public-endpoint clusters work from any standard runner.

### 4. Verify the configuration before exec

`tools/diagnose_iam_db_auth/run.sh` exercises the IAM + DB plumbing end-to-end. Run it from the in-VPC runner (with scanner credentials in scope) OR from an admin shell in admin-mode (skips live-connect tests but verifies the IAM policy):

```bash
# From the runner with scanner credentials in scope:
bash tools/diagnose_iam_db_auth/run.sh

# OR from an admin shell — inspects the scanner role's policies without
# needing to assume it (good when the scanner role's trust policy
# correctly excludes IAM users):
SCANNER_ROLE_ARN=arn:aws:iam::<account>:role/<scanner-role-name> \
  bash tools/diagnose_iam_db_auth/run.sh
```

The script prints PASS/FAIL/WARN per check with concrete next-step guidance; the summary names exactly what's misconfigured.

### Consumer inputs

| Input | Default | Purpose |
|---|---|---|
| `postgresql_endpoint` | `''` | Hostname of the writer/reader endpoint. Port may be included (`host:5432`) or omitted — the resource normalizes either form. |
| `postgresql_port` | `5432` | TCP port. |
| `postgresql_scanner_dbuser` | `'inspec_scanner'` | DB user name. Must match what's provisioned in step 1. |
| `postgresql_database_name` | `'postgres'` | Database to connect to. Override only for non-default deployments. |
| `aurora_cluster_endpoint`, `aurora_scanner_dbuser`, … | (aliases) | Deprecated aliases of the `postgresql_*` inputs; honored for backward compatibility. New deployments should use the `postgresql_*` names. |

## Running Locally

Prerequisites: Docker. Vendor once to pull the `inspec-aws` resource pack:

```bash
docker run --rm -v "$PWD:/src" risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 \
  vendor /src/profiles/cis-postgresql --overwrite
```

Execute against AWS Commercial (standalone RDS or Aurora):

```bash
docker run --rm \
  -v "$PWD:/src" \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_DEFAULT_REGION=us-east-1 \
  risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 exec /src/profiles/cis-postgresql \
  --input aws_partition=aws postgresql_version=15 \
  --reporter cli json:/src/hdf.json
```

## Local library files

- `libraries/_aws_backend_bootstrap.rb` — ensures `$LOAD_PATH` includes the vendored inspec-aws libraries directory. Required because InSpec's `instance_eval` load path can't be resolved via `__dir__` / `require_relative`. Verbatim copy of the same file in `cis-aws-foundations` and `cis-aws-database`. See issue #24 for context.
- `libraries/aws_rds_cluster_parameter_group.rb` — wraps `describe_db_cluster_parameters`, exposes `parameter_value(name)` and engine-specific convenience predicates. Verbatim copy from `cis-aws-database` (#6).
- `libraries/aws_rds_aurora_psql_query.rb` — wraps the `pg` Ruby gem + AWS SDK `generate_db_auth_token` to issue read-only psql queries against a PostgreSQL deployment via IAM-DB-auth. Despite the name (kept stable for backward compatibility with the file path referenced across docs), the resource works against both standalone RDS instances and Aurora clusters. `pg` is lazy-required inside `_connect` so the library loads even in cinc-auditor runtimes that don't ship the gem; missing gem surfaces via `connection_error` instead of crashing the profile. Exposes a `connection_error` accessor (returns `nil` or a human-readable error string) for controls to precheck before trusting query results. See `docs/dev/Vendored_Resource_Gaps.md` §4 (lazy-require pattern) and §5 (connection-precheck pattern).

### Connection failure semantics

Every Phase-C control emits two describes when `aurora_cluster_endpoint` is set:

1. **`CIS X.X — DB-connection precheck`** — fails loudly with a specific error message (`pg gem not installed`, `generate_db_auth_token failed`, `psql connect failed`) when connectivity can't be established. The control as a whole is FAILED in HDF.
2. **The compliance check** — runs against the actual query result when connectivity works. When connectivity fails, the precheck has already failed the control; the compliance describe still runs but its outcome is no longer the load-bearing signal.

When `aurora_cluster_endpoint` is unset, both describes are replaced by a single `pending-db-connection: aurora_cluster_endpoint not set` skip — the existing graceful-degradation pattern.

The CI exec-rds-psql job (`.github/workflows/validate.yml`) installs `pg` inside the same Docker container as the `cinc-auditor exec` call (`bash -c "gem install pg --no-document && cinc-auditor exec ..."`). For local runs, install pg the same way or use a custom image with pg pre-installed.

## NIST 800-53 Tagging

Every control carries `tag nist: [...]` resolved at scaffold time from DISA CCI identifiers. Same provenance chain as other profiles in this repo.

## Regenerating From XCCDF

The CIS PostgreSQL 18 XCCDF is the source-of-truth benchmark (v1.0.0 content is identical across v14–v18; CIS publishes a separate per-version XCCDF for administrative reasons). Regeneration is deferred while this profile is under active fill — re-running the scaffolder would overwrite authored describe bodies. See [`docs/dev/issue_rules.md`](../../docs/dev/issue_rules.md) for the guardrail.

## Status

All 72 controls have authored describe bodies. The Coverage Distribution table above reflects the as-shipped shape.

Phase C (#29) is complete: 6 of the original 17 `pending-db-connection` controls flipped to `implemented` via the `aws_rds_aurora_psql_query` resource; the remaining 11 reclassified across `alternative` / `inherited` / `not-applicable`. The `planned` bucket is empty. The Phase-C controls degrade gracefully (skip with `pending-db-connection: aurora_cluster_endpoint not set`) when the consumer doesn't supply `aurora_cluster_endpoint`.
