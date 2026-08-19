# cis-postgresql-baseline

InSpec / CINC Auditor profile validating **PostgreSQL on AWS** (RDS and Aurora)
against the **CIS PostgreSQL Benchmark v1.0.0** — 72 controls across engine
configuration, logging, roles and privileges, and the RDS-managed surface.

Targets **AWS Commercial** and **AWS GovCloud (non-DoD)**.

---

## Two halves, and they need different things

This is the one thing to understand before running it:

| half | assessed via | needs |
|---|---|---|
| **Configuration** | the RDS API | AWS credentials |
| **In-database** | a real connection to `pg_catalog` | endpoint, database, user, **and network reachability** |

**With no endpoint configured the in-database controls go Not Applicable.** They
do not fail, and the run still exits 0 — so a scan that never touched a database
looks very similar to one that did. Either set `postgresql_endpoint` /
`aurora_cluster_endpoint`, or know that you are assessing the configuration half
only.

Authentication is **IAM, not a password**: the scanning identity needs
`rds-db:connect` for the named database user, and the endpoint has to be
reachable from wherever the profile runs — in practice, from inside the VPC. A
scan from a laptop will not reach a private RDS endpoint.

---

## Quickstart

```bash
git clone https://github.com/risk-sentinel/cis-postgresql-baseline
cd cis-postgresql-baseline

cp inputs/example.yml inputs/mine.yml     # then edit — see Inputs below
cinc-auditor vendor . --overwrite

cinc-auditor exec . -t aws:// \
  --input-file inputs/mine.yml \
  --reporter cli json:results.json
```

### Credentials

```
rds:Describe*   rds:ListTagsForResource   kms:DescribeKey
ec2:DescribeSecurityGroups  ec2:DescribeRegions
rds-db:connect              (only for the in-database half)
```

### What a first run looks like

Against a real account with **no endpoint configured** — configuration half only:

**72 controls, 72 results — roughly 21 failed / 51 skipped.**

The skips break down as 34 inherited-from-AWS controls awaiting evidence, 8
partition-scoped, and 8 attestation-backed. If you configured an endpoint and
still see the in-database controls skipping, that is the case to investigate —
it means the connection did not happen.

---

## Inputs

Fully documented in [`inputs/example.yml`](inputs/example.yml). 34 inputs.

| Group | Inputs |
|---|---|
| **Required** | `aws_partition` |
| **In-database half** | `aurora_cluster_endpoint`, `postgresql_endpoint`, `postgresql_database_name`, `postgresql_scanner_dbuser` |
| **Scoping** | cluster / instance identifiers, `excluded_engines`, `forced_engines` |
| **Allow-lists** | five role allow-lists for the §4 and §5 controls |
| **Expected parameters** | five `cis_6_*_expected_params` hashes |
| **Logging + attestation** | `logging_requirements`, the `*_base` URIs, `inherited_evidence_uri` |

**The five `cis_6_*_expected_params` hashes encode *your* parameter policy.**
There is no universal correct answer for `log_destination` or
`logging_collector`, which is why they ship empty rather than guessed — and empty
means the control has nothing to compare against and skips.

**The inherited-from-AWS group is the largest single block of skips.** 34
controls ask for leveraged authorization evidence; pointing
`leveraged_evidence_base` at it is the highest-value single input here.

---

## Controls

72 controls following the CIS PostgreSQL v1.0.0 numbering:

| Section | Assesses |
|---|---|
| 1–2 | installation and platform — inherited from RDS, evidenced rather than asserted |
| 3 | logging — destination, collector, verbosity, retention |
| 4 | user access and authorization — roles, inactive accounts, password attributes |
| 5 | connection and login — limits, TLS enforcement, host-based rules |
| 6 | postgres settings — parameter-group values against your declared policy |
| 7–8 | replication and backup — RDS-managed, evidenced |

---

## Producing evidence

A `--reporter cli` run tells you the answer. It does not produce something an
assessor can trace back to what was assessed, when, by whom, or from which
scanner output. For that, use the CI templates — the whole pipeline, in YAML
with no helper scripts behind it:

**GitHub**

```yaml
jobs:
  evidence:
    uses: risk-sentinel/cis-postgresql-baseline/.github/workflows/exec-evidence.yml@main
    with:
      target: my-database
      profile_name: cis-postgresql-v1.0.0
      profile_version: "0.1.0"
    secrets:
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
```

**GitLab**

```yaml
include:
  - project: risk-sentinel/cis-postgresql-baseline
    file: /ci/gitlab/exec-evidence.yml
    inputs:
      target: my-database
      profile_name: cis-postgresql-v1.0.0
      profile_version: "0.1.0"
```

An `include:` brings YAML and nothing else, which is why the logic lives in the
YAML rather than in a script an including project would never receive. The
templates are carried in this repository on purpose: clone it or include it and
you have the entire pipeline, with nothing else to install.

### The order, and why it is that order

```
create passthrough -> execute -> convert (gate) -> apply -> label (gate)
                   -> validate (gate) -> display
```

The audit record is built **before** the scan, because that is when the honest
start time and the pipeline provenance are known. Only finish time, the artifact
digest and the outcome counts are added afterwards.

### Two artifacts

| artifact | shape | for |
|---|---|---|
| `results.final.json` | HDF v3 `baselines[]` | authoritative evidence — schema-validated, carries the audit record and typed target components, feeds `hdf convert --to oscal-sar` |
| `results-heimdall.json` | InSpec exec-json `profiles[]` | loading into Heimdall |

The Heimdall artifact is a **copy, not a conversion**. Tested against a live
Heimdall: every `profiles[]` variant loads, including the output of both
`--to hdf@1` and `--to hdf@2`; only the `baselines[]` v3 document is refused. So
the choice is fidelity, and every conversion path drops `resource_params` from
each result plus `depends` / `status` / `status_message` from the profile.
Copying what cinc-auditor already wrote loses nothing.

**Do not reach for `hdf convert --to hdf@2`.** The `hdf@N` namespace was
renumbered between hdf-libs 3.4.1 and 3.5.1 — on 3.4.1 it emits `baselines[]`,
on 3.5.1 `profiles[]` — so a pipeline pinned to it silently changes artifact
across an image bump. On 3.5.1, `@1` and `@2` are byte-identical.

### Three gates, each of which has failed silently in this estate

- `hdf convert` without `--no-validate`
- `hdf label` followed by `hdf label show | grep '^Component:'` — `label set`
  prints `Labels written` and writes a byte-identical file when the document has
  no components
- `hdf validate`

The exec step additionally fails the job on a missing or **zero-result**
artifact. A run that assessed nothing must not go green.

### The audit record

Written on every run — clean, failed, findings or none. Target, scan window,
scanner, profile and version, pipeline provenance, actor, converter, a sha256 of
the pre-conversion artifact, and outcome counts.

Two properties are deliberate: **absent is not empty** (an inapplicable field is
omitted, an undeterminable one is `null` with a reason), and the record **marks
which fields are corroborable** against systems the producer does not control.
An audit chain where every field is self-asserted is a story.

Schema authority: [dev-sec-ops-baseline#33](https://github.com/risk-sentinel/dev-sec-ops-baseline/issues/33).

---

## Consuming this profile

Depend on it rather than forking, so you get fixes:

```yaml
depends:
  - name: cis-postgresql-v1.0.0
    git: https://github.com/risk-sentinel/cis-postgresql-baseline.git
    tag: v0.1.5
```

Then `include_controls 'cis-postgresql-v1.0.0'` and supply your own inputs. Input overrides
reach the depended profile's controls, so your values win without editing
anything here.

## Contributing

Control logic changes belong here. `cinc-auditor check` only *loads* a profile —
it will not catch a resource that returns empty because an API call failed.
Anything touching `libraries/` needs a real `exec` against a real target before
it is trusted.

## License

Apache-2.0. See [LICENSE](LICENSE).
