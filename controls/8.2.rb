# encoding: UTF-8

control 'C-8.2' do
  title 'Ensure the backup and restore tool, \'pgBackRest\', is installed and configured'
  desc  "
    pgBackRest aims to be a simple, reliable backup and restore system that can seamlessly scale up to the largest databases and workloads. Instead of relying on traditional backup tools like `tar` and `rsync`, pgBackRest implements all backup features internally and uses a custom protocol for communicating with remote systems. Removing reliance on `tar` and `rsync` allows for better solutions to database-specific backup challenges. The custom remote protocol allows for more flexibility and limits the types of connections that are required to perform a backup which increases security.

    The native PostgreSQL backup facility `pg_dump` provides adequate logical backup operations but does not provide for Point In Time Recovery (PITR). The PostgreSQL facility `pg_basebackup` performs a physical backup of the database files and does provide for PITR, but it is constrained by single threading. Both of these methodologies are standard in the PostgreSQL ecosystem and appropriate for particular backup/recovery needs. `pgBackRest` offers another option with much more robust features and flexibility.

    `pgBackRest` is open-source software developed to perform efficient backups on PostgreSQL databases that measure in tens of terabytes and greater. It supports per-file checksums, compression, partial/failed backup resume, high-performance parallel transfer, asynchronous archiving, tablespaces, expiration, full/differential/incremental backups, local/remote operation via SSH or TLS, hard-linking, restore, backup encryption, and more. `pgBackRest` is written in C and does not depend on `rsync` or `tar` but instead performs its own deltas which give it maximum flexibility. Finally, `pgBackRest` provides an easy-to-use internal repository listing backup details accessible via the `pgbackrest info` command, as illustrated below.
    ```
    $ pgbackrest info
    stanza: proddb01
    status: ok

    db (current)
      wal archive min/max (18.0-1): 000000010000000000000012 / 000000010000000000000017

          full backup: 20231012-153106F
              timestamp start/stop: 2023-10-12 15:31:06 / 2023-10-12 15:31:49
              wal start/stop: 000000010000000000000012 / 000000010000000000000012
              database size: 29.4MB, backup size: 29.4MB
              repository size: 3.4MB, repository backup size: 3.4MB

          diff backup: 20231012-153106F_20231012-173109D
              timestamp start/stop: 2023-10-12 17:31:09 / 2023-10-12 17:31:19
              wal start/stop: 000000010000000000000015 / 000000010000000000000015
              database size: 29.4MB, backup size: 2.6MB
              repository size: 3.4MB, repository backup size: 346.8KB
              backup reference list: 20231012-153106F

          incr backup: 20231012-153106F_20231012-183114I
              timestamp start/stop: 2023-10-12 18:31:14 / 2023-10-12 18:31:22
              wal start/stop: 000000010000000000000017 / 000000010000000000000017
              database size: 29.4MB, backup size: 8.2KB
              repository size: 3.4MB, repository backup size: 519B
              backup reference list: 20231012-153106F, 20231012-153106F_20231012-173109D
    ```
  "
  desc  'rationale', "
    pgBackRest aims to be a simple, reliable backup and restore system that can seamlessly scale up to the largest databases and workloads. Instead of relying on traditional backup tools like `tar` and `rsync`, pgBackRest implements all backup features internally and uses a custom protocol for communicating with remote systems. Removing reliance on `tar` and `rsync` allows for better solutions to database-specific backup challenges. The custom remote protocol allows for more flexibility and limits the types of connections that are required to perform a backup which increases security.

    The native PostgreSQL backup facility `pg_dump` provides adequate logical backup operations but does not provide for Point In Time Recovery (PITR). The PostgreSQL facility `pg_basebackup` performs a physical backup of the database files and does provide for PITR, but it is constrained by single threading. Both of these methodologies are standard in the PostgreSQL ecosystem and appropriate for particular backup/recovery needs. `pgBackRest` offers another option with much more robust features and flexibility.

    `pgBackRest` is open-source software developed to perform efficient backups on PostgreSQL databases that measure in tens of terabytes and greater. It supports per-file checksums, compression, partial/failed backup resume, high-performance parallel transfer, asynchronous archiving, tablespaces, expiration, full/differential/incremental backups, local/remote operation via SSH or TLS, hard-linking, restore, backup encryption, and more. `pgBackRest` is written in C and does not depend on `rsync` or `tar` but instead performs its own deltas which give it maximum flexibility. Finally, `pgBackRest` provides an easy-to-use internal repository listing backup details accessible via the `pgbackrest info` command, as illustrated below.
    ```
    $ pgbackrest info
    stanza: proddb01
    status: ok

    db (current)
      wal archive min/max (18.0-1): 000000010000000000000012 / 000000010000000000000017

          full backup: 20231012-153106F
              timestamp start/stop: 2023-10-12 15:31:06 / 2023-10-12 15:31:49
              wal start/stop: 000000010000000000000012 / 000000010000000000000012
              database size: 29.4MB, backup size: 29.4MB
              repository size: 3.4MB, repository backup size: 3.4MB

          diff backup: 20231012-153106F_20231012-173109D
              timestamp start/stop: 2023-10-12 17:31:09 / 2023-10-12 17:31:19
              wal start/stop: 000000010000000000000015 / 000000010000000000000015
              database size: 29.4MB, backup size: 2.6MB
              repository size: 3.4MB, repository backup size: 346.8KB
              backup reference list: 20231012-153106F

          incr backup: 20231012-153106F_20231012-183114I
              timestamp start/stop: 2023-10-12 18:31:14 / 2023-10-12 18:31:22
              wal start/stop: 000000010000000000000017 / 000000010000000000000017
              database size: 29.4MB, backup size: 8.2KB
              repository size: 3.4MB, repository backup size: 519B
              backup reference list: 20231012-153106F, 20231012-153106F_20231012-173109D
    ```
  "
  desc  'check', "
    If installed, invoke it without arguments to see the help:
    ```
    # not installed
    $ pgbackrest
    -bash: pgbackrest: command not found
    # installed
    $ pgbackrest
    pgBackRest 2.58.0 - General help

    Usage:
        pgbackrest [options] [command] ```

    If pgBackRest is not installed, this is (potentially) a fail.
  "
  desc  'fix', "
    `pgBackRest` is not installed nor configured for PostgreSQL by default, but instead is maintained as a GitHub project. Fortunately, it is a part of the PGDG repository and can be easily installed:
    ```
    # whoami
    root
    # dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm Installed:
      epel-release-9-10.el9.noarch

    Complete!
    # dnf -y install pgbackrest Installed:
      libssh2-1.11.1-1.el9.x86_64                     pgbackrest-2.58.0-1PGDG.rhel9.7.x86_64

    Complete!
    ```
    Once installed, `pgBackRest` must be configured for things like stanza name, backup location, retention policy, logging, etc. Please consult the [configuration guide](http://pgbackrest.org/configuration.html).

    If employing `pgBackRest` for your backup/recovery solution, ensure the repository, base backups, and WAL archives are stored on a reliable file system separate from the database server. Further, the external storage system where backups reside should have limited access to only those system administrators as necessary. Finally, as with any backup/recovery solution, stringent testing must be conducted. A backup is only good if it can be restored successfully.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '8.2'
  tag cis_rid:               '8.2'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:         'aws-shared-responsibility'
  tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0802r1_rule'
  tag cis_version:           '1.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  applicable_partition  = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_version    = ['14', '15', '16', '17', '18'].include?(input('postgresql_version').to_s)
  deployment            = input('engine_deployment').to_s
  deployment            = 'rds_instance' if deployment.empty?
  applicable            = applicable_partition && applicable_version

  impact 0.5
  impact 0.0 unless applicable

  only_if("Backup-tool control out of scope: engine_deployment=#{deployment} — pgBackRest is a self-hosted backup tool. Managed Postgres (RDS instance / Aurora) uses AWS-internal continuous-backup; the operator-facing bar (RDS automated backups) is covered by cis-aws-database controls C-2.8 / C-3.10. Applies only when engine_deployment=self_managed. partition=#{input('aws_partition')}, postgresql_version=#{input('postgresql_version')}.") do
    applicable
  end

  uri = input('inherited_evidence_uri', value: '')
  uri = attestation_uri(:leveraged, 'aws-soc2-type2', ext: 'json') if uri.to_s.empty?
  max_age_days = input('leveraged_evidence_max_age_days', value: 365)
  if %w[rds_instance aurora_cluster].include?(deployment)
    if uri.to_s.empty?
      describe 'AWS shared-responsibility evidence (no leveraged source configured)' do
        skip 'inherited-from-aws: set leveraged_evidence_base / inherited_evidence_uri to the pulled AWS evidence manifest (SOC 2 / FedRAMP / ISO), or `saf attest apply`.'
      end
    else
      doc = document_attestation(uri, max_age_days: max_age_days)
      describe "AWS shared-responsibility leveraged evidence (#{uri})" do
        it('reachable') { expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}" }
        it('exists') { expect(doc.exists?).to eq(true) }
        it("current within #{max_age_days}d") { expect(doc.current?).to eq(true) }
      end
    end
  else
    describe "Ensure pgBackRest is Installed" do
      skip "engine_deployment=self_managed: this control's `desc 'check'` instructions are host-side and not reachable via the AWS-transport scanner. Re-exec with -t ssh://postgres-host to evaluate."
    end
  end
end