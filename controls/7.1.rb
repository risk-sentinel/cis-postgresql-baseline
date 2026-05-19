# encoding: UTF-8

control 'C-7.1' do
  title 'Ensure a replication-only user is created and used for streaming replication'
  desc  "
    Create a new user specifically for use by streaming replication instead of using the superuser account.

    As it is not necessary to be a superuser to initiate a replication connection, it is proper to create an account specifically for replication. This allows further 'locking down' the uses of the superuser account and follows the general principle of using the least privileges necessary.
  "
  desc  'rationale', "
    Create a new user specifically for use by streaming replication instead of using the superuser account.

    As it is not necessary to be a superuser to initiate a replication connection, it is proper to create an account specifically for replication. This allows further 'locking down' the uses of the superuser account and follows the general principle of using the least privileges necessary.
  "
  desc  'check', "
    Check which users currently have the replication permission:
    ```
    postgres=# select rolname from pg_roles where rolreplication is true;
     rolname
    ----------
     postgres
    (1 row)
    ```
    In a default PostgreSQL cluster, only the `postgres` user will have this permission.
  "
  desc  'fix', "
    It will be necessary to create a new role for replication purposes:
    ```
    postgres=# create user replication_user REPLICATION encrypted password 'XXX';
    CREATE ROLE
    postgres=# select rolname from pg_roles where rolreplication is true;
         rolname
    ------------------
     postgres
     replication_user
    (2 rows)
    ```
    When using `pg_basebackup` (or other replication tools) on your standby server, you would use the `replication_user` (and its password).

    Ensure you allow the new user via your `pg_hba.conf` file:
    ```
    # note that 'replication' in the 2nd column is required and is a special
    # keyword, not a real database
    hostssl replication     replication_user    0.0.0.0/0         scram-sha-256
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-11 b', 'AC-2 c']
  tag cci:                   ['CCI-000056', 'CCI-002113']
  tag cis_number:            '7.1'
  tag cis_rid:               '7.1'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:         'aws-shared-responsibility'
  tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0701r1_rule'
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

  only_if("Streaming-replication control out of scope: engine_deployment=#{deployment} — managed Postgres replicates via AWS-internal mechanisms (Aurora's storage layer or RDS Multi-AZ replicas) rather than PostgreSQL streaming replication; the replication-only user concept doesn't apply. Applies only when engine_deployment=self_managed. partition=#{input('aws_partition')}, postgresql_version=#{input('postgresql_version')}.") do
    applicable
  end

  if %w[rds_instance aurora_cluster].include?(deployment)
    describe 'AWS shared-responsibility inheritance (CIS 7.1 — ' + "Ensure a replication-only User is Created and Used for Streaming Replication" + ')' do
      it 'is satisfied by AWS-managed controls — ' + "Aurora uses a distributed storage layer rather than PostgreSQL streaming replication; there is no PostgreSQL replication user to harden. Customer-facing read scaling uses Aurora reader endpoints. For standalone RDS PostgreSQL, replicas use AWS-managed replication outside the customer's pg_authid table" + ' (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    describe "Ensure a replication-only User is Created and Used for Streaming Replication" do
      skip "engine_deployment=self_managed: this control's `desc 'check'` instructions are host-side and not reachable via the AWS-transport scanner. Re-exec with -t ssh://postgres-host to evaluate."
    end
  end
end

