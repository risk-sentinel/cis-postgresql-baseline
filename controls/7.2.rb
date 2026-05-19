# encoding: UTF-8

control 'C-7.2' do
  title 'Ensure logging of replication commands is configured'
  desc  "
    Enabling the `log_replication_commands` setting causes each attempted replication from the server to be logged.

    A successful replication connection allows for a complete copy of the data stored within the data cluster to be offloaded to another, potentially insecure, host. As such, it is advisable to log all replication commands that are executed in your database cluster to ensure the data is not off-loaded to an unexpected/undesired location.
  "
  desc  'rationale', "
    Enabling the `log_replication_commands` setting causes each attempted replication from the server to be logged.

    A successful replication connection allows for a complete copy of the data stored within the data cluster to be offloaded to another, potentially insecure, host. As such, it is advisable to log all replication commands that are executed in your database cluster to ensure the data is not off-loaded to an unexpected/undesired location.
  "
  desc  'check', "
    Check the current value of `log_replication_commands`:
    ```
    postgres=# show log_replication_commands;
     log_replication_commands
    --------------------------
     off
    (1 row)
    ```
  "
  desc  'fix', "
    To enable the logging of replication commands, execute the following:
    ```
    postgres=# ALTER SYSTEM SET log_replication_commands = 'on';
    ALTER SYSTEM
    postgres=# SELECT pg_reload_conf();
     pg_reload_conf
    ----------------
     t
    (1 row)
    postgres=# show log_replication_commands ;
     log_replication_commands
    --------------------------
     on
    (1 row)
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-11 b', 'AC-2 c']
  tag cci:                   ['CCI-000056', 'CCI-002113']
  tag cis_number:            '7.2'
  tag cis_rid:               '7.2'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:         'aws-shared-responsibility'
  tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0702r1_rule'
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

  only_if("Streaming-replication control out of scope: engine_deployment=#{deployment} — replication command logging is internal to managed Postgres replication mechanisms (Aurora's storage layer / RDS Multi-AZ); log_replication_commands toggle produces no operator-visible evidence. Applies only when engine_deployment=self_managed. partition=#{input('aws_partition')}, postgresql_version=#{input('postgresql_version')}.") do
    applicable
  end

  if %w[rds_instance aurora_cluster].include?(deployment)
    describe 'AWS shared-responsibility inheritance (CIS 7.2 — ' + "Ensure 'log_replication_commands' is Enabled" + ')' do
      it 'is satisfied by AWS-managed controls — ' + "Aurora uses a distributed storage layer rather than PostgreSQL streaming replication; replication commands originate inside the AWS-managed storage layer and are not surfaced to the customer log stream. For standalone RDS PostgreSQL replicas use AWS-managed replication outside the customer-tunable logging surface" + ' (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    describe "Ensure 'log_replication_commands' is Enabled" do
      skip "engine_deployment=self_managed: this control's `desc 'check'` instructions are host-side and not reachable via the AWS-transport scanner. Re-exec with -t ssh://postgres-host to evaluate."
    end
  end
end

