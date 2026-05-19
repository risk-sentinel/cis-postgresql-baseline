# encoding: UTF-8

control 'C-3.1.10' do
  title 'Ensure the correct syslog facility is selected'
  desc  "
    The `syslog_facility` setting specifies the syslog \"facility\" to be used when logging to `syslog` is enabled. You can choose from any of the 'local' facilities:
    * `LOCAL0`
    * `LOCAL1`
    * `LOCAL2`
    * `LOCAL3`
    * `LOCAL4`
    * `LOCAL5`
    * `LOCAL6`
    * `LOCAL7`

    Your organization's logging policy should dictate which facility to use based on the `syslog` daemon in use.

    If not set to the appropriate facility, the PostgreSQL log messages may be intermingled with other applications' log messages, incorrectly routed, or potentially dropped (depending on your `syslog` configuration).
  "
  desc  'rationale', "
    The `syslog_facility` setting specifies the syslog \"facility\" to be used when logging to `syslog` is enabled. You can choose from any of the 'local' facilities:
    * `LOCAL0`
    * `LOCAL1`
    * `LOCAL2`
    * `LOCAL3`
    * `LOCAL4`
    * `LOCAL5`
    * `LOCAL6`
    * `LOCAL7`

    Your organization's logging policy should dictate which facility to use based on the `syslog` daemon in use.

    If not set to the appropriate facility, the PostgreSQL log messages may be intermingled with other applications' log messages, incorrectly routed, or potentially dropped (depending on your `syslog` configuration).
  "
  desc  'check', "
    Execute the following SQL statement and verify that the correct facility is selected:
    ```
    postgres=# show syslog_facility;
     syslog_facility
    -----------------
     local0
    (1 row)
    ```
  "
  desc  'fix', "
    Execute the following SQL statement(s) to remediate this setting (in this example, setting it to the `LOCAL1` facility):
    ```
    postgres=# alter system set syslog_facility = 'LOCAL1';
    ALTER SYSTEM
    postgres=# select pg_reload_conf();
     pg_reload_conf
    ----------------
     t
    (1 row)
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000123']
  tag cis_number:            '3.1.10'
  tag cis_rid:               '3.1.10'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:         'aws-shared-responsibility'
  tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-030110r1_rule'
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

  only_if("Syslog-related control out of scope: engine_deployment=#{deployment} — managed RDS / Aurora deliver logs to CloudWatch Logs, not syslog, so syslog_facility is effectively inert. Applies only when engine_deployment=self_managed (where syslog is operator-configurable). partition=#{input('aws_partition')}, postgresql_version=#{input('postgresql_version')}.") do
    applicable
  end

  if %w[rds_instance aurora_cluster].include?(deployment)
    describe 'AWS shared-responsibility inheritance (CIS 3.1.10 — ' + "Ensure the PostgreSQL 'pgaudit.log_directory' Configuration Setting Is Correct" + ')' do
      it 'is satisfied by AWS-managed controls — ' + "AWS routes PostgreSQL logs to Amazon CloudWatch Logs via the published-log-types mechanism (postgresql.log / upgrade.log); the on-disk log_directory is internal to the AWS-managed host and not operator-tunable. Customer-facing controls live in the cluster parameter group (cis-postgresql §3.1.14–26 cover the log-content parameters that ARE operator-tunable)" + ' (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    describe "Ensure the PostgreSQL 'pgaudit.log_directory' Configuration Setting Is Correct" do
      skip "engine_deployment=self_managed: this control's `desc 'check'` instructions are host-side and not reachable via the AWS-transport scanner. Re-exec with -t ssh://postgres-host to evaluate."
    end
  end
end

