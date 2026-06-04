# encoding: UTF-8

control 'C-3.1.11' do
  title 'Ensure syslog messages are not suppressed'
  desc  "
    When logging to Syslog and `syslog_sequence_numbers` is on, then each message will be prefixed by an increasing sequence number (such as [2]).

    Many modern Syslog implementations perform a log optimization and suppress repeated log entries while emitting \"`--- last message repeated N times ---`\". In more modern Syslog implementations, repeated message suppression can be configured (for example, `$RepeatedMsgReduction` in `rsyslog`).
  "
  desc  'rationale', "
    When logging to Syslog and `syslog_sequence_numbers` is on, then each message will be prefixed by an increasing sequence number (such as [2]).

    Many modern Syslog implementations perform a log optimization and suppress repeated log entries while emitting \"`--- last message repeated N times ---`\". In more modern Syslog implementations, repeated message suppression can be configured (for example, `$RepeatedMsgReduction` in `rsyslog`).
  "
  desc  'check', "
    Execute the following SQL statement and confirm that the `syslog_sequence_numbers` is enabled (on):
    ```
    postgres=# show syslog_sequence_numbers;
     syslog_sequence_numbers
    -------------------------
     on
    (1 row)
    ```
  "
  desc  'fix', "
    Execute the following SQL statement(s) to remediate this setting:
    ```
    postgres=# alter system set syslog_sequence_numbers = 'on';
    ALTER SYSTEM
    postgres=# select pg_reload_conf();
     pg_reload_conf
    ----------------
     t
    (1 row)
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AU-3 a']
  tag cci:                   ['CCI-000130']
  tag cis_number:            '3.1.11'
  tag cis_rid:               '3.1.11'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:         'aws-shared-responsibility'
  tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-030111r1_rule'
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

  only_if("Syslog-related control out of scope: engine_deployment=#{deployment} — managed RDS / Aurora deliver logs to CloudWatch Logs, not syslog, so syslog_sequence_numbers is effectively inert. Applies only when engine_deployment=self_managed. partition=#{input('aws_partition')}, postgresql_version=#{input('postgresql_version')}.") do
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
    describe "Ensure the PostgreSQL 'pgaudit.log_filename' Configuration Setting Is Correct" do
      skip "engine_deployment=self_managed: this control's `desc 'check'` instructions are host-side and not reachable via the AWS-transport scanner. Re-exec with -t ssh://postgres-host to evaluate."
    end
  end
end