# encoding: UTF-8

control 'C-3.1.13' do
  title 'Ensure the program name for PostgreSQL syslog messages is correct'
  desc  "
    The `syslog_ident` setting specifies the program name used to identify PostgreSQL messages in syslog logs. An example of a possible program name is `postgres`.

    If this is not set correctly, it may be difficult or impossible to distinguish PostgreSQL messages from other messages in Syslog logs.
  "
  desc  'rationale', "
    The `syslog_ident` setting specifies the program name used to identify PostgreSQL messages in syslog logs. An example of a possible program name is `postgres`.

    If this is not set correctly, it may be difficult or impossible to distinguish PostgreSQL messages from other messages in Syslog logs.
  "
  desc  'check', "
    Execute the following SQL statement to verify the program name is set correctly:
    ```
    postgres=# show syslog_ident;
     syslog_ident
    --------------
     postgres
    (1 row)
    ```
  "
  desc  'fix', "
    Execute the following SQL statement(s) to remediate this setting (in this example, assuming a program name of `proddb`):
    ```
    postgres=# alter system set syslog_ident = 'proddb';
    ALTER SYSTEM
    postgres=# select pg_reload_conf();
     pg_reload_conf
    ----------------
     t
    (1 row)
    postgres=# show syslog_ident;
     syslog_ident
    --------------
     proddb
    (1 row)
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['IA-2 (2)', 'AU-3 a']
  tag cci:                   ['CCI-000766', 'CCI-000130']
  tag cis_number:            '3.1.13'
  tag cis_rid:               '3.1.13'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:         'aws-shared-responsibility'
  tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-030113r1_rule'
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

  only_if("Syslog-related control out of scope: engine_deployment=#{deployment} — managed RDS / Aurora deliver logs to CloudWatch Logs, not syslog, so syslog_ident is effectively inert. Applies only when engine_deployment=self_managed. partition=#{input('aws_partition')}, postgresql_version=#{input('postgresql_version')}.") do
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
    describe "Ensure the PostgreSQL 'pgaudit.log_rotation_size' Configuration Setting Is Correct" do
      skip "engine_deployment=self_managed: this control's `desc 'check'` instructions are host-side and not reachable via the AWS-transport scanner. Re-exec with -t ssh://postgres-host to evaluate."
    end
  end
end