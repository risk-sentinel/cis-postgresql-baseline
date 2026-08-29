# encoding: UTF-8

control 'C-3.1.3' do
  title 'Ensure the logging collector is enabled'
  desc  "
    The logging collector is a background process that captures log messages sent to `stderr` and redirects them into log files. The `logging_collector` setting must be enabled in order for this process to run. It can only be set at the server start.

    The logging collector approach is often more useful than logging to `syslog`, since some types of messages might not appear in `syslog` output. One common example is dynamic-linker failure message; another may be error messages produced by scripts such as `archive_command`.

    Note: This setting _must_ be enabled when `log_destination` is either `stderr` or `csvlog` or logs _will be lost_. Certain other logging parameters require it as well.
  "
  desc  'rationale', "
    The logging collector is a background process that captures log messages sent to `stderr` and redirects them into log files. The `logging_collector` setting must be enabled in order for this process to run. It can only be set at the server start.

    The logging collector approach is often more useful than logging to `syslog`, since some types of messages might not appear in `syslog` output. One common example is dynamic-linker failure message; another may be error messages produced by scripts such as `archive_command`.

    Note: This setting _must_ be enabled when `log_destination` is either `stderr` or `csvlog` or logs _will be lost_. Certain other logging parameters require it as well.
  "
  desc  'check', "
    Execute the following SQL statement and confirm that the `logging_collector` is enabled (`on`):
    ```
    postgres=# show logging_collector;
     logging_collector
    -------------------
     on
    (1 row)
    ```
  "
  desc  'fix', "
    Execute the following SQL statement(s) to remediate this setting:
    ```
    postgres=# alter system set logging_collector = 'on';
    ALTER SYSTEM
    ```
    Unfortunately, this setting can only be changed at the server (re)start. As root, restart the PostgreSQL service for this change to take effect:
    ```
    # whoami
    root
    # systemctl restart postgresql-18
    # systemctl status postgresql-18|grep 'ago$'
       Active: active (running) since ; s ago
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-2 a', 'AU-3 a']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000123', 'CCI-000130']
  tag cis_number:            '3.1.3'
  tag cis_rid:               '3.1.3'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:           'aws-shared-responsibility'
  tag attestation_references:   ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-030103r1_rule'
  tag cis_version:           '1.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_version   = ['14', '15', '16', '17', '18'].include?(input('postgresql_version').to_s)
  applicable = applicable_partition && applicable_version

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')}, postgresql_version=#{input('postgresql_version')})") do
    applicable
  end

  uri = input('inherited_evidence_uri', value: '')
  uri = attestation_uri(:leveraged, 'aws-soc2-type2', ext: 'json') if uri.to_s.empty?
  max_age_days = input('leveraged_evidence_max_age_days', value: 365)
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
end