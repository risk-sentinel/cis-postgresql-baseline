# encoding: UTF-8

control 'C-6.2' do
  title 'Ensure \'backend\' runtime parameters are configured correctly'
  desc  "
    In order to serve multiple clients efficiently, the PostgreSQL server launches a new \"backend\" process for each client. The runtime parameters in this benchmark section are controlled by the backend process. The server's performance, in the form of slow queries causing a denial of service, and the RDBM's auditing abilities for determining root cause analysis can be potentially compromised via these parameters.

    A denial of service is possible by denying the use of indexes and by slowing down client access to an unreasonable level. Unsanctioned behavior can be introduced by introducing rogue libraries which can then be called in a database session. Logging can be altered and obfuscated inhibiting root cause analysis.
  "
  desc  'rationale', "
    In order to serve multiple clients efficiently, the PostgreSQL server launches a new \"backend\" process for each client. The runtime parameters in this benchmark section are controlled by the backend process. The server's performance, in the form of slow queries causing a denial of service, and the RDBM's auditing abilities for determining root cause analysis can be potentially compromised via these parameters.

    A denial of service is possible by denying the use of indexes and by slowing down client access to an unreasonable level. Unsanctioned behavior can be introduced by introducing rogue libraries which can then be called in a database session. Logging can be altered and obfuscated inhibiting root cause analysis.
  "
  desc  'check', "
    Issue the following command to verify the backend runtime parameters are configured correctly:
    ```
    postgres=# SELECT name, setting FROM pg_settings WHERE context IN ('backend','superuser-backend') ORDER BY 1;
             name          | setting
    -----------------------+---------
     ignore_system_indexes | off
     jit_debugging_support | off
     jit_profiling_support | off
     log_connections       | all
     log_disconnections    | on
     post_auth_delay       | 0
    (6 rows)
    ```
    Note: Effecting changes to these parameters can only be made at server start. Therefore, a successful exploit *may not be detected until after* a server restart, e.g., during a maintenance window.
  "
  desc  'fix', "
    Once detected, the unauthorized/undesired change can be corrected by altering the configuration file and executing a server restart. In the case where the parameter has been specified on the command-line invocation of `pg_ctl` the `restart` invocation is insufficient and an explicit `stop` and `start` must instead be made.
    1. Query the view `pg_settings` and compare with previous query outputs for any changes.
    2. Review configuration files `postgresql.conf` and `postgresql.auto.conf` and compare them with previously archived file copies for any changes.
    3. Examine the process output and look for parameters that were used at server startup:
       ```
       ps -few | grep -E -- '[p]ost.*-[D]'
       ```
    4. Examine the contents of `$PGDATA/postmaster.opts`
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 a']
  tag cci:                   ['CCI-000363']
  tag cis_number:            '6.2'
  tag cis_rid:               '6.2'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag cis_rule_id:           'SV-0602r1_rule'
  tag cis_version:           '1.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_version   = ['14', '15', '16', '17', '18'].include?(input('postgresql_version').to_s)
  applicable           = applicable_partition && applicable_version

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')}, postgresql_version=#{input('postgresql_version')})") do
    applicable
  end

  # VERIFY-don't-trust: when the consumer declares the
  # security-relevant runtime params for this category (#cis_6_2_expected_params = a
  # {param => expected_value} hash), assert the ACTUAL parameter-group values
  # rather than trusting an attestation. Undeclared -> attestation floor.
  expected = input('cis_6_2_expected_params', value: {})
  if expected.respond_to?(:empty?) && !expected.empty?
    postgresql_parameter_groups.each do |target|
      next if target[:pg_name].nil?
      if target[:resource].respond_to?(:connection_error) && target[:resource].connection_error
        describe "RDS DB Parameter Group: #{target[:pg_name]}" do
          skip "pending-resource: parameter-group lookup failed for #{target[:id]} — #{target[:resource].connection_error}"
        end
        next
      end
      describe target[:resource] do
        expected.each do |param, val|
          its("parameter_value('#{param}')") { should cmp_pg_param(val.to_s) }
        end
      end
    end
  else
    uri = input('c_6_2_attestation_uri', value: '')
    uri = attestation_uri(:boundary, 'C-6.2') if uri.to_s.empty?
    max_age_days = input('attestation_max_age_days', value: 365)
    if uri.to_s.empty?
      describe 'CIS 6.2 — Backend runtime parameter category review' do
        skip "Requires manual review and attestation provided for this control. CIS 6.2 is an awareness-level review of the `backend` runtime-parameter category (parameters set per-session by client connection). Aurora exposes these via parameter-group settings. The implementable bar is operator confirmation that the consumer's application-side connection-pool config doesn't override security-relevant backend parameters; that's a consumer-policy attestation, not a SQL check. [Lift: set boundary_docs_base / c_6_2_attestation_uri, or `saf attest apply`.] Declare cis_6_2_expected_params to VERIFY actual param values instead of attesting. [Lift: set boundary_docs_base / c_6_2_attestation_uri, or `saf attest apply`.]"
      end
    else
      doc = document_attestation(uri, max_age_days: max_age_days)
      describe "CIS 6.2 — Backend runtime parameter category review (#{uri})" do
        it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
        it('exists') { expect(doc.exists?).to eq(true) }
        it("current within #{max_age_days}d") { expect(doc.current?).to eq(true) }
      end
    end
  end
end