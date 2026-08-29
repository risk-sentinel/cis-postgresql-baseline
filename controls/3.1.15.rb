# encoding: UTF-8

control 'C-3.1.15' do
  title 'Ensure the correct SQL statements generating errors are recorded'
  desc  "
    The `log_min_error_statement` setting causes all SQL statements generating errors at or above the specified severity level to be recorded in the server log. Each level includes all the levels that follow it. The lower the level (vertically, below), the fewer messages are recorded. Valid values are:
    * `DEBUG5`        <-- exceedingly chatty
    * `DEBUG4`
    * `DEBUG3`
    * `DEBUG2`
    * `DEBUG1`
    * `INFO`
    * `NOTICE`
    * `WARNING`
    * `ERROR`         <-- default
    * `LOG`
    * `FATAL`
    * `PANIC`         <-- practically mute

    `ERROR` is considered the best practice setting. Changes should only be made in accordance with your organization's logging policy.

    Note: To effectively turn off logging of failing statements, set this parameter to `PANIC`.

    If this is not set to the correct value, too many erring or too few erring SQL statements may be written to the server log.
  "
  desc  'rationale', "
    The `log_min_error_statement` setting causes all SQL statements generating errors at or above the specified severity level to be recorded in the server log. Each level includes all the levels that follow it. The lower the level (vertically, below), the fewer messages are recorded. Valid values are:
    * `DEBUG5`        <-- exceedingly chatty
    * `DEBUG4`
    * `DEBUG3`
    * `DEBUG2`
    * `DEBUG1`
    * `INFO`
    * `NOTICE`
    * `WARNING`
    * `ERROR`         <-- default
    * `LOG`
    * `FATAL`
    * `PANIC`         <-- practically mute

    `ERROR` is considered the best practice setting. Changes should only be made in accordance with your organization's logging policy.

    Note: To effectively turn off logging of failing statements, set this parameter to `PANIC`.

    If this is not set to the correct value, too many erring or too few erring SQL statements may be written to the server log.
  "
  desc  'check', "
    Execute the following SQL statement to verify the setting is correct:
    ```
    postgres=# show log_min_error_statement;
     log_min_error_statement
    -------------------------
     error
    (1 row)
    ```
    If not configured to at least `error`, this is a fail.
  "
  desc  'fix', "
    Execute the following SQL statement(s) as superuser to remediate this setting (in the example, to `error`):
    ```
    postgres=# alter system set log_min_error_statement = 'error';
    ALTER SYSTEM
    postgres=# select pg_reload_conf();
     pg_reload_conf
    ----------------
     t
    (1 row)
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 (2)', 'AU-4']
  tag nist_r4:               ['AC-2 (2)', 'AU-4']
  tag cci:                   ['CCI-001682', 'CCI-001848']
  tag cis_number:            '3.1.15'
  tag cis_rid:               '3.1.15'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-030115r1_rule'
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

  postgresql_parameter_groups.each do |target|
    next if target[:pg_name].nil?
    if target[:resource].respond_to?(:connection_error) && target[:resource].connection_error
      describe "RDS DB Parameter Group: #{target[:pg_name]}" do
        skip "pending-resource: parameter-group lookup failed for #{target[:id]} — #{target[:resource].connection_error}"
      end
      next
    end
    describe target[:resource] do
      its("parameter_value('log_min_error_statement')") { should match_pg_param(/error|warning|notice|info|debug/i) }
    end
  end
end
