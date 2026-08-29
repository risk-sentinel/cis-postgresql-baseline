# encoding: UTF-8

control 'C-3.1.14' do
  title 'Ensure the correct messages are written to the server log'
  desc  "
    The `log_min_messages` setting specifies the message levels that are written to the server log. Each level includes all the levels that follow it. The lower the level (vertically, below), the fewer messages are logged.

    Valid values are:
    * `DEBUG5`        <-- exceedingly chatty
    * `DEBUG4`
    * `DEBUG3`
    * `DEBUG2`
    * `DEBUG1`
    * `INFO`
    * `NOTICE`
    * `WARNING`       <-- default
    * `ERROR`
    * `LOG`
    * `FATAL`
    * `PANIC`         <-- practically mute

    `WARNING` is considered the best practice unless indicated otherwise by your organization's logging policy.

    If this is not set to the correct value, too many or too few messages may be written to the server log.
  "
  desc  'rationale', "
    The `log_min_messages` setting specifies the message levels that are written to the server log. Each level includes all the levels that follow it. The lower the level (vertically, below), the fewer messages are logged.

    Valid values are:
    * `DEBUG5`        <-- exceedingly chatty
    * `DEBUG4`
    * `DEBUG3`
    * `DEBUG2`
    * `DEBUG1`
    * `INFO`
    * `NOTICE`
    * `WARNING`       <-- default
    * `ERROR`
    * `LOG`
    * `FATAL`
    * `PANIC`         <-- practically mute

    `WARNING` is considered the best practice unless indicated otherwise by your organization's logging policy.

    If this is not set to the correct value, too many or too few messages may be written to the server log.
  "
  desc  'check', "
    Execute the following SQL statement to confirm the setting is correct:
    ```
    postgres=# show log_min_messages;
     log_min_messages
    ------------------
     warning
    (1 row)
    ```
    If logging is not configured to at least `warning`, this is a fail.
  "
  desc  'fix', "
    Execute the following SQL statement(s) as superuser to remediate this setting (in this example, to set it to `warning`):
    ```
    postgres=# alter system set log_min_messages = 'warning';
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
  tag cci:                   ['CCI-001682', 'CCI-001848']
  tag cis_number:            '3.1.14'
  tag cis_rid:               '3.1.14'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-030114r1_rule'
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
      its("parameter_value('log_min_messages')") { should match_pg_param(/warning|notice|info|debug/i) }
    end
  end
end
