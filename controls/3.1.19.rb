# encoding: UTF-8

control 'C-3.1.19' do
  title 'Ensure \'debug_pretty_print\' is enabled'
  desc  "
    Enabling `debug_pretty_print` indents the messages produced by `debug_print_parse`, `debug_print_rewritten`, or `debug_print_plan` making them significantly easier to read.

    If this setting is disabled, the \"compact\" format is used instead, significantly reducing the readability of the `DEBUG` statement log messages.
  "
  desc  'rationale', "
    Enabling `debug_pretty_print` indents the messages produced by `debug_print_parse`, `debug_print_rewritten`, or `debug_print_plan` making them significantly easier to read.

    If this setting is disabled, the \"compact\" format is used instead, significantly reducing the readability of the `DEBUG` statement log messages.
  "
  desc  'check', "
    Execute the following SQL statement to confirm the setting is enabled:
    ```
    postgres=# show debug_pretty_print;
     debug_pretty_print
    --------------------
     on
    (1 row)
    ```
    If not configured to `on`, this is a fail.
  "
  desc  'fix', "
    Execute the following SQL statement(s) to enable this setting:
    ```
    postgres=# alter system set debug_pretty_print = 'on';
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
  tag nist:                  ['IA-2 (2)', 'AU-3 a']
  tag nist_r4:               ['AU-3', 'IA-2 (2)']
  tag cci:                   ['CCI-000766', 'CCI-000130']
  tag cis_number:            '3.1.19'
  tag cis_rid:               '3.1.19'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-030119r1_rule'
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
      its("parameter_value('debug_pretty_print')") { should cmp_pg_param("on") }
    end
  end
end
