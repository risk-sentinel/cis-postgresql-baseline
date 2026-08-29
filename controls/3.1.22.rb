# encoding: UTF-8

control 'C-3.1.22' do
  title 'Ensure \'log_error_verbosity\' is set correctly'
  desc  "
    The `log_error_verbosity` setting specifies the verbosity (amount of detail) of logged messages. Valid values are:
    * `TERSE`
    * `DEFAULT`
    * `VERBOSE`

    with each containing the fields of the level above it as well as additional fields.

    `TERSE` excludes the logging of `DETAIL`, `HINT`, `QUERY`, and `CONTEXT` error information. 

    `VERBOSE` output includes the `SQLSTATE`, error code, and the source code file name, function name, and line number that generated the error.

    The appropriate value should be set based on your organization's logging policy.

    If this is not set to the correct value, too many details or too few details may be logged.
  "
  desc  'rationale', "
    The `log_error_verbosity` setting specifies the verbosity (amount of detail) of logged messages. Valid values are:
    * `TERSE`
    * `DEFAULT`
    * `VERBOSE`

    with each containing the fields of the level above it as well as additional fields.

    `TERSE` excludes the logging of `DETAIL`, `HINT`, `QUERY`, and `CONTEXT` error information. 

    `VERBOSE` output includes the `SQLSTATE`, error code, and the source code file name, function name, and line number that generated the error.

    The appropriate value should be set based on your organization's logging policy.

    If this is not set to the correct value, too many details or too few details may be logged.
  "
  desc  'check', "
    Execute the following SQL statement to verify the setting is correct:
    ```
    postgres=# show log_error_verbosity;
     log_error_verbosity
    ---------------------
     default
    (1 row)
    ```
    If not configured to `verbose`, this is a fail.
  "
  desc  'fix', "
    Execute the following SQL statement(s) as superuser to remediate this setting (in this example, to `verbose`):
    ```
    postgres=# alter system set log_error_verbosity = 'verbose';
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
  tag cis_number:            '3.1.22'
  tag cis_rid:               '3.1.22'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-030122r1_rule'
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
      its("parameter_value('log_error_verbosity')") { should match_pg_param(/verbose|default/i) }
    end
  end
end
