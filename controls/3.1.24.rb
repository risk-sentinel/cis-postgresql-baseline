# encoding: UTF-8

control 'C-3.1.24' do
  title 'Ensure \'log_line_prefix\' is set correctly'
  desc  "
    The `log_line_prefix` setting specifies a `printf`-style string that is prefixed to each log line. If blank, no prefix is used. You should configure this as recommended by the [pgBadger](https://pgbadger.darold.net/) development team unless directed otherwise by your organization's logging policy.

    `%` characters begin \"escape sequences\" that are replaced with status information as outlined below. Unrecognized escapes are ignored. Other characters are copied straight to the logline. Some escapes are only recognized by session processes and will be treated as empty by background processes such as the main server process. Status information may be aligned either left or right by specifying a numeric literal after the `%` and before the option. A negative value will cause the status information to be padded on the right with spaces to give it a minimum width, whereas a positive value will pad on the left. Padding can be useful to aid human readability in log files. 

    Any of the following escape sequences can be used:

    ```
    %a = application name
    %u = user name
    %d = database name
    %r = remote host and port
    %h = remote host
    %b = backend type
    %p = process ID
    %P = process ID of parallel group leader
    %t = timestamp without milliseconds
    %m = timestamp with milliseconds
    %n = timestamp with milliseconds (as a Unix epoch)
    %Q = query ID (0 if none or not computed)
    %i = command tag
    %e = SQL state
    %c = session ID
    %l = session line number
    %s = session start timestamp
    %v = virtual transaction ID
    %x = transaction ID (0 if none)
    %q = stop here in non-session processes
    %% = '%'
    ```

    Properly setting `log_line_prefix` allows for adding additional information to each log entry (such as the user, or the database). Said information may then be of use in auditing or security reviews.
  "
  desc  'rationale', "
    The `log_line_prefix` setting specifies a `printf`-style string that is prefixed to each log line. If blank, no prefix is used. You should configure this as recommended by the [pgBadger](https://pgbadger.darold.net/) development team unless directed otherwise by your organization's logging policy.

    `%` characters begin \"escape sequences\" that are replaced with status information as outlined below. Unrecognized escapes are ignored. Other characters are copied straight to the logline. Some escapes are only recognized by session processes and will be treated as empty by background processes such as the main server process. Status information may be aligned either left or right by specifying a numeric literal after the `%` and before the option. A negative value will cause the status information to be padded on the right with spaces to give it a minimum width, whereas a positive value will pad on the left. Padding can be useful to aid human readability in log files. 

    Any of the following escape sequences can be used:

    ```
    %a = application name
    %u = user name
    %d = database name
    %r = remote host and port
    %h = remote host
    %b = backend type
    %p = process ID
    %P = process ID of parallel group leader
    %t = timestamp without milliseconds
    %m = timestamp with milliseconds
    %n = timestamp with milliseconds (as a Unix epoch)
    %Q = query ID (0 if none or not computed)
    %i = command tag
    %e = SQL state
    %c = session ID
    %l = session line number
    %s = session start timestamp
    %v = virtual transaction ID
    %x = transaction ID (0 if none)
    %q = stop here in non-session processes
    %% = '%'
    ```

    Properly setting `log_line_prefix` allows for adding additional information to each log entry (such as the user, or the database). Said information may then be of use in auditing or security reviews.
  "
  desc  'check', "
    Execute the following SQL statement to verify the setting is correct:
    ```
    postgres=# show log_line_prefix;
     log_line_prefix
    -----------------
     < %m [%p] >
    (1 row)
    ```
    If the prefix does not at a minimum include `%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h ` (for non-Syslog logging), this is a fail. For Syslog logging, the prefix should include `user=%u,db=%d,app=%a,client=%h `.
  "
  desc  'fix', "
    Execute the following SQL statement(s) to remediate this setting:
    ```
    postgres=# alter system set log_line_prefix = '%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h ';
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
  tag cci:                   ['CCI-000766', 'CCI-000130']
  tag cis_number:            '3.1.24'
  tag cis_rid:               '3.1.24'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-030124r1_rule'
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
      its("parameter_value('log_line_prefix')") { should be_pg_present }
    end
  end
end
