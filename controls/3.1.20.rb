# encoding: UTF-8

control 'C-3.1.20' do
  title 'Ensure \'log_connections\' is enabled'
  desc  "
    Enabling the `log_connections` setting causes each attempted connection to the server to be logged, as well as successful completion of client authentication. This parameter cannot be changed after the session start.

    PostgreSQL does not maintain an internal record of attempted connections to the database for later auditing. It is only by enabling the logging of these attempts that one can determine if unexpected attempts are being made. PostgreSQL introduced the below new options for this setting:

    - `receipt`
    - `authentication`
    - `authorization`
    - `setup_durations`
    - `all`

    For the purposes of backwards compatibility, `on`, `off`, `true`, `false`, `yes`, `no`, `1`, and `0` are still supported. The equivalent of `on` is `all`.

    Note that enabling this without also enabling `log_disconnections` provides little value. Generally, you would enable/disable the pair together.
  "
  desc  'rationale', "
    Enabling the `log_connections` setting causes each attempted connection to the server to be logged, as well as successful completion of client authentication. This parameter cannot be changed after the session start.

    PostgreSQL does not maintain an internal record of attempted connections to the database for later auditing. It is only by enabling the logging of these attempts that one can determine if unexpected attempts are being made. PostgreSQL introduced the below new options for this setting:

    - `receipt`
    - `authentication`
    - `authorization`
    - `setup_durations`
    - `all`

    For the purposes of backwards compatibility, `on`, `off`, `true`, `false`, `yes`, `no`, `1`, and `0` are still supported. The equivalent of `on` is `all`.

    Note that enabling this without also enabling `log_disconnections` provides little value. Generally, you would enable/disable the pair together.
  "
  desc  'check', "
    Execute the following SQL statement to verify the setting is enabled:
    ```
    postgres=# show log_connections;
     log_connections
    -----------------
    all 
    (1 row)
    ```
    If not configured to `all`, this is a fail.
  "
  desc  'fix', "
    Execute the following SQL statement(s) to enable this setting:
    ```
    postgres=# alter system set log_connections = 'all';
    ALTER SYSTEM
    postgres=# select pg_reload_conf();
     pg_reload_conf
    ----------------
     t
    (1 row)
    ```
    Then, in a new connection to the database, verify the change:
    ```
    postgres=# show log_connections;
     log_connections
    -----------------
     all
    (1 row)
    ```
    Note that you cannot verify this change in the same connection in which it was changed; a new connection is needed.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['IA-2 (2)', 'AU-3 a']
  tag cci:                   ['CCI-000766', 'CCI-000130']
  tag cis_number:            '3.1.20'
  tag cis_rid:               '3.1.20'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-030120r1_rule'
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
      its("parameter_value('log_connections')") { should cmp_pg_param("on") }
    end
  end
end
