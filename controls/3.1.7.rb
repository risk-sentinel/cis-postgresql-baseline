# encoding: UTF-8

control 'C-3.1.7' do
  title 'Ensure \'log_truncate_on_rotation\' is enabled'
  desc  "
    Enabling the `log_truncate_on_rotation` setting when `logging_collector` is enabled causes PostgreSQL to truncate (overwrite) existing log files with the same name during log rotation instead of appending to them. For example, using this setting in combination with a `log_filename` setting value like `postgresql-%H.log` would result in generating 24 hourly log files and then cyclically overwriting them:
    ```
    postgresql-00.log
    postgresql-01.log
    [...]
    postgresql-23.log
    ``` 
    Note: Truncation will occur _only_ when a new file is being opened due to time-based rotation, not during server startup or size-based rotation (see later in this benchmark for size-based rotation details).

    If this setting is disabled, pre-existing log files will be appended to if `log_filename` is configured in such a way that static or recurring names are generated.

    Enabling or disabling the truncation should only be decided when also considering the value of `log_filename` and `log_rotation_age`/`log_rotation_size`. Some examples to illustrate the interaction between these settings:
    ```
    # truncation is moot, as each rotation gets a unique filename (postgresql-20180605.log)
    log_truncate_on_rotation = on
    log_filename = 'postgresql-%Y%m%d.log'
    log_rotation_age = '1d'
    log_rotation_size = 0
    ```
    ```
    # truncation every hour, losing log data every hour until the date changes
    log_truncate_on_rotation = on
    log_filename = 'postgresql-%Y%m%d.log'
    log_rotation_age = '1h'
    log_rotation_size = 0
    ```
    ```
    # no truncation if the date changed before generating 100M of log data, truncation otherwise
    log_truncate_on_rotation = on
    log_filename = 'postgresql-%Y%m%d.log'
    log_rotation_age = '0'
    log_rotation_size = '100M'
    ```
  "
  desc  'rationale', "
    Enabling the `log_truncate_on_rotation` setting when `logging_collector` is enabled causes PostgreSQL to truncate (overwrite) existing log files with the same name during log rotation instead of appending to them. For example, using this setting in combination with a `log_filename` setting value like `postgresql-%H.log` would result in generating 24 hourly log files and then cyclically overwriting them:
    ```
    postgresql-00.log
    postgresql-01.log
    [...]
    postgresql-23.log
    ``` 
    Note: Truncation will occur _only_ when a new file is being opened due to time-based rotation, not during server startup or size-based rotation (see later in this benchmark for size-based rotation details).

    If this setting is disabled, pre-existing log files will be appended to if `log_filename` is configured in such a way that static or recurring names are generated.

    Enabling or disabling the truncation should only be decided when also considering the value of `log_filename` and `log_rotation_age`/`log_rotation_size`. Some examples to illustrate the interaction between these settings:
    ```
    # truncation is moot, as each rotation gets a unique filename (postgresql-20180605.log)
    log_truncate_on_rotation = on
    log_filename = 'postgresql-%Y%m%d.log'
    log_rotation_age = '1d'
    log_rotation_size = 0
    ```
    ```
    # truncation every hour, losing log data every hour until the date changes
    log_truncate_on_rotation = on
    log_filename = 'postgresql-%Y%m%d.log'
    log_rotation_age = '1h'
    log_rotation_size = 0
    ```
    ```
    # no truncation if the date changed before generating 100M of log data, truncation otherwise
    log_truncate_on_rotation = on
    log_filename = 'postgresql-%Y%m%d.log'
    log_rotation_age = '0'
    log_rotation_size = '100M'
    ```
  "
  desc  'check', "
    Execute the following SQL statement to verify how `log_truncate_on_rotation` is set:
    ```
    postgres=# show log_truncate_on_rotation;
     log_truncate_on_rotation
    --------------------------
     on
    (1 row)
    ```
    If it is not set to `on`, this is a fail (depending on your organization's logging policy).
  "
  desc  'fix', "
    Execute the following SQL statement(s) to remediate this setting:
    ```
    postgres=# alter system set log_truncate_on_rotation = 'on';
    ALTER SYSTEM
    postgres=# select pg_reload_conf();
     pg_reload_conf
    ----------------
     t
    (1 row)
    postgres=# show log_truncate_on_rotation;
     log_truncate_on_rotation
    --------------------------
     on
    (1 row)
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 (2)', 'AU-4']
  tag ksi:                   ['KSI-IAM-AAM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-MLA-OSM']
  tag nist_r4:               ['AC-2 (2)', 'AU-4']
  tag cci:                   ['CCI-001682', 'CCI-001848']
  tag cis_number:            '3.1.7'
  tag cis_rid:               '3.1.7'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-030107r1_rule'
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
      its("parameter_value('log_truncate_on_rotation')") { should cmp_pg_param("on") }
    end
  end
end
