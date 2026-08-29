# encoding: UTF-8

control 'C-3.1.25' do
  title 'Ensure \'log_statement\' is set correctly'
  desc  "
    The `log_statement` setting specifies the types of SQL statements that are logged. Valid values are:
    * `none` (off)
    * `ddl`
    * `mod`
    * `all` (all statements)

    It is recommended this be set to `ddl` unless otherwise directed by your organization's logging policy.

    `ddl` logs all data definition statements:
    * `CREATE`
    * `ALTER`
    * `DROP` 

    `mod` logs all `ddl` statements, plus data-modifying statements:
    * `INSERT`
    * `UPDATE`
    * `DELETE`
    * `TRUNCATE`
    * `COPY FROM`

    (`PREPARE`, `EXECUTE`, and `EXPLAIN ANALYZE` statements are also logged if their contained command is of an appropriate type.)

    For clients using extended query protocol, logging occurs when an Execute message is received, and values of the Bind parameters are included (with any embedded single-quote marks doubled).

    Setting `log_statement` to align with your organization's security and logging policies facilitates later auditing and review of database activities.
  "
  desc  'rationale', "
    The `log_statement` setting specifies the types of SQL statements that are logged. Valid values are:
    * `none` (off)
    * `ddl`
    * `mod`
    * `all` (all statements)

    It is recommended this be set to `ddl` unless otherwise directed by your organization's logging policy.

    `ddl` logs all data definition statements:
    * `CREATE`
    * `ALTER`
    * `DROP` 

    `mod` logs all `ddl` statements, plus data-modifying statements:
    * `INSERT`
    * `UPDATE`
    * `DELETE`
    * `TRUNCATE`
    * `COPY FROM`

    (`PREPARE`, `EXECUTE`, and `EXPLAIN ANALYZE` statements are also logged if their contained command is of an appropriate type.)

    For clients using extended query protocol, logging occurs when an Execute message is received, and values of the Bind parameters are included (with any embedded single-quote marks doubled).

    Setting `log_statement` to align with your organization's security and logging policies facilitates later auditing and review of database activities.
  "
  desc  'check', "
    Execute the following SQL statement to verify the setting is correct:
    ```
    postgres=# show log_statement;
     log_statement
    ---------------
     none
    (1 row)
    ```
    If `log_statement` is set to `none` then this is a fail.
  "
  desc  'fix', "
    Execute the following SQL statement(s) as superuser to remediate this setting:
    ```
    postgres=# alter system set log_statement='ddl';
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
  tag cis_number:            '3.1.25'
  tag cis_rid:               '3.1.25'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-030125r1_rule'
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
      its("parameter_value('log_statement')") { should match_pg_param(/ddl|mod|all/i) }
    end
  end
end
