# encoding: UTF-8

control 'C-3.2' do
  title 'Ensure the PostgreSQL Audit Extension (pgAudit) is enabled'
  desc  "
    The PostgreSQL Audit Extension ([pgAudit](https://www.pgaudit.org/)) provides detailed session and/or object audit logging via the standard PostgreSQL logging facility. The goal of pgAudit is to provide PostgreSQL users with the capability to produce audit logs often required to comply with government, financial, or ISO certifications.

    Basic statement logging can be provided by the standard logging facility with `log_statement = all`. This is acceptable for monitoring and other uses but does not provide the level of detail generally required for an audit. It is not enough to have a list of all the operations performed against the database, it must also be possible to find particular statements that are of interest to an auditor. The standard logging facility shows what the user requested, while pgAudit focuses on the details of what happened while the database was satisfying the request.

    When logging `SELECT` and `DML` statements, pgAudit can be configured to log a separate entry for each relation referenced in a statement. No parsing is required to find all statements that touch a particular table. In fact, the goal is that the statement text is provided primarily for deep forensics and should not be required for an audit.
  "
  desc  'rationale', "
    The PostgreSQL Audit Extension ([pgAudit](https://www.pgaudit.org/)) provides detailed session and/or object audit logging via the standard PostgreSQL logging facility. The goal of pgAudit is to provide PostgreSQL users with the capability to produce audit logs often required to comply with government, financial, or ISO certifications.

    Basic statement logging can be provided by the standard logging facility with `log_statement = all`. This is acceptable for monitoring and other uses but does not provide the level of detail generally required for an audit. It is not enough to have a list of all the operations performed against the database, it must also be possible to find particular statements that are of interest to an auditor. The standard logging facility shows what the user requested, while pgAudit focuses on the details of what happened while the database was satisfying the request.

    When logging `SELECT` and `DML` statements, pgAudit can be configured to log a separate entry for each relation referenced in a statement. No parsing is required to find all statements that touch a particular table. In fact, the goal is that the statement text is provided primarily for deep forensics and should not be required for an audit.
  "
  desc  'check', "
    First, as the database administrator (shown here as \"postgres\"), verify pgAudit is enabled by running the following commands: 
    ```
    postgres=# show shared_preload_libraries;
     shared_preload_libraries
    --------------------------
    pgaudit
    (1 row)
    ```
    If the output does not contain \"pgaudit\", this is a fail. 

    Next, verify that desired auditing components are enabled: 
    ```
    postgres=# show pgaudit.log;
    ERROR:  unrecognized configuration parameter \"pgaudit.log\"
    ```
    If the output does not contain the desired auditing components, this is a fail. 

    The list below summarizes `pgAudit.log` components:
    * READ: `SELECT` and `COPY` when the source is a relation or a query.
    * WRITE: `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, and `COPY` when the destination is a relation.
    * FUNCTION: Function calls and `DO` blocks.
    * ROLE: Statements related to roles and privileges: `GRANT`, `REVOKE`, `CREATE/ALTER/DROP ROLE`.
    * DDL: All `DDL` that is not included in the `ROLE` class.
    * MISC: Miscellaneous commands, e.g. `DISCARD`, `FETCH`, `CHECKPOINT`, `VACUUM`.
  "
  desc  'fix', "
    To install and enable pgAudit, simply install the appropriate rpm from the PGDG repo:
    ```
    # whoami
    root
    # dnf -y install pgaudit_18
    [snip]
    Installed:
      pgaudit_18-18.0-1PGDG.rhel9.x86_64

    Complete!
    ```
    pgAudit is now installed and ready to be configured. Next, we need to alter the `postgresql.conf` configuration file to:
    * enable pgAudit as an extension in the `shared_preload_libraries` parameter
    * indicate which classes of statements we want to log via the `pgaudit.log` parameter

    and, finally, restart the PostgreSQL service:
    ```
    $ vi ${PGDATA}/postgresql.conf
    ```
    Find the `shared_preload_libraries` entry, and add 'pgaudit' to it (preserving any existing entries):
    ```
    shared_preload_libraries = 'pgaudit'

    OR

    shared_preload_libraries = 'pgaudit,somethingelse'
    ```
    Now, add a new `pgaudit`-specific entry:
    ```
    # for this example we are logging the ddl and write operations
    pgaudit.log='ddl,write'
    ```
    Restart the PostgreSQL server for changes to take affect:
    ```
    # whoami
    root
    # systemctl restart postgresql-18
    # systemctl status postgresql-18|grep 'ago$'
       Active: active (running) since [date] 10s ago
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'AU-2 a']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS', 'KSI-MLA-LET', 'KSI-MLA-OSM', 'KSI-MLA-RVL']
  tag nist_r4:               ['AC-2 f', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000123']
  tag cis_number:            '3.2'
  tag cis_rid:               '3.2'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-0302r1_rule'
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
      its("parameter_value('shared_preload_libraries')") { should match_pg_param(/pgaudit/i) }
    end
  end
end
