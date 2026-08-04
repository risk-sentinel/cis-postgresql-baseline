# encoding: UTF-8

control 'C-4.6' do
  title 'Ensure excessive DML privileges are revoked'
  desc  "
    DML (insert, update, delete) operations at the table level should be restricted to only authorized users. PostgreSQL manages table-level DML permissions via the GRANT statement.

    Excessive DML grants can lead to unprivileged users changing or deleting information without proper authorization.
  "
  desc  'rationale', "
    DML (insert, update, delete) operations at the table level should be restricted to only authorized users. PostgreSQL manages table-level DML permissions via the GRANT statement.

    Excessive DML grants can lead to unprivileged users changing or deleting information without proper authorization.
  "
  desc  'check', "
    To audit excessive DML privileges, take an inventory of all users defined in the cluster using the `\\du+ *` SQL command, as well as all tables defined in the database using the `\\dt *.*` SQL command. Furthermore, the intersection matrix of tables and user grants can be obtained by querying system catalogs `pg_tables` and `pg_user`. Note that in PostgreSQL, users can be defined cluster-wide across all databases or for a specific database, while schemas and tables are specific to a particular database. Therefore, the commands below should be executed for each defined database in the cluster. With this information, inspect database table grants and determine if any are excessive for defined database users.
    ```
    postgres=# -- display all users defined in the cluster
    postgres=# \\x
    Expanded display is on.
    postgres=# \\du+ *

    List of roles
    -[ RECORD 1 ]-----------------------------------------------------------
    Role name   | pg_checkpoint
    Attributes  | Cannot login
    Description | 
    -[ RECORD 2 ]-----------------------------------------------------------
    Role name   | pg_create_subscription
    Attributes  | Cannot login
    Description | 
    -[ RECORD 3 ]-----------------------------------------------------------
    Role name   | pg_database_owner
    Attributes  | Cannot login
    Description | 
    -[ RECORD 4 ]-----------------------------------------------------------
    Role name   | pg_execute_server_program
    Attributes  | Cannot login
    Description | 
    -[ RECORD 5 ]-----------------------------------------------------------
    Role name   | pg_maintain
    Attributes  | Cannot login
    Description | 
    -[ RECORD 6 ]-----------------------------------------------------------
    Role name   | pg_monitor
    Attributes  | Cannot login
    Description | 
    -[ RECORD 7 ]-----------------------------------------------------------
    Role name   | pg_read_all_data
    Attributes  | Cannot login
    Description | 
    -[ RECORD 8 ]-----------------------------------------------------------
    Role name   | pg_read_all_settings
    Attributes  | Cannot login
    Description | 
    -[ RECORD 9 ]-----------------------------------------------------------
    Role name   | pg_read_all_stats
    Attributes  | Cannot login
    Description | 
    -[ RECORD 10 ]----------------------------------------------------------
    Role name   | pg_read_server_files
    Attributes  | Cannot login
    Description | 
    -[ RECORD 11 ]----------------------------------------------------------
    Role name   | pg_signal_autovacuum_worker
    Attributes  | Cannot login
    Description | 
    -[ RECORD 12 ]----------------------------------------------------------
    Role name   | pg_signal_backend
    Attributes  | Cannot login
    Description | 
    -[ RECORD 13 ]----------------------------------------------------------
    Role name   | pg_stat_scan_tables
    Attributes  | Cannot login
    Description | 
    -[ RECORD 14 ]----------------------------------------------------------
    Role name   | pg_use_reserved_connections
    Attributes  | Cannot login
    Description | 
    -[ RECORD 15 ]----------------------------------------------------------
    Role name   | pg_write_all_data
    Attributes  | Cannot login
    Description | 
    -[ RECORD 16 ]----------------------------------------------------------
    Role name   | pg_write_server_files
    Attributes  | Cannot login
    Description | 
    -[ RECORD 17 ]----------------------------------------------------------
    Role name   | postgres
    Attributes  | Superuser, Create role, Create DB, Replication, Bypass RLS
    Description | 

    postgres=# \\x
    Expanded display is off.
    postgres=# \\dt+ *.*
                                                            List of relations
           Schema       |           Name           |    Type     |  Owner   | Persistence | Access method
     |    Size    | Description
    --------------------+--------------------------+-------------+----------+-------------+--------------
    -+------------+-------------
     information_schema | sql_features             | table       | postgres | permanent   | heap
     | 104 kB     |
     information_schema | sql_implementation_info  | table       | postgres | permanent   | heap
     | 48 kB      |
     information_schema | sql_parts                | table       | postgres | permanent   | heap
     | 48 kB      |
     information_schema | sql_sizing               | table       | postgres | permanent   | heap
     | 48 kB      | postgres=# -- query all tables and user grants in the current database
    postgres=# -- the system catalogs 'information_schema' and 'pg_catalog' are
    excluded
    postgres=# select t.schemaname, t.tablename, u.usename,
         has_table_privilege(u.usename, t.tablename, 'select') as select,
         has_table_privilege(u.usename, t.tablename, 'insert') as insert,
         has_table_privilege(u.usename, t.tablename, 'update') as update,
         has_table_privilege(u.usename, t.tablename, 'delete') as delete
    from  pg_tables t, pg_user u
    where t.schemaname not in ('information_schema','pg_catalog');

     schemaname | tablename | usename | select | insert | update | delete
    ------------+-----------+---------+--------+--------+--------+--------
    (0 rows)
    ```
    For the example below, we illustrate using a single table `customer`, and two application users `appwriter` and `appreader`. The intention is for `appwriter` to have full select, insert, update, and delete rights and for `appreader` to only have select rights. We can query these privileges with the example below using the `has_table_privilege` function and filtering for just the table and roles in question.
    ```
    postgres=# select t.tablename, u.usename,
           has_table_privilege(u.usename, t.tablename, 'select') as select,
           has_table_privilege(u.usename, t.tablename, 'insert') as insert,
           has_table_privilege(u.usename, t.tablename, 'update') as update,
           has_table_privilege(u.usename, t.tablename, 'delete') as delete
    from   pg_tables t, pg_user u
    where  t.tablename = 'customer' 
    and    u.usename in ('appwriter','appreader');

    tablename |  usename  | select | insert | update | delete
    ----------+-----------+--------+--------+--------+--------
    customer  | appwriter | t      | t      | t      | t
    customer  | appreader | t      | t      | t      | t
    (2 rows)
    ```
    As depicted, both users have full privileges for the customer table. This is a fail.

    When inspecting database-wide results for all users and all table grants, employ a comprehensive approach. Collaboration with application developers is paramount to collectively determine only those database users that require specific DML privileges and on which tables.
  "
  desc  'fix', "
    If a given database user has been granted excessive DML privileges for a given database table, those privileges should be revoked immediately using the `REVOKE` SQL command.

    Continuing with the example above, remove unauthorized grants for `appreader` user using the `REVOKE` statement and verify the Boolean values are now false.
    ```
    postgres=# REVOKE INSERT, UPDATE, DELETE ON TABLE customer FROM appreader;
    REVOKE

    postgres=# select t.tablename, u.usename,
           has_table_privilege(u.usename, t.tablename, 'select') as select,
           has_table_privilege(u.usename, t.tablename, 'insert') as insert,
           has_table_privilege(u.usename, t.tablename, 'update') as update,
           has_table_privilege(u.usename, t.tablename, 'delete') as delete
    from   pg_tables t, pg_user u
    where  t.tablename = 'customer' 
    and    u.usename in ('appwriter','appreader');

    tablename |  usename  | select | insert | update | delete
    ----------+-----------+--------+--------+--------+--------
    customer  | appwriter | t      | t      | t      | t
    customer  | appreader | t      | f      | f      | f
    (2 rows)
    ```

    Note: For versions of PostgreSQL prior to version 15, [CVE-2018-1058](https://nvd.nist.gov/vuln/detail/CVE-2018-1058) is applicable and it is recommended that all privileges be revoked from the `public` schema for all users on all databases. If you have upgraded from one of these earlier releases, this CVE is not fixed for you during an upgrade. You can correct this CVE by issuing:
    ```
    postgres=# REVOKE CREATE ON SCHEMA public FROM PUBLIC;
    REVOKE
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 a', 'AC-2 a']
  tag cci:                   ['CCI-000364', 'CCI-002110']
  tag cis_number:            '4.6'
  tag cis_rid:               '4.6'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-0406r1_rule'
  tag cis_version:           '1.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_version   = ['14', '15', '16', '17', '18'].include?(input('postgresql_version').to_s)
  applicable_scope     = postgresql_in_scope?
  applicable           = applicable_partition && applicable_version && applicable_scope

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')}, postgresql_version=#{input('postgresql_version')}, scope=#{postgresql_scope_reason})") do
    applicable
  end

  q = postgresql_query

  # Connection-precheck — fails LOUDLY on no-endpoint-configured /
  # pg-missing / token-gen-failed / network-unreachable / auth-failed.
  describe 'CIS 4.6 — DB-connection precheck' do
    subject { q.connection_error }
    it { should be_nil }
  end

  # DML privileges (INSERT/UPDATE/DELETE/TRUNCATE) granted to PUBLIC
  # outside system schemas.
  sql = <<~SQL
    SELECT table_schema, table_name, privilege_type
    FROM information_schema.table_privileges
    WHERE grantee = 'PUBLIC'
      AND privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')
      AND table_schema NOT IN ('information_schema', 'pg_catalog')
      AND table_schema NOT LIKE 'pg\_%';
  SQL
  offenders = q.query(sql)

  describe 'DML (INSERT/UPDATE/DELETE/TRUNCATE) privileges granted to PUBLIC outside system schemas (CIS 4.6)' do
    subject { offenders.map { |r| "\#{r['table_schema']}.\#{r['table_name']}:\#{r['privilege_type']}" } }
    it { should be_empty }
  end
end
