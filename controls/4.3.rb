# encoding: UTF-8

control 'C-4.3' do
  title 'Ensure excessive administrative privileges are revoked'
  desc  "
    With respect to PostgreSQL administrative SQL commands, only superusers should have elevated privileges. PostgreSQL regular, or application, users should not possess the ability to create roles, create new databases, manage replication, or perform any other action deemed privileged. Typically, regular users should only be granted the minimal set of privileges commensurate with managing the application:
    * DDL (`create table`, `create view`, `create index`, etc.)
    * DML (`select`, `insert`, `update`, `delete`)

    Further, it has become best practice to create separate roles for DDL and DML. Given an application called 'payroll', one would create the following users:
    * `payroll_owner`
    * `payroll_user`

    Any DDL privileges would be granted to the `payroll_owner` account only, while DML privileges would be given to the `payroll_user` account only. This prevents accidental creation/altering/dropping of database objects by application code that runs as the `payroll_user` account.

    By not restricting global administrative commands to superusers only, regular users granted excessive privileges may execute administrative commands with unintended and undesirable results.
  "
  desc  'rationale', "
    With respect to PostgreSQL administrative SQL commands, only superusers should have elevated privileges. PostgreSQL regular, or application, users should not possess the ability to create roles, create new databases, manage replication, or perform any other action deemed privileged. Typically, regular users should only be granted the minimal set of privileges commensurate with managing the application:
    * DDL (`create table`, `create view`, `create index`, etc.)
    * DML (`select`, `insert`, `update`, `delete`)

    Further, it has become best practice to create separate roles for DDL and DML. Given an application called 'payroll', one would create the following users:
    * `payroll_owner`
    * `payroll_user`

    Any DDL privileges would be granted to the `payroll_owner` account only, while DML privileges would be given to the `payroll_user` account only. This prevents accidental creation/altering/dropping of database objects by application code that runs as the `payroll_user` account.

    By not restricting global administrative commands to superusers only, regular users granted excessive privileges may execute administrative commands with unintended and undesirable results.
  "
  desc  'check', "
    First, inspect the privileges granted to the database superuser (identified here as `postgres`) using the display command `psql -c \"\\du postgres\"` to establish a baseline for granted administrative privileges. Based on the output below, the `postgres` superuser can create roles, create databases, manage replication, and bypass row-level security (RLS):
    ```
    # whoami
    postgres
    # psql -c \"\\du+ postgres\"
                                  List of roles
    Role name |                    Attributes                   | Description
    ----------+-------------------------------------------------+-----------
    postgres  | Superuser, Create role, Create DB, Replication, | 
              | Bypass RLS                                      |
    ```
    Now, let's inspect the same information for a mock regular user called `appuser` using the display command `psql -c \"\\du+ appuser\"`. The output confirms that regular user `appuser` has the same elevated privileges as system administrator user `postgres`. This is a fail.
    ```
    # whoami
    postgres
    # psql -c \"\\du+ appuser\"
                                  List of roles
    Role name |                    Attributes                   | Description
    ----------+-------------------------------------------------+-----------
    appuser   | Superuser, Create role, Create DB, Replication, | 
              | Bypass RLS                                      |
    ```
    While this example demonstrated excessive administrative privileges granted to a single user, a comprehensive audit should be conducted to inspect all database users for excessive administrative privileges. This can be accomplished via either of the commands below.
    ```
    # whoami
    postgres
    # psql -c \"\\du+ *\"
    # psql -c \"select * from pg_user order by usename\"
    ```

    Note: Using `\\du+ *` will show all the default PostgreSQL roles (e.g. `pg_monitor`) as well as any 'normal' roles. This is expected, and should not be cause for alarm.
  "
  desc  'fix', "
    If any regular or application users have been granted excessive administrative rights, those privileges should be removed immediately via the PostgreSQL `ALTER ROLE` SQL command. Using the same example above, the following SQL statements revoke all unnecessary elevated administrative privileges from the regular user `appuser`:
    ```
    # whoami
    postgres
    # psql -c \"ALTER ROLE appuser NOSUPERUSER;\"
    ALTER ROLE
    # psql -c \"ALTER ROLE appuser NOCREATEROLE;\"
    ALTER ROLE
    # psql -c \"ALTER ROLE appuser NOCREATEDB;\"
    ALTER ROLE
    # psql -c \"ALTER ROLE appuser NOREPLICATION;\"
    ALTER ROLE
    # psql -c \"ALTER ROLE appuser NOBYPASSRLS;\"
    ALTER ROLE
    # psql -c \"ALTER ROLE appuser NOINHERIT;\"
    ALTER ROLE
    ```
    Verify the `appuser` now passes your check by having no defined Attributes:
    ```
    # whoami
    postgres
    # psql -c \"\\du+ appuser\"
              List of roles
    Role name | Attributes | Description
    ----------+------------+-----------
    appuser   |            | 
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 a', 'AC-2 a']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['AC-2 a', 'CM-6 a']
  tag cci:                   ['CCI-000364', 'CCI-002110']
  tag cis_number:            '4.3'
  tag cis_rid:               '4.3'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-0403r1_rule'
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
  # Without this, a failed connection returns [] from query, which
  # would silently pass `should be_empty` matchers.
  describe 'CIS 4.3 — DB-connection precheck' do
    subject { q.connection_error }
    it { should be_nil }
  end

  # Excessive admin privileges: any non-default role flagged with
  # rolsuper / rolcreaterole / rolcreatedb / rolreplication / rolbypassrls
  # OUTSIDE the recognised system-role namespace (pg_*, rds*). The
  # `cis_4_3_admin_role_allowlist` input exempts roles the consumer has
  # declared as legitimately privileged (e.g., the RDS master user,
  # which carries CREATEROLE/CREATEDB by design and cannot be
  # filtered out by the hardcoded namespace prefix).
  allowlist = (Array(input('postgresql_admin_role_allowlist')) + Array(input('cis_4_3_admin_role_allowlist'))).map(&:to_s)
  sql = <<~SQL
    SELECT rolname,
           rolsuper, rolcreaterole, rolcreatedb,
           rolreplication, rolbypassrls
    FROM pg_roles
    WHERE rolname NOT LIKE 'pg\\_%'
      AND rolname NOT LIKE 'rds%'
      AND rolname <> 'postgres'
      AND ( rolsuper       OR rolcreaterole
         OR rolcreatedb    OR rolreplication
         OR rolbypassrls   );
  SQL
  offenders = q.query(sql).reject { |r| allowlist.include?(r['rolname']) }

  describe 'Non-system roles with elevated administrative privileges (CIS 4.3)' do
    subject { offenders.map { |r| r['rolname'] } }
    it { should be_empty }
  end
end
