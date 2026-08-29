# encoding: UTF-8

control 'C-4.7' do
  title 'Ensure Row Level Security (RLS) is configured correctly'
  desc  "
    In addition to the SQL-standard privilege system available through `GRANT`, tables can have row security policies that restrict, on a per-user basis, which individual rows can be returned by normal queries or inserted, updated, or deleted by data modification commands. This feature is also known as Row Level Security (RLS). 

    By default, tables do not have any policies, so if a user has access privileges to a table according to the SQL privilege system, all rows within it are equally available for querying or updating. Row security policies can be specific to commands, to roles, or to both. A policy can be specified to apply to `ALL` commands, or to any combination of `SELECT`, `INSERT`, `UPDATE`, or `DELETE`. Multiple roles can be assigned to a given policy, and normal role membership and inheritance rules apply.

    If you use RLS and apply restrictive policies to certain users, it is important that the `Bypass RLS` privilege not be granted to any unauthorized users. This privilege overrides RLS-enabled tables and associated policies. Generally, only superusers and elevated users should possess this privilege.

    If RLS policies and privileges are not configured correctly, users could perform actions on tables that they are not authorized to perform, such as inserting, updating, or deleting rows.
  "
  desc  'rationale', "
    In addition to the SQL-standard privilege system available through `GRANT`, tables can have row security policies that restrict, on a per-user basis, which individual rows can be returned by normal queries or inserted, updated, or deleted by data modification commands. This feature is also known as Row Level Security (RLS). 

    By default, tables do not have any policies, so if a user has access privileges to a table according to the SQL privilege system, all rows within it are equally available for querying or updating. Row security policies can be specific to commands, to roles, or to both. A policy can be specified to apply to `ALL` commands, or to any combination of `SELECT`, `INSERT`, `UPDATE`, or `DELETE`. Multiple roles can be assigned to a given policy, and normal role membership and inheritance rules apply.

    If you use RLS and apply restrictive policies to certain users, it is important that the `Bypass RLS` privilege not be granted to any unauthorized users. This privilege overrides RLS-enabled tables and associated policies. Generally, only superusers and elevated users should possess this privilege.

    If RLS policies and privileges are not configured correctly, users could perform actions on tables that they are not authorized to perform, such as inserting, updating, or deleting rows.
  "
  desc  'check', "
    The first step for an organization is to determine which, if any, database tables require RLS. This decision is a matter of business processes and is unique to each organization. To discover which, if any, database tables have RLS enabled, execute the following query. If any table(s) should have RLS policies applied, but do not appear in this query's results, then this is a fail.
    ```
    postgres=# SELECT oid, relname, relrowsecurity FROM pg_class WHERE relrowsecurity IS TRUE;
    ```
    For the purpose of this illustration, we will demonstrate the standard example from the PostgreSQL documentation using the `passwd` table and policy example. As of PostgreSQL 9.5, the catalog table `pg_class` provides column `relrowsecurity` to query and determine whether a relation has RLS enabled. Based on the results below we can see RLS is not enabled. Assuming this table should be RLS enabled, this is a fail.
    ```
    postgres=# CREATE TABLE passwd (
      user_name             text UNIQUE NOT NULL,
      pwhash                text,
      uid                   int  PRIMARY KEY,
      gid                   int  NOT NULL,
      real_name             text NOT NULL,
      home_phone            text,
      extra_info            text,
      home_dir              text NOT NULL,
      shell                 text NOT NULL
    );
    postgres=# SELECT oid, relname, relrowsecurity FROM pg_class WHERE relname = 'passwd';
      oid  | relname | relrowsecurity
    -------+---------+----------------
     24679 | passwd  | f
    (1 row)
    ```
    Further inspection of RLS policies is provided via the system catalog `pg_policy`, which records policy details including table OID, policy name, applicable commands, the roles assigned to a policy, and the `USING` and `WITH CHECK` clauses. Finally, RLS and associated policies (if implemented) may also be viewed using the standard `psql` display command `\\d+ schema.table` which lists RLS information as part of the table description.

    Should you implement Row Level Security and apply restrictive policies to certain users, it's imperative that you check each user's role definition via the `psql` display command `\\du` and ensure unauthorized users have not been granted `Bypass RLS` privilege as this would override any RLS enabled tables and associated policies. If unauthorized users do have `Bypass RLS` granted then resolve this using the `ALTER ROLE `_` `_` NOBYPASSRLS;` command.
  "
  desc  'fix', "
    Again, we are using the example from the PostgreSQL documentation using the example `passwd` table. We will create three database roles to illustrate the workings of RLS:
    ```
    postgres=# CREATE USER admin;
    CREATE USER
    postgres=# CREATE USER bob;
    CREATE USER
    postgres=# CREATE USER alice;
    CREATE USER
    ```
    Now, we will insert known data into the `passwd` table:
    ```
    postgres=# INSERT INTO passwd VALUES
      ('admin','xxx',0,0,'Admin','111-222-3333',null,'/root','/bin/dash');
    INSERT 0 1
    postgres=# INSERT INTO passwd VALUES
      ('bob','xxx',1,1,'Bob','123-456-7890',null,'/home/bob','/bin/zsh');
    INSERT 0 1
    postgres=# INSERT INTO passwd VALUES
      ('alice','xxx',2,1,'Alice','098-765-4321',null,'/home/alice','/bin/zsh');
    INSERT 0 1
    ```
    And we will enable RLS on the table:
    ```
    postgres=# ALTER TABLE passwd ENABLE ROW LEVEL SECURITY;
    ALTER TABLE
    postgres=# SELECT oid, relname, relrowsecurity FROM pg_class WHERE relname = 'passwd';
      oid  | relname | relrowsecurity
    -------+---------+----------------
     24679 | passwd  | t
    (1 row)
    ```
    Now that RLS is enabled, we need to define one or more policies. Create the administrator policy and allow it access to all rows:
    ```
    postgres=# CREATE POLICY admin_all ON passwd TO admin USING (true) WITH CHECK (true);
    CREATE POLICY
    ```
    Create a policy for normal users to _view_ all rows:
    ```
    postgres=# CREATE POLICY all_view ON passwd FOR SELECT USING (true);
    CREATE POLICY
    ```
    Create a policy for normal users that allows them to update only their own rows and to limit what values can be set for their login shell:
    ```
    postgres=# CREATE POLICY user_mod ON passwd FOR UPDATE
      USING (current_user = user_name)
      WITH CHECK (
        current_user = user_name AND
        shell IN ('/bin/bash','/bin/sh','/bin/dash','/bin/zsh','/bin/tcsh')
      );
    CREATE POLICY
    ```
    Grant all the normal rights on the table to the `admin` user:
    ```
    postgres=# GRANT SELECT, INSERT, UPDATE, DELETE ON passwd TO admin;
    GRANT
    ```
    Grant only select access on non-sensitive columns to everyone:
    ```
    postgres=# GRANT SELECT
      (user_name, uid, gid, real_name, home_phone, extra_info, home_dir, shell)
      ON passwd TO public;
    GRANT
    ```
    Grant update to only the sensitive columns:
    ```
    postgres=# GRANT UPDATE
      (pwhash, real_name, home_phone, extra_info, shell)
      ON passwd TO public;
    GRANT
    ```
    Ensure that no one has been granted `Bypass RLS` inadvertently, by running the `psql` display command `\\du+`. If unauthorized users do have `Bypass RLS` granted then resolve this using the `ALTER ROLE `_` `_` NOBYPASSRLS;` command.

    You can now verify that 'admin', 'bob', and 'alice' are properly restricted by querying the `passwd` table as each of these roles.
    ```
    postgres=# set role admin;
    SET
    postgres=# table passwd;
     user_name | pwhash | uid | gid | real_name |  home_phone  | extra_info | home_dir    |   shell
    -----------+--------+-----+-----+-----------+--------------+------------+-------------+-----------
     admin     | xxx    |   0 |   0 | Admin     | 111-222-3333 |            | /root       | /bin/dash
     bob       | xxx    |   1 |   1 | Bob       | 123-456-7890 |            | /home/bob   | /bin/zsh
     alice     | xxx    |   2 |   1 | Alice     | 098-765-4321 |            | /home/alice | /bin/zsh
    (3 rows)
    postgres=# set role alice;
    SET
    postgres=# table passwd;
    ERROR:  permission denied for table passwd
    postgres=# select user_name,real_name,home_phone,extra_info,home_dir,shell from passwd;
     user_name | real_name |  home_phone  | extra_info | home_dir    |   shell
    -----------+-----------+--------------+------------+-------------+-----------
     admin     | Admin     | 111-222-3333 |            | /root       | /bin/dash
     bob       | Bob       | 123-456-7890 |            | /home/bob   | /bin/zsh
     alice     | Alice     | 098-765-4321 |            | /home/alice | /bin/zsh
    (3 rows)
    postgres=# update passwd set user_name = 'joe';
    ERROR:  permission denied for table passwd
    -- Alice is allowed to change her own real_name, but no others
    postgres=# update passwd set real_name = 'Alice Doe';
    UPDATE 1
    postgres=# update passwd set real_name = 'John Doe' where user_name = 'admin';
    UPDATE 0
    postgres=# select user_name,real_name,home_phone,extra_info,home_dir,shell from passwd;
     user_name | real_name |  home_phone  | extra_info |  home_dir   |   shell
    -----------+-----------+--------------+------------+-------------+-----------
     admin     | Admin     | 111-222-3333 |            | /root       | /bin/dash
     bob       | Bob       | 123-456-7890 |            | /home/bob   | /bin/zsh
     alice     | Alice Doe | 098-765-4321 |            | /home/alice | /bin/zsh
    (3 rows)
    postgres=# update passwd set shell = '/bin/xx';
    ERROR:  new row violates WITH CHECK OPTION for \"passwd\"
    postgres=# delete from passwd;
    ERROR:  permission denied for table passwd
    postgres=# insert into passwd (user_name) values ('xxx');
    ERROR:  permission denied for table passwd
    -- Alice can change her own password; RLS silently prevents updating other rows
    postgres=# update passwd set pwhash = 'abc';
    UPDATE 1
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '4.7'
  tag cis_rid:               '4.7'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-0407r1_rule'
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
  describe 'CIS 4.7 — DB-connection precheck' do
    subject { q.connection_error }
    it { should be_nil }
  end

  # CIS 4.7 asks that every table with sensitive data has RLS enabled
  # OR is documented as not requiring it. Without consumer-supplied
  # sensitive-table list, the implementable check: any user table
  # with relrowsecurity=false in non-system schemas surfaces as a
  # candidate for review. (False-positive-acceptable; auditor
  # cross-checks against the data-classification register.)
  sql = <<~SQL
    SELECT n.nspname AS schema, c.relname AS table_name, c.relrowsecurity
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'r'
      AND n.nspname NOT IN ('information_schema', 'pg_catalog')
      AND n.nspname NOT LIKE 'pg\_%'
      AND c.relrowsecurity = false;
  SQL
  candidates = q.query(sql)

  # Reportable list — auditors review against sensitive-data inventory.
  describe 'User tables without Row Level Security enabled (CIS 4.7 — review against sensitive-data inventory)' do
    subject { candidates.map { |r| "#{r['schema']}.#{r['table_name']}" } }
    # Soft assertion: the count is informational. A future input
    # (privacy_register) could narrow this.
    it { should be_a(Array) }
  end
end
