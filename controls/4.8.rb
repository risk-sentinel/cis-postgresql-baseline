# encoding: UTF-8

control 'C-4.8' do
  title 'Ensure the set_user extension is installed'
  desc  "
    PostgreSQL access to the superuser database role must be controlled and audited to prevent unauthorized access.

    Note: Prior to performing this audit you must create a `roletree` view. Here are the procedures to create this view:
    ```
    postgres=# 
    DROP VIEW IF EXISTS roletree;
    CREATE OR REPLACE VIEW roletree AS
    WITH RECURSIVE
    roltree AS (
      SELECT u.rolname AS rolname,
             u.oid AS roloid,
             u.rolcanlogin,
             u.rolsuper,
             '{}'::name[] AS rolparents,
             NULL::oid AS parent_roloid,
             NULL::name AS parent_rolname
      FROM pg_catalog.pg_authid u
      LEFT JOIN pg_catalog.pg_auth_members m on u.oid = m.member
      LEFT JOIN pg_catalog.pg_authid g on m.roleid = g.oid
      WHERE g.oid IS NULL
      UNION ALL
      SELECT u.rolname AS rolname,
             u.oid AS roloid,
             u.rolcanlogin,
             u.rolsuper,
             t.rolparents || g.rolname AS rolparents,
             g.oid AS parent_roloid,
             g.rolname AS parent_rolname
      FROM pg_catalog.pg_authid u
      JOIN pg_catalog.pg_auth_members m on u.oid = m.member
      JOIN pg_catalog.pg_authid g on m.roleid = g.oid
      JOIN roltree t on t.roloid = g.oid
    )
    SELECT
      r.rolname,
      r.roloid,
      r.rolcanlogin,
      r.rolsuper,
      r.rolparents
    FROM roltree r
    ORDER BY 1;
    ```

    Even when reducing and limiting the access to the superuser role as described earlier in this benchmark, it is still difficult to determine who accessed the superuser role and what actions were taken using that role. As such, it is ideal to prevent anyone from logging in as the superuser and forcing them to escalate their role. This model is used at the OS level by the use of `sudo` and should be emulated in the database. The `set_user` extension allows for this setup.
  "
  desc  'rationale', "
    PostgreSQL access to the superuser database role must be controlled and audited to prevent unauthorized access.

    Note: Prior to performing this audit you must create a `roletree` view. Here are the procedures to create this view:
    ```
    postgres=# 
    DROP VIEW IF EXISTS roletree;
    CREATE OR REPLACE VIEW roletree AS
    WITH RECURSIVE
    roltree AS (
      SELECT u.rolname AS rolname,
             u.oid AS roloid,
             u.rolcanlogin,
             u.rolsuper,
             '{}'::name[] AS rolparents,
             NULL::oid AS parent_roloid,
             NULL::name AS parent_rolname
      FROM pg_catalog.pg_authid u
      LEFT JOIN pg_catalog.pg_auth_members m on u.oid = m.member
      LEFT JOIN pg_catalog.pg_authid g on m.roleid = g.oid
      WHERE g.oid IS NULL
      UNION ALL
      SELECT u.rolname AS rolname,
             u.oid AS roloid,
             u.rolcanlogin,
             u.rolsuper,
             t.rolparents || g.rolname AS rolparents,
             g.oid AS parent_roloid,
             g.rolname AS parent_rolname
      FROM pg_catalog.pg_authid u
      JOIN pg_catalog.pg_auth_members m on u.oid = m.member
      JOIN pg_catalog.pg_authid g on m.roleid = g.oid
      JOIN roltree t on t.roloid = g.oid
    )
    SELECT
      r.rolname,
      r.roloid,
      r.rolcanlogin,
      r.rolsuper,
      r.rolparents
    FROM roltree r
    ORDER BY 1;
    ```

    Even when reducing and limiting the access to the superuser role as described earlier in this benchmark, it is still difficult to determine who accessed the superuser role and what actions were taken using that role. As such, it is ideal to prevent anyone from logging in as the superuser and forcing them to escalate their role. This model is used at the OS level by the use of `sudo` and should be emulated in the database. The `set_user` extension allows for this setup.
  "
  desc  'check', "
    Check if the extension is available by querying the `pg_available_extensions` table:
    ```
    postgres=# select * from pg_available_extensions where name = 'set_user';
     name | default_version | installed_version | comment
    ------+-----------------+-------------------+---------
    (0 rows)
    ```
    If the extension is not listed this is a fail.

    Identify roles that are superusers and can still login:
    ```
    postgres=# SELECT rolname FROM pg_authid WHERE rolsuper and rolcanlogin;
     rolname
    ---------
    postgres
    (1 rows)
    ```
    Identify any unprivileged roles that can log in directly that are granted a superuser role even if it is multiple layers removed:

    Note: If you have not done so already, follow the procedures in the description to create a `roletree` view.
    ```
    -- Verify there are no unexpected unprivileged roles that can login directly

    SELECT
      r.rolname,
      r.roloid,
      r.rolcanlogin,
      r.rolsuper,
      r.rolparents
    FROM roletree r
    ORDER BY 1;

    -- Verify there are no roles granted a superuser role even if it is multiple layers
    -- removed
    SELECT
      ro.rolname,
      ro.roloid,
      ro.rolcanlogin,
      ro.rolsuper,
      ro.rolparents
    FROM roletree ro
    WHERE (ro.rolcanlogin AND ro.rolsuper)
    OR
    (
        ro.rolcanlogin AND EXISTS
        (
          SELECT TRUE FROM roletree ri
          WHERE ri.rolname = ANY (ro.rolparents)
          AND ri.rolsuper
        )
    );
      rolname | roloid | rolcanlogin | rolsuper | rolparents
    ----------+--------+-------------+----------+------------
     postgres |     10 | t           | t        | {}
    (1 row)
    ```
    A lack of results is a pass.
  "
  desc  'fix', "
    We will install the `set_user` extension:
    ```
    # whoami
    root
    # dnf -y install set_user_18
    [snip]
    Installed:
      set_user_18-4.2.0-1.rhel9.1.x86_64

    Complete!
    ```

    Now that `set_user` is installed, we need to tell PostgreSQL to load its library:

    ```
    # whoami
    root
    # vi ~postgres/18/data/postgresql.conf
    ```
    Find the `shared_preload_libraries` entry, and add 'set_user' to it (preserving any existing entries):
    ```
    shared_preload_libraries = 'set_user'

    OR

    shared_preload_libraries = 'set_user,pgaudit,somethingelse'
    ```
    Restart the PostgreSQL server for changes to take effect:
    ```
    # systemctl restart postgresql-18
    # systemctl status postgresql-18|grep 'ago$'
       Active: active (running) since [timestamp]; 1s ago
    ```
    And now, we can install the extension with SQL:
    ```
    # su - postgres
    # psql
    postgres=# select * from pg_available_extensions where name = 'set_user';
      name   | default_version | installed_version |                  comment
    ---------+-----------------+-------------------+-----------------------------
    set_user | 4.2.0           |                   | similar to SET ROLE but with
             |                 |                   | added logging
    (1 row)

    postgres=# create extension set_user;
    CREATE EXTENSION
    postgres=# select * from pg_available_extensions where name = 'set_user';
      name   | default_version | installed_version |                  comment
    ---------+-----------------+-------------------+-----------------------------
    set_user | 4.2.0           | 4.2.0             | similar to SET ROLE but with
             |                 |                   | added logging
    (1 row)
    ```
    Now, we use `GRANT` to configure each DBA role to allow it to use the `set_user` functions. In the example below, we will configure my db user `doug`. (You would do this for each DBA's normal user role.)
    ```
    postgres=# grant execute on function set_user(text) to doug;
    GRANT
    postgres=# grant execute on function set_user_u(text) to doug;
    GRANT
    ```
    Connect to PostgreSQL as yourself and verify it works as expected:
    ```
    # whoami
    psql
    # psql -U doug -d postgres -h 127.0.0.1
    postgres=> select set_user('postgres');
    ERROR:  switching to superuser not allowed
    HINT:  Use 'set_user_u' to escalate.
    postgres=> select set_user_u('postgres');
     set_user_u
    ------------
     OK
    (1 row)
    postgres=# select current_user, session_user;
     current_user | session_user
    --------------+--------------
     postgres     | doug
    (1 row)
    postgres=# select reset_user();
     reset_user
    ------------
     OK
    (1 row)
    postgres=> select current_user, session_user;
     current_user | session_user
    --------------+--------------
     doug         | doug
    (1 row)
    ```
    Once all DBA's normal user accounts have been `GRANT`ed permission, revoke the ability to login as the `postgres` (superuser) user:
    ```
    postgres=# ALTER USER postgres NOLOGIN;
    ALTER ROLE
    ```
    Which results in:
    ```
    $ psql
    psql: FATAL:  role \"postgres\" is not permitted to log in
    $ psql -U doug -d postgres -h 127.0.0.1
    psql (18.0)
    ```

    Revoke SUPERUSER and/or LOGIN from any other roles that were previously identified:
    ```
    postgres=# ALTER USER usera NOSUPERUSER; -- revoke superuser
    ALTER ROLE
    postgres=# ALTER USER usera NOLOGIN; -- revoke login
    ALTER ROLE
    postgres=# ALTER USER usera NOSUPERUSER NOLOGIN; -- revoke both at once
    ALTER ROLE
    ```
    Note that we show dropping the privileges both individually and as one. Pick an appropriate version based on your application/business needs.

    Remove any escalated privileges on users granted indirectly that were previously identified using the `roletree` view:
     ```
    postgres=# REVOKE name_of_granting_role FROM bob; -- an example only
    REVOKE ROLE
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-11 b', 'AC-2 c']
  tag cci:                   ['CCI-000056', 'CCI-002113']
  tag cis_number:            '4.8'
  tag cis_rid:               '4.8'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'not-applicable'
  tag cis_rule_id:           'SV-0408r1_rule'
  tag cis_version:           '1.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  applicable_partition  = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_version    = ['14', '15', '16', '17', '18'].include?(input('postgresql_version').to_s)
  deployment            = input('engine_deployment').to_s
  deployment            = 'rds_instance' if deployment.empty?
  applicable_deployment = (deployment == 'self_managed')
  applicable            = applicable_partition && applicable_version && applicable_deployment

  impact 0.5
  impact 0.0 unless applicable

  only_if("set_user-extension control out of scope: engine_deployment=#{deployment} — AWS managed Postgres (RDS instance / Aurora) does not ship the `set_user` extension; the equivalent superuser-elevation guarantee is provided by the `rds_superuser` role abstraction. Applies only when engine_deployment=self_managed. partition=#{input('aws_partition')}, postgresql_version=#{input('postgresql_version')}.") do
    applicable
  end

  describe 'CIS 4.8 — set_user extension' do
    skip "engine_deployment=self_managed: this control's `desc 'check'` instructions query pg_available_extensions and audit superuser-elevation roles. Re-exec the profile with a host transport (or a DB connection that runs queries) to evaluate this control on the self-managed Postgres server."
  end
end
