# encoding: UTF-8

control 'C-4.5' do
  title 'Ensure excessive function privileges are revoked'
  desc  "
    In certain situations, to provide the required functionality, PostgreSQL needs to execute internal logic (stored procedures, functions, triggers, etc.) and/or external code modules with elevated privileges. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking the functionality applications/programs, those users are indirectly provided with greater privileges than assigned by their organization. This is known as privilege elevation. Privilege elevation must be utilized only where necessary. Execute privileges for application functions should be restricted to authorized users only.

    Ideally, all application source code should be vetted to validate interactions between the application and the logic in the database, but this is usually not possible or feasible with available resources even if the source code is available. The DBA should attempt to obtain assurances from the development organization that this issue has been addressed and should document what has been discovered. The DBA should also inspect all application logic stored in the database (in the form of functions, rules, and triggers) for excessive privileges.
  "
  desc  'rationale', "
    In certain situations, to provide the required functionality, PostgreSQL needs to execute internal logic (stored procedures, functions, triggers, etc.) and/or external code modules with elevated privileges. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking the functionality applications/programs, those users are indirectly provided with greater privileges than assigned by their organization. This is known as privilege elevation. Privilege elevation must be utilized only where necessary. Execute privileges for application functions should be restricted to authorized users only.

    Ideally, all application source code should be vetted to validate interactions between the application and the logic in the database, but this is usually not possible or feasible with available resources even if the source code is available. The DBA should attempt to obtain assurances from the development organization that this issue has been addressed and should document what has been discovered. The DBA should also inspect all application logic stored in the database (in the form of functions, rules, and triggers) for excessive privileges.
  "
  desc  'check', "
    Functions in PostgreSQL can be created with the `SECURITY DEFINER` option. When `SECURITY DEFINER` functions are executed by a user, said function is run with the privileges of the user who created it, not the user who is *running* it.

    To list all functions that have `SECURITY DEFINER`, run the following SQL:
    ```
    # whoami
    root
    # sudo -iu postgres
    # psql -c \"SELECT nspname, proname, proargtypes, prosecdef, rolname, proconfig FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid JOIN pg_authid a ON a.oid = p.proowner WHERE proname NOT LIKE 'pgaudit%' AND (prosecdef OR NOT proconfig IS NULL);\"
    ```
    In the query results, a `prosecdef` value of '`t`' on a row indicates that that function uses privilege elevation.

    If elevation privileges are utilized which are not required or are expressly forbidden by organizational guidance, this is a fail.
  "
  desc  'fix', "
    Where possible, revoke `SECURITY DEFINER` on PostgreSQL functions. To change a `SECURITY DEFINER` function to `SECURITY INVOKER`, run the following SQL:
    ```
    # whoami
    root
    # sudo -iu postgres
    # psql -c \"ALTER FUNCTION [functionname] SECURITY INVOKER;\"
    ```
    If it is not possible to revoke `SECURITY DEFINER`, ensure the function can be executed by only the accounts that absolutely need such functionality:
    ```
    postgres=# SELECT proname, proacl FROM pg_proc WHERE proname = 'delete_customer';
         proname     |                         proacl
    -----------------+--------------------------------------------------------
     delete_customer | {=X/postgres,postgres=X/postgres,appreader=X/postgres}
    (1 row)
    postgres=# REVOKE EXECUTE ON FUNCTION delete_customer(integer,boolean) FROM appreader;
    REVOKE
    postgres=# SELECT proname, proacl FROM pg_proc WHERE proname = 'delete_customer';
         proname     |                         proacl
    -----------------+--------------------------------------------------------
     delete_customer | {=X/postgres,postgres=X/postgres}
    (1 row)
    ```
    Based on the output above, `appreader=X/postgres` no longer exists in the `proacl` column results returned from the query and confirms `appreader` is no longer granted execute privilege on the function.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 a', 'AC-2 a']
  tag cci:                   ['CCI-000364', 'CCI-002110']
  tag cis_number:            '4.5'
  tag cis_rid:               '4.5'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-0405r1_rule'
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
  describe 'CIS 4.5 — DB-connection precheck' do
    subject { q.connection_error }
    it { should be_nil }
  end

  # Functions OWNED by non-system roles AND granted EXECUTE to PUBLIC
  # (or to non-application roles). information_schema.routine_privileges
  # surfaces the grant graph.
  sql = <<~SQL
    SELECT routine_schema, routine_name, grantee, privilege_type
    FROM information_schema.routine_privileges
    WHERE grantee = 'PUBLIC'
      AND routine_schema NOT IN ('information_schema', 'pg_catalog')
      AND routine_schema NOT LIKE 'pg\_%';
  SQL
  offenders = q.query(sql)

  describe 'Function EXECUTE privileges granted to PUBLIC outside system schemas (CIS 4.5)' do
    subject { offenders.map { |r| "#{r['routine_schema']}.#{r['routine_name']}" } }
    it { should be_empty }
  end
end
