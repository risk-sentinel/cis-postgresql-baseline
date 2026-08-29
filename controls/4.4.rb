# encoding: UTF-8

control 'C-4.4' do
  title 'Lock Out Accounts if Not Currently in Use'
  desc  "
    If users with database accounts will not be using the database for some time, disabling the account will reduce the risk of attacks or inappropriate account usage.

    Only actively used database accounts should be allowed to login to the database.
  "
  desc  'rationale', "
    If users with database accounts will not be using the database for some time, disabling the account will reduce the risk of attacks or inappropriate account usage.

    Only actively used database accounts should be allowed to login to the database.
  "
  desc  'check', "
    Review the status of all database accounts:

    ```
    SELECT rolname FROM pg_catalog.pg_roles WHERE rolname !~ '^pg_' AND rolcanlogin;
    ```

    Inactive accounts should not be shown in the output.
  "
  desc  'fix', "
    To lock accounts, as a superuser, run:

    ```
    ALTER ROLE NOLOGIN;
    ```

    To unlock accounts, as a superuser, runL

    ```
    ALTER ROLE LOGIN;
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '4.4'
  tag cis_rid:               '4.4'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-0404r1_rule'
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
  describe 'CIS 4.4 — DB-connection precheck' do
    subject { q.connection_error }
    it { should be_nil }
  end

  # Inactivity-lockout proxy: any login-enabled non-system role with no
  # `rolvaliduntil` set is unbounded — it can authenticate indefinitely
  # regardless of activity. CIS 4.4's literal remediation is to set
  # VALID UNTIL on roles that should expire. The `cis_4_4_inactive_role_allowlist`
  # input lets operators exempt service-account roles that are
  # legitimately long-lived (e.g., the application's connection-pool
  # role, the IAM-DB-auth principal). Default empty allowlist = every
  # non-system login role must have a non-NULL rolvaliduntil.
  allowlist = (Array(input('postgresql_admin_role_allowlist')) + Array(input('cis_4_4_inactive_role_allowlist'))).map(&:to_s)
  sql = <<~SQL
    SELECT rolname, rolvaliduntil
    FROM pg_roles
    WHERE rolname NOT LIKE 'pg\\_%'
      AND rolname NOT LIKE 'rds%'
      AND rolname <> 'postgres'
      AND rolcanlogin = true
      AND rolvaliduntil IS NULL;
  SQL
  offenders = q.query(sql).reject { |r| allowlist.include?(r['rolname']) }

  describe 'PostgreSQL roles without VALID UNTIL (CIS 4.4)' do
    subject { offenders.map { |r| r['rolname'] } }
    it { should be_empty }
  end
end
