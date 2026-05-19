# encoding: UTF-8

control 'C-5.5' do
  title 'Ensure per-account connection limits are used'
  desc  "
    Limiting concurrent connections to a PostgreSQL server can be used to reduce the risk of Denial of Service (DoS) attacks.

    Limiting the number of concurrent sessions at the user level helps to reduce the risk of DoS attacks.
  "
  desc  'rationale', "
    Limiting concurrent connections to a PostgreSQL server can be used to reduce the risk of Denial of Service (DoS) attacks.

    Limiting the number of concurrent sessions at the user level helps to reduce the risk of DoS attacks.
  "
  desc  'check', "
    To check the connection limits for all users, run the following:

    ```
    SELECT rolname, rolconnlimit
    FROM pg_roles
    WHERE rolname NOT LIKE 'pg_%';
    ```

    Any user with a connection limit of `-1` should be considered a failure.
  "
  desc  'fix', "
    Set a per-user connection limit by running:
    ```
     ALTER USER CONNECTION LIMIT ;
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.5'
  tag cis_rid:               '5.5'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-0505r1_rule'
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

  q = aws_rds_aurora_psql_query

  # Connection-precheck — fails LOUDLY on no-endpoint-configured /
  # pg-missing / token-gen-failed / network-unreachable / auth-failed.
  describe 'CIS 5.5 — DB-connection precheck' do
    subject { q.connection_error }
    it { should be_nil }
  end

  # CIS 5.5 wants per-account connection limits set (rolconnlimit > 0
  # AND not -1 'unlimited'). System / RDS-managed roles have
  # rolconnlimit = -1 by design and are excluded. The
  # `cis_5_5_connection_limit_allowlist` input exempts additional roles
  # the consumer has declared as legitimately unlimited (e.g., the RDS
  # master user, which is unlimited by design and cannot be filtered
  # out by the hardcoded namespace prefix).
  allowlist = (Array(input('postgresql_admin_role_allowlist')) + Array(input('cis_5_5_connection_limit_allowlist'))).map(&:to_s)
  sql = <<~SQL
    SELECT rolname, rolconnlimit
    FROM pg_roles
    WHERE rolname NOT LIKE 'pg\_%'
      AND rolname NOT LIKE 'rds%'
      AND rolname <> 'postgres'
      AND rolconnlimit = -1;
  SQL
  offenders = q.query(sql).reject { |r| allowlist.include?(r['rolname']) }

  describe 'Non-system roles without per-account connection limit (CIS 5.5)' do
    subject { offenders.map { |r| r['rolname'] } }
    it { should be_empty }
  end
end
