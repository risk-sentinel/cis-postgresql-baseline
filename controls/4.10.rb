# encoding: UTF-8

control 'C-4.10' do
  title 'Ensure all accounts that can log in have passwords'
  desc  "
    If not using certificate-based authentication, all database accounts that have the ability to login should have a password set.

    All accounts that can login to the database should challenge the user for an SSL certificate or an account password.
  "
  desc  'rationale', "
    If not using certificate-based authentication, all database accounts that have the ability to login should have a password set.

    All accounts that can login to the database should challenge the user for an SSL certificate or an account password.
  "
  desc  'check', "
    To find all the database users that can login and do not have a password:
    ```
    postgres=# SELECT rolname FROM pg_authid WHERE rolpassword IS NULL AND rolcanlogin;
    ```
    If any accounts are returned that are not known to use SSL certificates, this is a  potential fail.
  "
  desc  'fix', "
    Set a valid password for any database user identified above.
    ```
    postgres=# \\password user1
    ```
    This shows setting the password for `user1`. You can use `ALTER ROLE`, but note that the passwords will be emitted to the PostgreSQL logs.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_number:            '4.10'
  tag cis_rid:               '4.10'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-0410r1_rule'
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

  # CIS 4.10 literal: every login-capable role must have a stored
  # password (`pg_authid.rolpassword IS NOT NULL`). Under managed
  # Postgres on AWS with IAM-DB-auth, login is gated by an IAM session
  # token, not a stored password — the literal check inverts. The
  # `inspec_scanner` user itself is the reference: a login role that
  # is `rds_iam` member with NO stored password.
  #
  # Reframed automation: every non-system login-capable role must
  # either be an `rds_iam` member (IAM-DB-auth posture) OR have a
  # stored password. We can observe `rds_iam` membership via the
  # public pg_auth_members / pg_roles views; we cannot read
  # `pg_authid.rolpassword` (scanner role has no grant — password
  # hashes are off-limits to the scanner).
  #
  # Implication of the unobservable rolpassword: a role that's NOT
  # rds_iam member may still have a valid stored password. So the
  # automated check is a conservative under-approximation: it FAILs
  # only when a non-system login role lacks rds_iam membership AND
  # the consumer hasn't allowlisted it via `cis_4_10_password_role_allowlist`
  # (for roles that genuinely use stored passwords).
  q = postgresql_query

  describe 'CIS 4.10 — DB-connection precheck' do
    subject { q.connection_error }
    it { should be_nil }
  end

  # Roles whose authentication mechanism cannot be observed (no rds_iam
  # membership). Consumer can allowlist roles that legitimately use
  # stored passwords via cis_4_10_password_role_allowlist.
  password_allowlist = (Array(input('postgresql_admin_role_allowlist')) + Array(input('cis_4_10_password_role_allowlist'))).map(&:to_s)
  sql = <<~SQL
    SELECT r.rolname
    FROM pg_roles r
    WHERE r.rolcanlogin = true
      AND r.rolname NOT LIKE 'pg\\_%'
      AND r.rolname NOT LIKE 'rds%'
      AND r.rolname <> 'postgres'
      AND r.oid NOT IN (
        SELECT m.member
        FROM pg_auth_members m
        JOIN pg_roles g ON g.oid = m.roleid
        WHERE g.rolname = 'rds_iam'
      );
  SQL
  offenders = q.query(sql).reject { |r| password_allowlist.include?(r['rolname']) }

  describe 'PostgreSQL login roles without IAM-DB-auth (CIS 4.10 — IAM-DB-auth posture)' do
    subject { offenders.map { |r| r['rolname'] } }
    it { should be_empty }
  end
end
