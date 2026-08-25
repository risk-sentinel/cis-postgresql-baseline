# encoding: UTF-8

control 'C-5.6' do
  title 'Ensure Password Complexity is configured'
  desc  "
    Password complexity configuration is crucial to restrict unauthorized access to data. By default, PostgreSQL doesn't provide for password complexity. Moreover, many compliance frameworks such as PCI DSS, and HIPPA require both password complexity and length. It is worth stating that the NIST 800-63B Password Guidelines publication is a good reference of authentication management.

    Having strong password management for your locally-authenticated PostgreSQL accounts will protect against attackers' brute force techniques. This is important especially if external authentication is not possible to implement due to application requirements or restrictions.
  "
  desc  'rationale', "
    Password complexity configuration is crucial to restrict unauthorized access to data. By default, PostgreSQL doesn't provide for password complexity. Moreover, many compliance frameworks such as PCI DSS, and HIPPA require both password complexity and length. It is worth stating that the NIST 800-63B Password Guidelines publication is a good reference of authentication management.

    Having strong password management for your locally-authenticated PostgreSQL accounts will protect against attackers' brute force techniques. This is important especially if external authentication is not possible to implement due to application requirements or restrictions.
  "
  desc  'check', "
    Check parameter values of both `shared_preload_libraries` and `dynamic_library_path`
    ```
    postgres=# SHOW shared_preload_libraries;
     shared_preload_libraries
    --------------------------
     set_user,pgaudit
    (1 row)
    postgres=# SHOW dynamic_library_path;
     dynamic_library_path
    ----------------------
     $libdir
    (1 row)
    ```
    If `$libdir/passwordcheck` is not listed in `shared_preload_libraries` this is a failure (based on `$libdir` being returned for `dynamic_library_path`).
  "
  desc  'fix', "
    Alter the `postgresql.conf` configuration file to enable `passwordcheck` as an extension in the `shared_preload_libraries` parameter and restart the PostgreSQL service:
    ```
    $ vi ${PGDATA}/postgresql.conf
    ```
    Find the `shared_preload_libraries` entry, and add `passwordcheck` to it (preserving any existing entries):
    ```
    shared_preload_libraries = '$libdir/passwordcheck'
    ```
    OR
    ```
    shared_preload_libraries = 'pgaudit,$libdir/passwordcheck,somethingelse'
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
  tag nist:                  ['IA-5 (1) (e)']
  tag cci:                   ['CCI-000200']
  tag cis_number:            '5.6'
  tag cis_rid:               '5.6'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag cis_rule_id:           'SV-0506r1_rule'
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

  # Consumer-policy attestation. document_attestation against
  # the boundary's own policy/register doc; empty -> Skip.
  uri = input('c_5_6_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-5.6') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'CIS 5.6 — Password complexity' do
      skip "Requires manual review and attestation provided for this control. Aurora-PostgreSQL doesn't ship the `passwordcheck` contrib module — Aurora consumers manage password complexity via parameter-group settings (`rds.force_ssl`, custom auth methods) and AWS-side controls (Secrets Manager rotation policies, IAM-DB-auth where applicable). Under the consumer's IAM-DB-auth posture this control is moot for the scanner identity; for application roles using stored passwords, operators attest the password-policy implementation. [Lift: set boundary_docs_base / c_5_6_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "CIS 5.6 — Password complexity (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current within #{max_age_days}d") { expect(doc.current?).to eq(true) }
    end
  end
end