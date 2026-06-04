# encoding: UTF-8

control 'C-4.9' do
  title 'Make use of predefined roles'
  desc  "
    PostgreSQL provides a set of predefined roles that provide access to certain commonly needed privileged capabilities and information. Administrators can GRANT these roles to users and/or other roles in their environment, providing those users with access to the specified capabilities and information.

    In keeping with the principle of least privilege, judicious use of the PostgreSQL predefined roles can greatly limit the access to privileged, or superuser, access.
  "
  desc  'rationale', "
    PostgreSQL provides a set of predefined roles that provide access to certain commonly needed privileged capabilities and information. Administrators can GRANT these roles to users and/or other roles in their environment, providing those users with access to the specified capabilities and information.

    In keeping with the principle of least privilege, judicious use of the PostgreSQL predefined roles can greatly limit the access to privileged, or superuser, access.
  "
  desc  'check', "
    Review the list of all database roles that have `superuser` access and determine if one or more of the predefined roles would suffice for the needs of that role:

    ```
    # whoami
    postgres
    # psql
    postgres=# select rolname from pg_roles where rolsuper is true;
     rolname  
    ----------
     postgres
     doug
    (2 rows)
    ```
  "
  desc  'fix', "
    If you've determined that one or more of the predefined roles can be used, simply `GRANT` it:

    ```
    postgres=# GRANT pg_monitor TO doug;
    GRANT ROLE
    ```

    And then remove `superuser` from the account:

    ```
    postgres=# ALTER ROLE doug NOSUPERUSER;
    ALTER ROLE
    postgres=# select rolname from pg_roles where rolsuper is true;
     rolname  
    ----------
     postgres
    (1 row)
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 a', 'AC-2 a']
  tag cci:                   ['CCI-000364', 'CCI-002110']
  tag cis_number:            '4.9'
  tag cis_rid:               '4.9'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag cis_rule_id:           'SV-0409r1_rule'
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

  # Consumer-policy attestation (sparc-validate#154). document_attestation against
  # the boundary's own policy/register doc; empty -> Skip.
  uri = input('c_4_9_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-4.9') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'CIS 4.9 — Make use of predefined roles' do
      skip "Requires manual review and attestation provided for this control. Predefined-role usage (pg_monitor, pg_read_all_settings, pg_read_all_stats, etc.) is a consumer-policy decision documented in the role-design register. Operators attest from that register; the SQL surface (`SELECT * FROM pg_roles WHERE rolname LIKE 'pg\_%'`) lists what's available but doesn't tell us whether application roles SHOULD use them. [Lift: set boundary_docs_base / c_4_9_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "CIS 4.9 — Make use of predefined roles (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current within #{max_age_days}d") { expect(doc.current?).to eq(true) }
    end
  end
end