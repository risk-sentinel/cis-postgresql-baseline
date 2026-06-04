# encoding: UTF-8

control 'C-1.3' do
  title 'Ensure systemd Service Files Are Enabled'
  desc  "
    Confirm, and correct if necessary, the PostgreSQL `systemd` service is enabled.

    Enabling the `systemd` service on the OS ensures the database service is active when a change of state occurs as in the case of a system startup or reboot.
  "
  desc  'rationale', "
    Confirm, and correct if necessary, the PostgreSQL `systemd` service is enabled.

    Enabling the `systemd` service on the OS ensures the database service is active when a change of state occurs as in the case of a system startup or reboot.
  "
  desc  'check', "
    Confirm the PostgreSQL service is enabled by executing the following:
    ```
    $ whoami
    root
    $ systemctl is-enabled postgresql-18.service
    enabled
    ```
    If the intended PostgreSQL service is not registered as a dependency (or \"want\") of the default target (anything other than 'enabled' is returned), this is a failure.
  "
  desc  'fix', "
    Irrespective of package source, PostgreSQL services can be identified because it typically includes the text string \"postgresql\". PGDG installs do not automatically register the service as a \"want\" of the default `systemd` target. Multiple instances of PostgreSQL services often distinguish themselves using a version number. 

    ```
    # whoami
    root
    # systemctl enable postgresql-18
    Created symlink /etc/systemd/system/multi-user.target.wants/postgresql-18.service → /usr/lib/systemd/system/postgresql-18.service.
    # systemctl is-enabled postgresql-18.service
    enabled
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 a', 'AC-2 a']
  tag cci:                   ['CCI-000364', 'CCI-002110']
  tag cis_number:            '1.3'
  tag cis_rid:               '1.3'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:           'aws-shared-responsibility'
  tag attestation_references:   ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0103r1_rule'
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

  uri = input('inherited_evidence_uri', value: '')
  uri = attestation_uri(:leveraged, 'aws-soc2-type2', ext: 'json') if uri.to_s.empty?
  max_age_days = input('leveraged_evidence_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'AWS shared-responsibility evidence (no leveraged source configured)' do
      skip 'inherited-from-aws: set leveraged_evidence_base / inherited_evidence_uri to the pulled AWS evidence manifest (SOC 2 / FedRAMP / ISO), or `saf attest apply`.'
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "AWS shared-responsibility leveraged evidence (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current within #{max_age_days}d") { expect(doc.current?).to eq(true) }
    end
  end
end