# encoding: UTF-8

control 'C-4.1' do
  title 'Ensure Interactive Login is Disabled'
  desc  "
    When created, the PostgreSQL user may have interactive access to the operating system, which means that the PostgreSQL user could login to the host as any other user would.

    Preventing the PostgreSQL user from logging in interactively may reduce the impact of a compromised PostgreSQL account.
    There is also more accountability, as accessing the operating system where the PostgreSQL server lies will require the user's own account and the apprpriate `sudo` configuration.
    Interactive access by the PostgreSQL user is unnecessary and should be disabled.
  "
  desc  'rationale', "
    When created, the PostgreSQL user may have interactive access to the operating system, which means that the PostgreSQL user could login to the host as any other user would.

    Preventing the PostgreSQL user from logging in interactively may reduce the impact of a compromised PostgreSQL account.
    There is also more accountability, as accessing the operating system where the PostgreSQL server lies will require the user's own account and the apprpriate `sudo` configuration.
    Interactive access by the PostgreSQL user is unnecessary and should be disabled.
  "
  desc  'check', "
    Execute the following terminal command as low-privileged user to assess this recommendation:

    ```
    sudo grep postgres /etc/shadow | cut -d: -f1-2
    ```

    If this output is not `postgres:! ` then this is a failure.
  "
  desc  'fix', "
    Execute the following command:

    ```
    sudo passwd -l postgres
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 c']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS']
  tag nist_r4:               ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '4.1'
  tag cis_rid:               '4.1'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:           'aws-shared-responsibility'
  tag attestation_references:   ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0401r1_rule'
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