# encoding: UTF-8

control 'C-2.4' do
  title 'Ensure Passwords are Not Stored in the service file'
  desc  "
    One can set a `password` in a PostgreSQL connection service file. Verify the `password` option is not used in a connection service file.

    Using the `password` parameter may negatively impact the confidentiality of the user's password.
  "
  desc  'rationale', "
    One can set a `password` in a PostgreSQL connection service file. Verify the `password` option is not used in a connection service file.

    Using the `password` parameter may negatively impact the confidentiality of the user's password.
  "
  desc  'check', "
    To assess this recommendation, perform the following steps:

    ```
    sudo find / -name .pg_service.conf -type f -exec cat {} \\; 2>/dev/null | grep password
    sudo grep password /root/.pg_service.conf
    grep password \"${PGSERVICEFILE}\"
    grep password \"${PGSYSCONFDIR}/pg_service.conf\"
    ```

    If any of the commands above returns a line `password=...`, this is a finding.
  "
  desc  'fix', "
    Delete every `password` entry in the file(s) previously identified.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-28']
  tag cci:                   ['CCI-001199']
  tag cis_number:            '2.4'
  tag cis_rid:               '2.4'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:         'aws-shared-responsibility'
  tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0204r1_rule'
  tag cis_version:           '1.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  applicable_partition  = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_version    = ['14', '15', '16', '17', '18'].include?(input('postgresql_version').to_s)
  deployment            = input('engine_deployment').to_s
  deployment            = 'rds_instance' if deployment.empty?
  applicable            = applicable_partition && applicable_version

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')}, postgresql_version=#{input('postgresql_version')})") do
    applicable
  end

  uri = input('inherited_evidence_uri', value: '')
  uri = attestation_uri(:leveraged, 'aws-soc2-type2', ext: 'json') if uri.to_s.empty?
  max_age_days = input('leveraged_evidence_max_age_days', value: 365)
  if %w[rds_instance aurora_cluster].include?(deployment)
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
  else
    describe "Do Not Use a Cluster-Wide File for Password Storage" do
      skip "engine_deployment=self_managed: this control's `desc 'check'` instructions are host-side and not reachable via the AWS-transport scanner. Re-exec with -t ssh://postgres-host to evaluate."
    end
  end
end