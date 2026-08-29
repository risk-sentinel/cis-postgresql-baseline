# encoding: UTF-8

control 'C-2.3' do
  title 'Disable PostgreSQL Command History'
  desc  "
    On Linux/UNIX, the PostgreSQL client logs most interactive statements to a history file.
    The default PostgreSQL history file is named `.psql_history` in the user's home directory.

    The PostgreSQL command history should be disabled.

    Disabling the PostgreSQL command history reduces the probability of exposing
    sensitive information, such as passwords, encryption keys, or sensitive data.
  "
  desc  'rationale', "
    On Linux/UNIX, the PostgreSQL client logs most interactive statements to a history file.
    The default PostgreSQL history file is named `.psql_history` in the user's home directory.

    The PostgreSQL command history should be disabled.

    Disabling the PostgreSQL command history reduces the probability of exposing
    sensitive information, such as passwords, encryption keys, or sensitive data.
  "
  desc  'check', "
    Execute the following command as privileged user to assess this recommendation:
    ```
    sudo find /home -name \".psql_history\" -exec ls -la {} \\;
    sudo find /root -name \".psql_history\" -exec ls -la {} \\;
    ```
    For each file returned, determine whether that file is symbolically linked to `/dev/null`:
    ```
    lrwxrwxrwx 1 doug doug 9 Feb 26 18:18 /home/doug/.psql_history -> /dev/null
    lrwxrwxrwx 1 jim  jim  9 Feb 26 18:18 /home/jim/.psql_history
    ```
    In the above, Jim's history file is a finding, while Doug's is not.
  "
  desc  'fix', "
    For each OS user on the PostgreSQL server, perform the following steps to implement this setting:
    1. Remove `.psql_history` if it exists.
       ```
       rm -f ~ /.psql_history || true
       ```
    2. Use either of the techniques below to prevent it from being created again:

       1. Set the `HISTFILE` variable to `/dev/null` in `~ /.psqlrc`
          ```
          cat << EOF >> ~ /.psqlrc
          \\set HISTFILE /dev/null
          EOF
          ```
       2. Create `~ /.psql_history` as a symbolic to `/dev/null`.
          ```
          ln -s /dev/null $HOME/.psql_history
          ```
    3. Set the `PSQL_HISTORY` variable for all users:
       ```
       sudo echo 'PSQL_HISTORY=/dev/null' >> /etc/environment
       ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['MP-6 a']
  tag nist_r4:               ['MP-6 a']
  tag cci:                   ['CCI-001028']
  tag cis_number:            '2.3'
  tag cis_rid:               '2.3'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:         'aws-shared-responsibility'
  tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0203r1_rule'
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
    describe "Disable PostgreSQL Command History" do
      skip "engine_deployment=self_managed: this control's `desc 'check'` instructions are host-side and not reachable via the AWS-transport scanner. Re-exec with -t ssh://postgres-host to evaluate."
    end
  end
end