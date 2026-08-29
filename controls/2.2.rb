# encoding: UTF-8

control 'C-2.2' do
  title 'Ensure extension directory has appropriate ownership and permissions'
  desc  "
    The extension directory is the location of the PostgreSQL extensions. Extensions are storage engines or user defined functions (UDFs).

    Limiting the accessibility of these objects will protect the confidentiality, integrity, and availability of the PostgreSQL database. If someone can modify extensions, then these extensions can be used to execute illicit instructions.
  "
  desc  'rationale', "
    The extension directory is the location of the PostgreSQL extensions. Extensions are storage engines or user defined functions (UDFs).

    Limiting the accessibility of these objects will protect the confidentiality, integrity, and availability of the PostgreSQL database. If someone can modify extensions, then these extensions can be used to execute illicit instructions.
  "
  desc  'check', "
    Determine the PostgreSQL share directory:

    ```
    sudo /usr/pgsql-18/bin/pg_config --sharedir
    /usr/pgsql-18/share
    ```

    The extension directory, lives under that share directory:
    ```
    sudo export ext_dir=/usr/pgsql-18/share/extension
    sudo ls -ld $ext_dir
    ```
    This should return:
    ```
    drwxr-xr-x 1 root root 7826 Feb  9 14:27 /usr/pgsql-18/share/extension
    ```

    Any differences in permissions (the first field) is a failure.
  "
  desc  'fix', "
    If needed, correct the permissions on the extension dir by eecuting:
    ```
    sudo chown root:root $ext_dir
    sudo chmod 0755 $ext_dir
    ```

    If the permissions needed correct, it is *imperative* that all extensions found in `$ext_dir` are evaluated to ensure they have not been modified!
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213']
  tag cis_number:            '2.2'
  tag cis_rid:               '2.2'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:           'aws-shared-responsibility'
  tag attestation_references:   ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0202r1_rule'
  tag cis_version:           '1.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_version   = ['14', '15', '16', '17', '18'].include?(input('postgresql_version').to_s)
  applicable = applicable_partition && applicable_version

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