# encoding: UTF-8

control 'C-1.5' do
  title 'Ensure the Latest Security Patches are Applied'
  desc  "
    PostgreSQL updates are released to resolve bugs, and mitigate vulnerabilities quarterly (or sooner for drastic CVEs). It is recommended that PostgreSQL installations are kept up to date with the latest security updates. The PostgreSQL development group _guarantees_ that point releases (or \"minor releases\") _will not_ change the behavior of an existing install and as such are \"safe\" to install without fear of changes to your application's behavior.

    Maintaining parity with PostgreSQL patches will help reduce the risk associated with known vulnerabilities present in the PostgreSQL server.

    Without the latest security patches, PostgreSQL might have known vulnerabilities which could be used by an attacker to gain access.
  "
  desc  'rationale', "
    PostgreSQL updates are released to resolve bugs, and mitigate vulnerabilities quarterly (or sooner for drastic CVEs). It is recommended that PostgreSQL installations are kept up to date with the latest security updates. The PostgreSQL development group _guarantees_ that point releases (or \"minor releases\") _will not_ change the behavior of an existing install and as such are \"safe\" to install without fear of changes to your application's behavior.

    Maintaining parity with PostgreSQL patches will help reduce the risk associated with known vulnerabilities present in the PostgreSQL server.

    Without the latest security patches, PostgreSQL might have known vulnerabilities which could be used by an attacker to gain access.
  "
  desc  'check', "
    Execute the following SQL statement as low-privileged user to identify the PostgreSQL server version:

    ```
    SHOW server_version;
    ```

    Now compare the version returned with the security announcements shown on the PostgreSQL [news](https://www.postgresql.org/about/newsarchive/) page. For convenience, the latest PostgreSQL release versions are always shown in a banner at the top of that page along with the release date.
  "
  desc  'fix', "
    Install the latest patches available for your version:

    RHEL:
    ```
    sudo dnf update $(rpm -qa | grep '^postgresql')
    ```

    Debian:
    ```
    sudo apt-get install --only-upgrade $(dpkg-query -W -f '${db:Status-Status} ${Package}\\n' 'postgresql*' | awk '$1 != \"not-installed\" {print $NF}')
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['MA-3 a']
  tag cci:                   ['CCI-000865']
  tag cis_number:            '1.5'
  tag cis_rid:               '1.5'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:           'aws-shared-responsibility'
  tag attestation_references:   ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0105r1_rule'
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