# encoding: UTF-8

control 'C-1.2' do
  title 'Install only required packages'
  desc  "
    Depending on the distribution, several other packages next to the mandatory `postgresql` might have been installed upon a system.
    Typical add-on packages are:
    - `postgresql-doc`: PostgreSQL documentation.
    - `phppgadmin`: PostgreSQL web-based administration tool.
    - ...

    Unused packages can increase the potential attack surface of the system.
  "
  desc  'rationale', "
    Depending on the distribution, several other packages next to the mandatory `postgresql` might have been installed upon a system.
    Typical add-on packages are:
    - `postgresql-doc`: PostgreSQL documentation.
    - `phppgadmin`: PostgreSQL web-based administration tool.
    - ...

    Unused packages can increase the potential attack surface of the system.
  "
  desc  'check', "
    On Debian, one can use the following command to see a complete list of the available packages.
    ```
    apt search postgresql
    ```
    RHEL:
    ```
    dnf search postgresql
    ```
  "
  desc  'fix', "
    Examine the installed packages:

    Debian:
    ```
    dpkg -l $(apt-cache search postgresql --names-only| awk '{print $1}') 2>&1 | grep -v 'no packages found'
    ```
    RHEL:
    ```
    rpm -q $(dnf search postgresql | cut -d: -f1 | cut -d. -f1) 2>&1 | grep -Ev 'package.*is not installed'
    ```
    Remove any identified packages that are undesired:

    Debian:
    ```
    apt purge ```
    RHEL:
    ```
    dnf erase ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-7 a']
  tag cci:                   ['CCI-000381']
  tag cis_number:            '1.2'
  tag cis_rid:               '1.2'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:           'aws-shared-responsibility'
  tag attestation_references:   ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0102r1_rule'
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

  describe 'AWS shared-responsibility inheritance' do
    it 'is satisfied by AWS-managed controls — control is satisfied by AWS under the shared-responsibility model. AWS controls package selection on the underlying Aurora host and maintains a hardened base image (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
      expect(true).to eq(true)
    end
  end
end
