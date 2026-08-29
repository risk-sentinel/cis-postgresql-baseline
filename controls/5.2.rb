# encoding: UTF-8

control 'C-5.2' do
  title 'Ensure PostgreSQL is Bound to an IP Address'
  desc  "
    By default, `listen_addresses` is set to `localhost` which prevents any and all remote TCP connections to the PostgreSQL port.

    Some Docker images may set `listen_addesses` to `*`. `*` corresponds to all available IP interfaces; thus, the PostgreSQL server then accepts TCP connections on all the server's IPv6 and IPv4 interfaces. (The same is true for a setting of `0.0.0.0`.)

    You can make this configuration more restrictive by setting the `listen_addresses` configuration option to a specific list of IPv4 or IPv6 address so that the server only accepts TCP connections on those addresses.

    This parameter can only be set at server start.

    Limiting the IP addresses that PostgreSQL listens on provides additional restrictions on where client applications/users can connect from.
  "
  desc  'rationale', "
    By default, `listen_addresses` is set to `localhost` which prevents any and all remote TCP connections to the PostgreSQL port.

    Some Docker images may set `listen_addesses` to `*`. `*` corresponds to all available IP interfaces; thus, the PostgreSQL server then accepts TCP connections on all the server's IPv6 and IPv4 interfaces. (The same is true for a setting of `0.0.0.0`.)

    You can make this configuration more restrictive by setting the `listen_addresses` configuration option to a specific list of IPv4 or IPv6 address so that the server only accepts TCP connections on those addresses.

    This parameter can only be set at server start.

    Limiting the IP addresses that PostgreSQL listens on provides additional restrictions on where client applications/users can connect from.
  "
  desc  'check', "
    Run the following statement:
    ```
    SHOW listen_addresses;
    ```
    If `*` or `0.0.0.0` is returned, this is a failure.
  "
  desc  'fix', "
    To have the PostgreSQL server only accept connections on a specific IP address, add an entry similar to this in the PostgreSQL configuration file `postgresql.conf`:
    ```
    listen_addresses = ' '
    ```
    To listen on multiple addresses, a comma-separated list may be used:
    ```
    listen_addresses = ' , '
    ```
    In this case, clients can connect to the server using `--host=`_` `_, while connections on other server host addresses are not possible.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SA-8']
  tag ksi:                   ['KSI-PIY-RSD']
  tag nist_r4:               ['SA-8']
  tag cci:                   ['CCI-000664']
  tag cis_number:            '5.2'
  tag cis_rid:               '5.2'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:           'aws-shared-responsibility'
  tag attestation_references:   ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0502r1_rule'
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