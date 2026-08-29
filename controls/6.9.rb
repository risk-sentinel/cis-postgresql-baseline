# encoding: UTF-8

control 'C-6.9' do
  title 'Ensure the TLSv1.0 and TLSv1.1 Protocols are Disabled'
  desc  "
    Transport Layer Security (TLS), and its predecessor Secure Sockets Layer (SSL) are cryptographic protocols which can be used to encrypt data sent between client and server.

    The TLSv1.0 protocol is vulnerable to the BEAST attack when used in CBC mode (October 2011). TLSv1.0 uses CBC modes for all of the block mode ciphers, which only leaves the RC4 streaming cipher which is also weak and therefore not recommended. Therefore, it is recommended that the TLSv1.0 protocol is disabled. The TLSv1.1 protocol does not support *Authenticated Encryption with Associated Data* (AEAD) which is designed to simultaneously provide confidentiality, integrity, and authenticity. All major up-to-date browsers support TLSv1.2, and most recent versions of *Firefox* and *Chrome* support the newer TLSv1.3 protocol, since 2017.

    *IETF* deprecated TLSv1.0 and TLSv1.1 in March 2021 (see *RFC 8996*).
  "
  desc  'rationale', "
    Transport Layer Security (TLS), and its predecessor Secure Sockets Layer (SSL) are cryptographic protocols which can be used to encrypt data sent between client and server.

    The TLSv1.0 protocol is vulnerable to the BEAST attack when used in CBC mode (October 2011). TLSv1.0 uses CBC modes for all of the block mode ciphers, which only leaves the RC4 streaming cipher which is also weak and therefore not recommended. Therefore, it is recommended that the TLSv1.0 protocol is disabled. The TLSv1.1 protocol does not support *Authenticated Encryption with Associated Data* (AEAD) which is designed to simultaneously provide confidentiality, integrity, and authenticity. All major up-to-date browsers support TLSv1.2, and most recent versions of *Firefox* and *Chrome* support the newer TLSv1.3 protocol, since 2017.

    *IETF* deprecated TLSv1.0 and TLSv1.1 in March 2021 (see *RFC 8996*).
  "
  desc  'check', "
    1. Execute the following command
       ```
       SHOW ssl_min_protocol_version;
       ```
    2. Check the output to verify that the `ssl_min_protocol_version` directive is set to either `TLSv1.2` or `TLSv1.3` (preferred).
  "
  desc  'fix', "
    Adjust the ssl_min_protocol_version to at least TLSv1.2:
    ```
    ALTER SYSTEM SET ssl_min_protocol_version = 'TLSv1.2';
    ```
    or (preferred):
    ```
    ALTER SYSTEM SET ssl_min_protocol_version = 'TLSv1.3';
    ```

    In either case, make the change active:
    ```
    SELECT pg_reload_conf();
    SHOW ssl_min_protocol_version;
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-8']
  tag cci:                   ['CCI-002418']
  tag cis_number:            '6.9'
  tag cis_rid:               '6.9'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-0609r1_rule'
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

  postgresql_parameter_groups.each do |target|
    next if target[:pg_name].nil?
    if target[:resource].respond_to?(:connection_error) && target[:resource].connection_error
      describe "RDS DB Parameter Group: #{target[:pg_name]}" do
        skip "pending-resource: parameter-group lookup failed for #{target[:id]} — #{target[:resource].connection_error}"
      end
      next
    end
    describe target[:resource] do
      its("parameter_value('ssl_min_protocol_version')") { should match_pg_param(/TLSv1\.2|TLSv1\.3/) }
    end
  end
end
