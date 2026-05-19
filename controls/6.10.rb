# encoding: UTF-8

control 'C-6.10' do
  title 'Ensure Weak SSL/TLS Ciphers Are Disabled'
  desc  "
    The PostgreSQL `ssl_ciphers` and `ssl_tls13_ciphers` directives specify which Cipher Suites are allowed in the negotiation with the client. `ssl_ciphers` is used to specify the list of allowed cipher suites for TLS 1.2 and earlier versions. While `ssl_tls13_ciphers` is a list of cipher suites that are allowed by connections using TLS version 1.3.

    In cryptography, _perfect forward secrecy_ (PFS), also known as _forward secrecy_ (FS), is a feature of specific key exchange protocols that give assurance that the session keys will not be compromised even if the private key of the server is compromised. For instance, `RSA` does not provide PFS, while the `ECDHE` (Elliptic-Curve Diffie-Hellman Ephemeral) and `DHE` (Diffie-Hellman Ephemeral) provides PFS.

    `ECDHE` is the stronger protocol and should be preferred, while `DHE` may be allowed for greater compatibility with older clients.
    Only Cipher Suites with either the `ECDHE` or the `DHE` key exchange are allowed.

    The SSL/TLS protocols support a large number of Cipher Suites including many weak and medium strength algorithms that are subject to man-in-the middle attacks and information disclosure. Some implementations even support the `NULL` Cipher Suite which allows a TLS connection without any cryptographic protection. Therefore, it is critical to ensure the configuration only allows strong algorithms greater than or equal to 128-bit to be negotiated with the client. Stronger 256-bit algorithms should be allowed and preferred.

    Furthermore, during the TLS handshake, after the initial _Client Hello_ and _Server Hello_, there is a pre-master secret generated, which is used to generate the master secret, and in turn generates the session key. When using protocols that do not provide forward secrecy, such as RSA, the pre-master secret is encrypted by the client with the server's public key and sent over the network. However, with protocols such as `ECDHE` (Elliptic-Curve Diffie-Hellman Ephemeral) the pre-master secret is not sent over the wire, even in encrypted format. The key exchange arrives at the shared secret in the clear using ephemeral keys that are not stored or used again. With forward secrecy, each session has a unique key exchange, so that future sessions are protected.

    Note This recommendation is primarily targeted at those installs that cannot run in FIPS-mode, or need to further refine the allowable cipher list.
  "
  desc  'rationale', "
    The PostgreSQL `ssl_ciphers` and `ssl_tls13_ciphers` directives specify which Cipher Suites are allowed in the negotiation with the client. `ssl_ciphers` is used to specify the list of allowed cipher suites for TLS 1.2 and earlier versions. While `ssl_tls13_ciphers` is a list of cipher suites that are allowed by connections using TLS version 1.3.

    In cryptography, _perfect forward secrecy_ (PFS), also known as _forward secrecy_ (FS), is a feature of specific key exchange protocols that give assurance that the session keys will not be compromised even if the private key of the server is compromised. For instance, `RSA` does not provide PFS, while the `ECDHE` (Elliptic-Curve Diffie-Hellman Ephemeral) and `DHE` (Diffie-Hellman Ephemeral) provides PFS.

    `ECDHE` is the stronger protocol and should be preferred, while `DHE` may be allowed for greater compatibility with older clients.
    Only Cipher Suites with either the `ECDHE` or the `DHE` key exchange are allowed.

    The SSL/TLS protocols support a large number of Cipher Suites including many weak and medium strength algorithms that are subject to man-in-the middle attacks and information disclosure. Some implementations even support the `NULL` Cipher Suite which allows a TLS connection without any cryptographic protection. Therefore, it is critical to ensure the configuration only allows strong algorithms greater than or equal to 128-bit to be negotiated with the client. Stronger 256-bit algorithms should be allowed and preferred.

    Furthermore, during the TLS handshake, after the initial _Client Hello_ and _Server Hello_, there is a pre-master secret generated, which is used to generate the master secret, and in turn generates the session key. When using protocols that do not provide forward secrecy, such as RSA, the pre-master secret is encrypted by the client with the server's public key and sent over the network. However, with protocols such as `ECDHE` (Elliptic-Curve Diffie-Hellman Ephemeral) the pre-master secret is not sent over the wire, even in encrypted format. The key exchange arrives at the shared secret in the clear using ephemeral keys that are not stored or used again. With forward secrecy, each session has a unique key exchange, so that future sessions are protected.

    Note This recommendation is primarily targeted at those installs that cannot run in FIPS-mode, or need to further refine the allowable cipher list.
  "
  desc  'check', "
    1. Execute the following command
       ```
       postgres=# SHOW ssl_ciphers;
       postgres=# SHOW ssl_tls13_ciphers;
       ```
    2. Check the output to verify that the `ssl_ciphers` and `ssl_tls13_ciphers` directives do NOT include values other than these:
       ```
       TLS_AES_256_GCM_SHA384
       TLS_AES_128_GCM_SHA256
       TLS_AES_128_CCM_SHA256
       ```
    - Note: If you leave `ssl_tls13_ciphers` empty, PostgreSQL falls back to the default cipher list provided by your underlying OpenSSL library for TLS 1.3 connections.

    3. Ensure there are no existing connections using weaker ciphers:
       ```
       postgres=# SELECT * FROM pg_stat_ssl WHERE cipher NOT IN ('TLS_AES_256_GCM_SHA384','TLS_AES_128_GCM_SHA256','TLS_AES_128_CCM_SHA256');
       ```
  "
  desc  'fix', "
    Add or modify the `ssl_ciphers` directive to the following value:
    ```
    postgres=# ALTER SYSTEM SET ssl_ciphers = 'TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_AES_128_CCM_SHA256';
    postgres=# ALTER SYSTEM SET ssl_tls13_ciphers = 'TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_AES_128_CCM_SHA256';
    ALTER SYSTEM
    postgres=# SELECT pg_reload_conf();
     pg_reload_conf
    ----------------
     t
    (1 row)
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '6.10'
  tag cis_rid:               '6.10'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-0610r1_rule'
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
      its("parameter_value('ssl_ciphers')") { should match_pg_param(/HIGH|TLSv1\.2/) }
    end
  end
end
