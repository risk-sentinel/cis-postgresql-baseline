# encoding: UTF-8

control 'C-6.8' do
  title 'Ensure TLS is enabled and configured correctly'
  desc  "
    TLS on a PostgreSQL server should be enabled and configured to encrypt TCP traffic to and from the server.

    If TLS is not enabled and configured correctly, this increases the risk of data being compromised in transit.
  "
  desc  'rationale', "
    TLS on a PostgreSQL server should be enabled and configured to encrypt TCP traffic to and from the server.

    If TLS is not enabled and configured correctly, this increases the risk of data being compromised in transit.
  "
  desc  'check', "
    To determine whether TLS is enabled, simply query the parameter value while logged into the database using either the `SHOW ssl` command or `SELECT` from system catalog view `pg_settings` as illustrated below. In both cases, `ssl` is `off`; this is a fail.
    ```
    postgres=# SHOW ssl;
    ssl
    -----
    off
    (1 row)

    postgres=# SELECT name, setting, source FROM pg_settings WHERE name = 'ssl';
    name | setting |       source      
    -----+---------+--------------------
    ssl  | off     | default
    (1 row)
    ```
  "
  desc  'fix', "
    For this example, and ease of illustration, we will be using a self-signed certificate (generated via `openssl`) for the server, and the PostgreSQL defaults for file naming and location in the PostgreSQL `$PGDATA` directory.
    ```
    # whoami
    postgres
    # # create new certificate and enter details at prompts
    # openssl req -new -text -out server.req
    Generating a 2048 bit RSA private key
    .....................+++
    ..................................................................+++
    writing new private key to 'privkey.pem'
    Enter PEM pass phrase:
    Verifying - Enter PEM pass phrase:
    -----
    You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.
    -----
    Country Name (2 letter code) [XX]:US
    State or Province Name (full name) []:Ohio
    Locality Name (eg, city) [Default City]:Columbus
    Organization Name (eg, company) [Default Company Ltd]:Me Inc
    Organizational Unit Name (eg, section) []:IT
    Common Name (eg, your name or your server's hostname) []:my.me.inc
    Email Address []:me@meinc.com

    Please enter the following 'extra' attributes
    to be sent with your certificate request
    A challenge password []:
    An optional company name []:

    # # remove passphrase (required for automatic server start up, if not using `ssl_passphrase_command`)
    # openssl rsa -in privkey.pem -out server.key && rm privkey.pem
    Enter pass phrase for privkey.pem:
    writing RSA key

    # # modify certificate to self signed, generate .key and .crt files
    # openssl req -x509 -in server.req -text -key server.key -out server.crt

    # # copy .key and .crt files to appropriate location, here default $PGDATA
    $ cp server.key server.crt $PGDATA

    # # restrict file mode for server.key
    $ chmod og-rwx server.key
    ```
    Edit the PostgreSQL configuration file `postgresql.conf` to ensure the following items are set. Again, we are using defaults. Note that altering these parameters will require restarting the cluster.
    ```
    # (change requires restart)
    ssl = on

    # force clients to use TLS v1.3 or newer
    ssl_min_protocol_version = 'TLSv1.3'

    # (change requires restart)
    ssl_cert_file = 'server.crt'

    # (change requires restart)
    ssl_key_file = 'server.key'
    ```
    Finally, restart PostgreSQL and confirm `ssl` using commands outlined in Audit Procedures:
    ```
    postgres=# show ssl;
     ssl
    -----
     on
    (1 row)
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '6.8'
  tag cis_rid:               '6.8'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-0608r1_rule'
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
      its("parameter_value('rds.force_ssl')") { should cmp_pg_param("1") }
    end
  end
end
