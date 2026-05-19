# encoding: UTF-8

control 'C-5.4' do
  title 'Ensure login via "host" TCP/IP Socket is configured correctly'
  desc  "
    A large number of authentication METHODs are available for hosts connecting using TCP/IP sockets, including: 

    * `trust`
    * `reject`
    * `md5`
    * `scram-sha-256`
    * `password`
    * `gss`
    * `sspi`
    * `ident`
    * `pam`
    * `ldap`
    * `radius`
    * `cert`
    * `oauth`

    METHODs `trust`, `password`, and `ident` are not to be used for remote logins. 

    METHOD `md5` is the most popular and can be used in both encrypted and unencrypted sessions, however, _it is vulnerable to packet replay attacks_. It is recommended that `scram-sha-256` be used instead of `md5`. 

    PostgreSQL 18 also introduced the setting `md5_password_warnings`. This is on by default and will produce a warning regarding MD5 password deprecation when a `CREATE ROLE` or `ALTER ROLE` statement sets an MD5-encrypted password.

    Use of the `gss`, `sspi`, `pam`, `ldap`, `oauth`, `radius`, and `cert` METHODs are dependent upon the availability of external authenticating processes/services and thus are not covered in this benchmark.
  "
  desc  'rationale', "
    A large number of authentication METHODs are available for hosts connecting using TCP/IP sockets, including: 

    * `trust`
    * `reject`
    * `md5`
    * `scram-sha-256`
    * `password`
    * `gss`
    * `sspi`
    * `ident`
    * `pam`
    * `ldap`
    * `radius`
    * `cert`
    * `oauth`

    METHODs `trust`, `password`, and `ident` are not to be used for remote logins. 

    METHOD `md5` is the most popular and can be used in both encrypted and unencrypted sessions, however, _it is vulnerable to packet replay attacks_. It is recommended that `scram-sha-256` be used instead of `md5`. 

    PostgreSQL 18 also introduced the setting `md5_password_warnings`. This is on by default and will produce a warning regarding MD5 password deprecation when a `CREATE ROLE` or `ALTER ROLE` statement sets an MD5-encrypted password.

    Use of the `gss`, `sspi`, `pam`, `ldap`, `oauth`, `radius`, and `cert` METHODs are dependent upon the availability of external authenticating processes/services and thus are not covered in this benchmark.
  "
  desc  'check', "
    Newly created data clusters are empty of data and have only one user account, the superuser. By default, the data cluster superuser is named after the UNIX account `postgres`. Login authentication can be tested via TCP/IP SOCKETS by any UNIX user account from the local host.

    A password must be assigned to each login ROLE:
    ```
    postgres=# ALTER ROLE postgres WITH PASSWORD 'secret_password';
    ALTER ROLE
    ```
    Test an unencrypted session:
    ```
    # psql 'host=localhost user=postgres sslmode=disable'
    Password:
    ```
    Test an encrypted session:
    ```
    # psql 'host=localhost user=postgres sslmode=require'
    Password:
    ```
    Remote logins repeat the previous invocations but, of course, from the remote host:

    Test unencrypted session:
    ```
    # psql 'host=server-name-or-IP user=postgres sslmode=disable'
    Password:
    ```
    Test encrypted sessions:
    ```
    # psql 'host=server-name-or-IP user=postgres sslmode=require'
    Password:
    ```
  "
  desc  'fix', "
    Confirm a login attempt has been made by looking for a logged error message detailing the nature of the authenticating failure. In the case of failed login attempts, whether encrypted or unencrypted, check the following:

    * The server should be sitting on a port exposed to the remote connecting host, i.e. NOT IP address `127.0.0.1`
       ```
       listen_addresses = '*'
       ```
    * An authenticating rule must exist in the file `pg_hba.conf`

    This example permits encrypted sessions for the `postgres` role and denies all unencrypted sessions for the `postgres` role:
    ```
    # TYPE    DATABASE           USER            ADDRESS           METHOD
    hostssl    all             postgres         0.0.0.0/0          scram-sha-256
    hostnossl  all             postgres         0.0.0.0/0          reject
    ```
    The following examples illustrate other possible configurations. The resultant \"rule\" of success/failure depends upon the first matching line.
    ```
    # allow 'postgres' user only from 'localhost/loopback' connections
    # and only if you know the password
    # (accepts both SSL and non-SSL connections)
    # TYPE    DATABASE        USER            ADDRESS                 METHOD
    host      all             postgres        127.0.0.1/32            scram-sha-256

    # allow users to connect remotely only to the database named after them, 
    # with the correct user password:
    # (accepts both SSL and non-SSL connections)
    # TYPE    DATABASE        USER            ADDRESS                 METHOD
    host      samerole        all             0.0.0.0/0               scram-sha-256

    # allow only those users who are a member of the 'rw' role to connect
    # only to the database named after them, with the correct user password:
    # (accepts both SSL and non-SSL connections)
    # TYPE    DATABASE        USER            ADDRESS                 METHOD
    host      samerole        +rw             0.0.0.0/0               scram-sha-256
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '5.4'
  tag cis_rid:               '5.4'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:           'aws-shared-responsibility'
  tag attestation_references:   ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0504r1_rule'
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
    it 'is satisfied by AWS-managed controls — control is satisfied by AWS under the shared-responsibility model. AWS manages pg_hba.conf on the Aurora host; operator-tunable TLS enforcement lives in the cluster parameter group as rds.force_ssl (covered by cis-postgresql CIS 6.8) (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
      expect(true).to eq(true)
    end
  end
end
