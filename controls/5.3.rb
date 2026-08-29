# encoding: UTF-8

control 'C-5.3' do
  title 'Ensure login via "local" UNIX Domain Socket is configured correctly'
  desc  "
    A remote host login, via SSH, is arguably the most secure means of remotely accessing and administering the PostgreSQL server. Once connected to the PostgreSQL server, using the `psql` client, via UNIX DOMAIN SOCKETS, while using the `peer` authentication method is the most secure mechanism available for local database connections. Provided a database user account of the same name of the UNIX account has already been defined in the database, even ordinary user accounts can access the cluster in a similarly highly secure manner.
  "
  desc  'rationale', "
    A remote host login, via SSH, is arguably the most secure means of remotely accessing and administering the PostgreSQL server. Once connected to the PostgreSQL server, using the `psql` client, via UNIX DOMAIN SOCKETS, while using the `peer` authentication method is the most secure mechanism available for local database connections. Provided a database user account of the same name of the UNIX account has already been defined in the database, even ordinary user accounts can access the cluster in a similarly highly secure manner.
  "
  desc  'check', "
    Newly created data clusters are empty of data and have only one user account, the superuser (`postgres`). By default, the data cluster superuser is named after the UNIX account. Login authentication is tested via UNIX DOMAIN SOCKETS by the UNIX user account `postgres`, the default account, and `set_user` has not yet been configured:
    ```
    # whoami
    postgres
    # psql postgres
    postgres=#
    ```
    Login attempts by another UNIX user account as the superuser should be denied:
    ```
    # su - user1
    # whoami
    user1
    # psql -U postgres -d postgres
    psql: FATAL:  Peer authentication failed for user \"postgres\"
    # exit
    ```
    This test demonstrates that not only is logging in as the superuser blocked, but so is logging in as another user:
    ```
    # su - user2
    # whoami
    user2
    # psql -U postgres -d postgres
    psql: FATAL: Peer authentication failed for user \"postgres\"
    # psql -U user1 -d postgres
    psql: FATAL: Peer authentication failed for user \"user1\"
    # psql -U user2 -d postgres
    postgres=>
    ```
  "
  desc  'fix', "
    Creation of a database account that matches the local account allows PEER authentication:
    ```
    # psql -c \"CREATE ROLE user1 WITH LOGIN;\"
    CREATE ROLE
    ```
    Execute the following as the UNIX user account, the default authentication rules should now permit the login:
    ```
    # su - user1
    # whoami
    user1
    # psql -u user1 -d postgres
    postgres=>
    ```
    As per the host-based authentication rules in `$PGDATA/pg_hba.conf`, all login attempts via UNIX DOMAIN SOCKETS are processed on the line beginning with `local`.

    This is the minimal rule that must be in place allowing PEER connections:
    ```
    # TYPE  DATABASE        USER            ADDRESS                 METHOD
    local   all             all                                     peer
    ```
    Once edited, the server process must reload the authentication file before it can take effect. Improperly configured rules cannot update i.e. the old rules remain in place. The PostgreSQL logs will report the outcome of the SIGHUP:
    ```
    postgres=# select pg_reload_conf();
     pg_reload_conf
    ----------------
     t
    (1 row)
    ```
    The following examples illustrate other possible configurations. The resultant \"rule\" of success/failure depends upon the first matching line:
    ```
    # allow only postgres user logins locally via UNIX socket
    # TYPE  DATABASE        USER            ADDRESS                 METHOD
    local   all             postgres                                peer
    ```
    ```
    # allow all local users via UNIX socket
    # TYPE  DATABASE        USER            ADDRESS                 METHOD
    local   all             all                                     peer
    ```
    ```
    # allow all local users, via UNIX socket, only if they are connecting to a db named the same as their username
    # e.g. if user 'bob' is connecting to a db named 'bob'
    # TYPE  DATABASE        USER                                    METHOD
    local   samerole        all                                     peer
    ```
    ```
    # allow only local users, via UNIX socket, who are members of the 'rw' role in the db
    # TYPE  DATABASE        USER            ADDRESS                 METHOD
    local   all             +rw                                     peer
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a', 'IA-2 (2)']
  tag ksi:                   ['KSI-CNA-ULN', 'KSI-IAM-APM', 'KSI-SVC-EIS']
  tag nist_r4:               ['IA-2 (2)', 'SC-7 a']
  tag cci:                   ['CCI-001097', 'CCI-000766']
  tag cis_number:            '5.3'
  tag cis_rid:               '5.3'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:           'aws-shared-responsibility'
  tag attestation_references:   ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0503r1_rule'
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