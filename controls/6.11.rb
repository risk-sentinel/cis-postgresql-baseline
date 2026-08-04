# encoding: UTF-8

control 'C-6.11' do
  title 'Ensure the pgcrypto extension is installed and configured correctly'
  desc  "
    PostgreSQL must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.

    PostgreSQL instances handling data that requires \"data at rest\" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to PostgreSQL or implemented via additional software or operating system/file system settings, as appropriate to the situation. Information at rest refers to the state of information when it is located on a secondary storage device (e.g. disk drive, tape drive) within an organizational information system.

    The selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e. full disk encryption) or encrypt specific data structures (e.g. files, records, or fields). Organizations may also optionally choose to implement both to implement layered security.

    The decision of whether, and what, to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protection, as appropriate. If the confidentiality and integrity of application data are not protected, the data will be open to compromise and unauthorized modification.

    The PostgreSQL `pgcrypto` extension provides cryptographic functions for PostgreSQL and is intended to address the confidentiality and integrity of user and system information at rest in non-mobile devices.
  "
  desc  'rationale', "
    PostgreSQL must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.

    PostgreSQL instances handling data that requires \"data at rest\" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to PostgreSQL or implemented via additional software or operating system/file system settings, as appropriate to the situation. Information at rest refers to the state of information when it is located on a secondary storage device (e.g. disk drive, tape drive) within an organizational information system.

    The selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e. full disk encryption) or encrypt specific data structures (e.g. files, records, or fields). Organizations may also optionally choose to implement both to implement layered security.

    The decision of whether, and what, to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protection, as appropriate. If the confidentiality and integrity of application data are not protected, the data will be open to compromise and unauthorized modification.

    The PostgreSQL `pgcrypto` extension provides cryptographic functions for PostgreSQL and is intended to address the confidentiality and integrity of user and system information at rest in non-mobile devices.
  "
  desc  'check', "
    One possible way to encrypt data within PostgreSQL is to use the `pgcrypto` extension.

    To check if `pgcrypto` is installed on PostgreSQL, as a database administrator run the following commands:
    ```
    postgres=# SELECT * FROM pg_available_extensions WHERE name='pgcrypto'; 

    name      | default_version | installed_version |         comment        
    ----------+-----------------+-------------------+-------------------------
    pgcrypto  | 1.4             |                   | cryptographic functions
    (1 row)
    ```
    If data in the database requires encryption and `pgcrypto` is not available, this is a fail.

    If disk or filesystem requires encryption, ask the system owner, DBA, and SA to demonstrate the use of disk-level encryption. If this is required and is not found, this is a fail. If controls do not exist or are not enabled, this is also a fail.
  "
  desc  'fix', "
    The `pgcrypto` extension is included with the PostgreSQL `contrib` package. Although included, it needs to be created in the database.

    As the database administrator, run the following:
    ```
    postgres=# CREATE EXTENSION pgcrypto;
    CREATE EXTENSION
    ```
    Verify `pgcrypto` is installed:
    ```
    postgres=# SELECT * FROM pg_available_extensions WHERE name='pgcrypto';
       name   | default_version | installed_version |         comment
    ----------+-----------------+-------------------+-------------------------
     pgcrypto | 1.4             | 1.4               | cryptographic functions
    (1 row)
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '6.11'
  tag cis_rid:               '6.11'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag cis_rule_id:           'SV-0611r1_rule'
  tag cis_version:           '1.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_version   = ['14', '15', '16', '17', '18'].include?(input('postgresql_version').to_s)
  applicable_scope     = postgresql_in_scope?
  applicable           = applicable_partition && applicable_version && applicable_scope

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')}, postgresql_version=#{input('postgresql_version')}, scope=#{postgresql_scope_reason})") do
    applicable
  end

  q = postgresql_query

  # Connection-precheck — fails LOUDLY on no-endpoint-configured /
  # pg-missing / token-gen-failed / network-unreachable / auth-failed.
  describe 'CIS 6.11 — DB-connection precheck' do
    subject { q.connection_error }
    it { should be_nil }
  end

  # pgcrypto is shipped with RDS / Aurora PostgreSQL but must be
  # explicitly CREATE EXTENSION'd in each database that needs it.
  sql = "SELECT extname, extversion FROM pg_extension WHERE extname = 'pgcrypto';"
  rows = q.query(sql)

  describe 'pgcrypto extension installed (CIS 6.11)' do
    subject { rows }
    it { should_not be_empty }
  end
end
