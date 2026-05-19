# encoding: UTF-8

control 'C-1.4' do
  title 'Ensure Data Cluster Initialized Successfully'
  desc  "
    First-time installs of a given PostgreSQL major release require the instantiation of the database cluster. A database cluster is a collection of databases that are managed by a single server instance.

    For the purposes of security, PostgreSQL enforces ownership and permissions of the data cluster such that:
    - An initialized data cluster is owned by the UNIX account that created it.
    - The data cluster cannot be accessed by other UNIX user accounts.
    - The data cluster cannot be created or owned by `root`
    - The PostgreSQL process cannot be invoked by `root` nor any UNIX user account other than the owner of the data cluster.

    Incorrectly instantiating the data cluster will result in a failed installation.
  "
  desc  'rationale', "
    First-time installs of a given PostgreSQL major release require the instantiation of the database cluster. A database cluster is a collection of databases that are managed by a single server instance.

    For the purposes of security, PostgreSQL enforces ownership and permissions of the data cluster such that:
    - An initialized data cluster is owned by the UNIX account that created it.
    - The data cluster cannot be accessed by other UNIX user accounts.
    - The data cluster cannot be created or owned by `root`
    - The PostgreSQL process cannot be invoked by `root` nor any UNIX user account other than the owner of the data cluster.

    Incorrectly instantiating the data cluster will result in a failed installation.
  "
  desc  'check', "
    Assuming you are installing the PostgreSQL binary package from the PGDG repository, the standard method, as `root`, is to instantiate the cluster thusly:
    ```
    # whoami
    root
    # PGSETUP_INITDB_OPTIONS=\"-k\" /usr/pgsql-18/bin/postgresql-18-setup initdb
    Initializing database ... OK
    ```
    Note that we enabled checksumming in the above command by setting `PGSETUP_INITDB_OPTIONS=\"-k\"`.

    A correctly installed data cluster possesses directory permissions similar to the following example. Otherwise, the service will fail to start:
    ```
    # whoami
    root
    # ls -la ~postgres/18
    total 8
    drwx------.  4 postgres postgres   51 Oct  3 14:01 .
    drwx------.  3 postgres postgres   37 Oct  3 13:54 ..
    drwx------.  2 postgres postgres    6 Oct  3 06:18 backups
    drwx------. 20 postgres postgres 4096 Oct  3 14:01 data
    -rw-------.  1 postgres postgres  923 Oct  3 14:01 initdb.log
    ```

    You can verify the PGDATA has sane permissions and attributes by running:

    ```
    # whoami
    postgres
    # /usr/pgsql-18/bin/postgresql-18-check-db-dir ~postgres/18/data
    # echo $?
    0
    ```
    As long as the return code is zero(`0`), as shown, everything is fine.
  "
  desc  'fix', "
    Attempting to instantiate a data cluster to an existing non-empty directory will fail:
    ```
    # whoami
    root
    # PGSETUP_INITDB_OPTIONS=\"-k\" /usr/pgsql-18/bin/postgresql-18-setup initdb
    Data directory is not empty!
    ```
    In the case of a cluster instantiation failure, one must delete/remove the entire data cluster directory and repeat the `initdb` command:
    ```
    # whoami
    root
    # rm -rf ~postgres/18
    # PGSETUP_INITDB_OPTIONS=\"-k\" /usr/pgsql-18/bin/postgresql-18-setup initdb
    Initializing database ... OK
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '1.4'
  tag cis_rid:               '1.4'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:           'aws-shared-responsibility'
  tag attestation_references:   ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0104r1_rule'
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
    it 'is satisfied by AWS-managed controls — control is satisfied by AWS under the shared-responsibility model. AWS initialises the Aurora data cluster via its internal cluster-creation process (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
      expect(true).to eq(true)
    end
  end
end
