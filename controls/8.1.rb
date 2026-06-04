# encoding: UTF-8

control 'C-8.1' do
  title 'Ensure PostgreSQL subdirectory locations are outside the data cluster'
  desc  "
    The PostgreSQL cluster is organized to carry out specific tasks in subdirectories. For the purposes of performance, reliability, and security some of these subdirectories should be relocated outside the data cluster.

    Some subdirectories contain information, such as logs, which can be of value to others such as developers. Other subdirectories can gain a performance benefit when placed on fast storage devices. Other subdirectories contain temporary files created and used during processing. Finally, relocating a subdirectory to a separate and distinct partition mitigates denial of service and involuntary server shutdown when excessive writes fill the data cluster's partition, e.g. `pg_wal`, `pg_log`, and `temp_tablespaces`.
  "
  desc  'rationale', "
    The PostgreSQL cluster is organized to carry out specific tasks in subdirectories. For the purposes of performance, reliability, and security some of these subdirectories should be relocated outside the data cluster.

    Some subdirectories contain information, such as logs, which can be of value to others such as developers. Other subdirectories can gain a performance benefit when placed on fast storage devices. Other subdirectories contain temporary files created and used during processing. Finally, relocating a subdirectory to a separate and distinct partition mitigates denial of service and involuntary server shutdown when excessive writes fill the data cluster's partition, e.g. `pg_wal`, `pg_log`, and `temp_tablespaces`.
  "
  desc  'check', "
    Execute the following SQL statement to verify the configuration is correct. Alternatively, inspect the parameter settings in the `postgresql.conf` configuration file.
    ```
    postgres=# select name, setting from pg_settings where (name ~ '_directory$' or name ~ '_tablespace');
                name            |         setting
    ----------------------------+-------------------------
     allow_in_place_tablespaces | off
     data_directory             | /var/lib/pgsql/18/data
     default_tablespace         |
     log_directory              | log
     temp_tablespaces           |
    (5 rows)
    ```
    Inspect the file and directory permissions for all returned values. Only superusers and authorized users should have access control rights for these files and directories. If permissions are not highly restrictive, this is a fail.

    If `temp_tablespaces` is undefined and `temp_file_limit` has not been set, this is a fail.
  "
  desc  'fix', "
    Perform the following steps to remediate the subdirectory locations and permissions:
    * Determine appropriate data, log, and tablespace directories and locations based on your organization's security policies. If necessary, relocate all listed directories outside the data cluster.
    * If not relocating `temp_tablespaces`, the `temp_file_limit` parameter must be changed from its default value.
    * Ensure file permissions are restricted as much as possible, i.e. only superuser read access. 
    * When directories are relocated to other partitions, ensure that they are of sufficient size to mitigate against excessive space utilization. 
    * Lastly, change the settings accordingly in the `postgresql.conf` configuration file and restart the database cluster for changes to take effect.

    To relocate `temp_tablespaces` to an existing mount point outside the data cluster is accomplished by:
    ```
    postgres=# CREATE TABLESPACE temp_tablespc LOCATION '/path/to/existing/desired/mount/point';
    postgres=# ALTER SYSTEM SET temp_tablespaces = 'temp_tablespc';
    postgres=# SELECT pg_reload_conf();
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 a']
  tag cci:                   ['CCI-000363']
  tag cis_number:            '8.1'
  tag cis_rid:               '8.1'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:           'aws-shared-responsibility'
  tag attestation_references:   ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0801r1_rule'
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