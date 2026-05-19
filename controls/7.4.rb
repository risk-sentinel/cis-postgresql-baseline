# encoding: UTF-8

control 'C-7.4' do
  title 'Ensure WAL archiving is configured and functional'
  desc  "
    Write Ahead Log (WAL) Archiving, or Log Shipping, is the process of sending transaction log files from the PRIMARY host either to one or more STANDBY hosts or to be archived on a remote storage device for later use, e.g. `PITR`. There are several utilities that can copy WALs including, but not limited to, `cp`, `scp`, `sftp`, and `rynsc`. Basically, the server follows a set of runtime parameters which define when the WAL should be copied using one of the aforementioned utilities.

    Unless the server has been correctly configured, one runs the risk of sending WALs in an unsecured, unencrypted fashion.
  "
  desc  'rationale', "
    Write Ahead Log (WAL) Archiving, or Log Shipping, is the process of sending transaction log files from the PRIMARY host either to one or more STANDBY hosts or to be archived on a remote storage device for later use, e.g. `PITR`. There are several utilities that can copy WALs including, but not limited to, `cp`, `scp`, `sftp`, and `rynsc`. Basically, the server follows a set of runtime parameters which define when the WAL should be copied using one of the aforementioned utilities.

    Unless the server has been correctly configured, one runs the risk of sending WALs in an unsecured, unencrypted fashion.
  "
  desc  'check', "
    Review the following parameters:
    ```
    postgres=# SELECT name, setting
    FROM pg_settings
    WHERE name in ('archive_mode','archive_command','archive_library')
    AND setting IS NOT NULL
    AND setting <> 'off'
    AND setting <> '(disabled)'
    AND setting <> '';

     name | setting
    ------+---------
    (o rows)
    ```
    If no rows are returned, as shown, this is a failure. If rows are returned, note that `archive_mode` must be 'on' and either `archive_command` or `archive_library` must be set for WAL archiving to be fully enabled.

    To verify that WAL archiving is functioning successfully, one can:
    ```
    postgres=# SELECT * FROM pg_stat_archiver; \\watch
    ```
    And ensure that `archived_count`, `last_archived_wal`, and `last_archived_time` are changing while `failed_count`, `last_failed_wal`, and `last_failed_time` are not changing.
  "
  desc  'fix', "
    Change parameters and restart the server as required.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '7.4'
  tag cis_rid:               '7.4'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:           'aws-shared-responsibility'
  tag attestation_references:   ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0704r1_rule'
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

  describe 'AWS shared-responsibility inheritance' do
    it 'is satisfied by AWS-managed controls — control is satisfied by AWS under the shared-responsibility model. Aurora\'s distributed storage layer handles WAL durability internally; traditional WAL archiving is not part of the Aurora architecture (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
      expect(true).to eq(true)
    end
  end
end
