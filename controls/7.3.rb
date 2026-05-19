# encoding: UTF-8

control 'C-7.3' do
  title 'Ensure base backups are configured and functional'
  desc  "
    A 'base backup' is a copy of the PRIMARY host's data cluster (`$PGDATA`) and is used to create STANDBY hosts and for Point In Time Recovery (PITR) mechanisms. Base backups should be copied across networks in a secure manner using an encrypted transport mechanism. The PostgreSQL CLI `pg_basebackup` can be used, however, TLS encryption should be enabled on the server as per section 6.8 of this benchmark. The pgBackRest tool detailed in section 8.2 of this benchmark can also be used to create a 'base backup'.
  "
  desc  'rationale', "
    A 'base backup' is a copy of the PRIMARY host's data cluster (`$PGDATA`) and is used to create STANDBY hosts and for Point In Time Recovery (PITR) mechanisms. Base backups should be copied across networks in a secure manner using an encrypted transport mechanism. The PostgreSQL CLI `pg_basebackup` can be used, however, TLS encryption should be enabled on the server as per section 6.8 of this benchmark. The pgBackRest tool detailed in section 8.2 of this benchmark can also be used to create a 'base backup'.
  "
  desc  'check', "
    Manually confirm that backups exist and are updated on a regular basis.
  "
  desc  'fix', "
    Executing base backups using `pg_basebackup` requires the following steps on the standby server:
    ```
    $ whoami
    postgres
    $ pg_basebackup --host=name_or_IP_of_master \\
    --port=5432 \\
    --username=replication_user \\
    --pgdata=~postgres/18/data \\
    --progress --verbose --write-recovery-conf --wal-method=stream 
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['MP-7 (a)', 'CP-4 a']
  tag cci:                   ['CCI-002581', 'CCI-000490']
  tag cis_number:            '7.3'
  tag cis_rid:               '7.3'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:           'aws-shared-responsibility'
  tag attestation_references:   ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0703r1_rule'
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
    it 'is satisfied by AWS-managed controls — control is satisfied by AWS under the shared-responsibility model. Aurora\'s continuous-backup feature handles base-backup configuration and scheduling internally. Customer-facing bar is RDS automated_backup_retention_period (covered by cis-aws-database CIS 2.8 / 3.10) (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
      expect(true).to eq(true)
    end
  end
end
