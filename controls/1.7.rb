# encoding: UTF-8

control 'C-1.7' do
  title 'Verify That the \'PGPASSWORD\' Environment Variable is Not in Use'
  desc  "
    PostgreSQL can read a default database password from an environment variable
    called `PGPASSWORD`.

    Using the `PGPASSWORD` environment variable implies PostgreSQL credentials are stored as clear text.
    Avoiding use of this environment variable can better safeguard the confidentiality of PostgreSQL credentials.
  "
  desc  'rationale', "
    PostgreSQL can read a default database password from an environment variable
    called `PGPASSWORD`.

    Using the `PGPASSWORD` environment variable implies PostgreSQL credentials are stored as clear text.
    Avoiding use of this environment variable can better safeguard the confidentiality of PostgreSQL credentials.
  "
  desc  'check', "
    To assess this recommendation, use the `/proc` filesystem and the following terminal command as privileged root user to determine if `PGPASSWORD` is currently set for any process.

    ```
    sudo grep PGPASSWORD /proc/*/environ
    ```

    This may return one false-positive entry for the process which is executing the grep command.
  "
  desc  'fix', "
    Check which users and/or scripts are setting `PGPASSWORD` and change them
    to use a more secure method.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-28']
  tag cci:                   ['CCI-001199']
  tag cis_number:            '1.7'
  tag cis_rid:               '1.7'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:         'aws-shared-responsibility'
  tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0107r1_rule'
  tag cis_version:           '1.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  applicable_partition  = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_version    = ['14', '15', '16', '17', '18'].include?(input('postgresql_version').to_s)
  deployment            = input('engine_deployment').to_s
  deployment            = 'rds_instance' if deployment.empty?
  applicable            = applicable_partition && applicable_version

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')}, postgresql_version=#{input('postgresql_version')})") do
    applicable
  end

  if %w[rds_instance aurora_cluster].include?(deployment)
    describe 'AWS shared-responsibility inheritance (CIS 1.7 — ' + "Verify That the 'PGPASSWORD' Environment Variable is Not in Use" + ')' do
      it 'is satisfied by AWS-managed controls — ' + "AWS provides no shell access to the underlying RDS / Aurora host. Operators cannot set PGPASSWORD in the environment of the PostgreSQL daemon; the daemon environment is AWS-managed" + ' (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    describe "Verify That the 'PGPASSWORD' Environment Variable is Not in Use" do
      skip "engine_deployment=self_managed: this control's `desc 'check'` instructions are host-side and not reachable via the AWS-transport scanner. Re-exec with -t ssh://postgres-host to evaluate."
    end
  end
end

