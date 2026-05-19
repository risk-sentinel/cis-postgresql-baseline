# encoding: UTF-8

control 'C-1.6' do
  title 'Verify That \'PGPASSWORD\' is Not Set in Users\' Profiles'
  desc  "
    PostgreSQL can read a default database password from an environment variable called `PGPASSWORD`.

    Use of the `PGPASSWORD` environment variable implies PostgreSQL credentials are stored as clear text. Avoiding this may increase assurance that the confidentiality of PostgreSQL credentials is preserved.
  "
  desc  'rationale', "
    PostgreSQL can read a default database password from an environment variable called `PGPASSWORD`.

    Use of the `PGPASSWORD` environment variable implies PostgreSQL credentials are stored as clear text. Avoiding this may increase assurance that the confidentiality of PostgreSQL credentials is preserved.
  "
  desc  'check', "
    To assess this recommendation check if `PGPASSWORD` is set in login scripts using the following terminal command as privileged user:

    ```
    grep PGPASSWORD --no-messages /home/*/.{bashrc,profile,bash_profile}
    grep PGPASSWORD --no-messages /root/.{bashrc,profile,bash_profile}
    grep PGPASSWORD --no-messages /etc/environment
    ```

    Note that the above only covers Bash as the login shell. If OS users are configured to use Zsh, Csh, or other login shells, the list of files would need adjusted appropriately.
  "
  desc  'fix', "
    Check which users and/or scripts are setting `PGPASSWORD` and change them to use a more secure method.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-28']
  tag cci:                   ['CCI-001199']
  tag cis_number:            '1.6'
  tag cis_rid:               '1.6'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:         'aws-shared-responsibility'
  tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0106r1_rule'
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
    describe 'AWS shared-responsibility inheritance (CIS 1.6 — ' + "Verify That 'PGPASSWORD' is Not Set in Users' Profiles" + ')' do
      it 'is satisfied by AWS-managed controls — ' + "AWS provides no shell access to the underlying RDS / Aurora host. Operators cannot set PGPASSWORD in shell profiles on the database server (no profile files are operator-accessible); the credential-handling boundary stays with the customer-managed client workstation, which is out of scope for this control on a managed engine" + ' (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    describe "Verify That 'PGPASSWORD' is Not Set in Users' Profiles" do
      skip "engine_deployment=self_managed: this control's `desc 'check'` instructions are host-side and not reachable via the AWS-transport scanner. Re-exec with -t ssh://postgres-host to evaluate."
    end
  end
end

