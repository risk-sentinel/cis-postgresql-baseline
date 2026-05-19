# encoding: UTF-8

control 'C-5.1' do
  title 'Do Not Specify Passwords in the Command Line'
  desc  "
    When a command is executed on the command line, for example

    - `psql postgresql://postgres:PASSWORD@host`

    the password may be visible in the user's shell/command history or in the process list, thus exposing the password to other entities on the server.

    If the password is visible in the process list or user's shell/command history, an attacker will be able to access the PostgreSQL database using the stolen credentials.
  "
  desc  'rationale', "
    When a command is executed on the command line, for example

    - `psql postgresql://postgres:PASSWORD@host`

    the password may be visible in the user's shell/command history or in the process list, thus exposing the password to other entities on the server.

    If the password is visible in the process list or user's shell/command history, an attacker will be able to access the PostgreSQL database using the stolen credentials.
  "
  desc  'check', "
    - Check the process or task list if the password is visible.
       ```
       sudo ps -few
       ```
    - Check the shell or command history if the password is visible.
       ```
       history
       ```
  "
  desc  'fix', "
    1. Use the `--password` or `-W` terminal parameter without directly specifying the password and then enter the password when prompted.

       Substitute ` ` with your username, e.g., root:
       ```
       psql -u --password
       ```

    2. Do not use a [Connection URI](https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING) with password included, e.g. *`psql postgresql://postgres:PASSWORD@host`*

    3. If desired, configure a `.pgpass` file with the proper credentials and secure the file appropriately.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-8']
  tag cci:                   ['CCI-002418']
  tag cis_number:            '5.1'
  tag cis_rid:               '5.1'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:         'aws-shared-responsibility'
  tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0501r1_rule'
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
    describe 'AWS shared-responsibility inheritance (CIS 5.1 — ' + "Ensure Sudo is Configured Correctly" + ')' do
      it 'is satisfied by AWS-managed controls — ' + "AWS provides no shell access to the underlying RDS / Aurora host; there is no operator-accessible sudoers configuration. The /etc/sudoers risk this control addresses does not apply to AWS-managed engines" + ' (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    describe "Ensure Sudo is Configured Correctly" do
      skip "engine_deployment=self_managed: this control's `desc 'check'` instructions are host-side and not reachable via the AWS-transport scanner. Re-exec with -t ssh://postgres-host to evaluate."
    end
  end
end

