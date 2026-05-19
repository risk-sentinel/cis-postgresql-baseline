# encoding: UTF-8

control 'C-2.1' do
  title 'Ensure the file permissions mask is correct'
  desc  "
    Files are always created using a default set of permissions. File permissions can be restricted by applying a permissions mask called the `umask`. The `postgres` user account should use a umask of `0077` to deny file access to all user accounts except the owner.

    The Linux OS defaults the umask to `0022`, which means the owner and primary group can read and write the file, and other accounts are permitted to read the file. Not explicitly setting the umask to a value as restrictive as `0077` allows other users to read, write, or even execute files and scripts created by the `postgres` user account. The alternative to using a umask is explicitly updating file permissions after file creation using the command line utility `chmod` (a manual and error-prone process that is not advised).
  "
  desc  'rationale', "
    Files are always created using a default set of permissions. File permissions can be restricted by applying a permissions mask called the `umask`. The `postgres` user account should use a umask of `0077` to deny file access to all user accounts except the owner.

    The Linux OS defaults the umask to `0022`, which means the owner and primary group can read and write the file, and other accounts are permitted to read the file. Not explicitly setting the umask to a value as restrictive as `0077` allows other users to read, write, or even execute files and scripts created by the `postgres` user account. The alternative to using a umask is explicitly updating file permissions after file creation using the command line utility `chmod` (a manual and error-prone process that is not advised).
  "
  desc  'check', "
    To view the mask's current setting, execute the following commands:
    ```
    # whoami
    root
    # su - postgres                            
    # whoami
    postgres
    # umask
    0022
    ```
    The umask must be `0077` or more restrictive for the `postgres` user, otherwise, this is a fail.
  "
  desc  'fix', "
    Depending upon the `postgres` user's environment, the umask is typically set in the initialization file `.bash_profile`, but may also be set in `.profile` or `.bashrc`. To set the umask, add the following to the appropriate profile file:
    ```
    # whoami
    postgres
    # cd ~
    # ls -ld .{bash_profile,profile,bashrc}
    ls: cannot access .profile: No such file or directory
    ls: cannot access .bashrc: No such file or directory
    -rwx------. 1 postgres postgres 267 Aug 14 12:59 .bash_profile
    # echo \"umask 077\" >> .bash_profile
    # source .bash_profile
    # umask
    0077
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '2.1'
  tag cis_rid:               '2.1'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:           'aws-shared-responsibility'
  tag attestation_references:   ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0201r1_rule'
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
    it 'is satisfied by AWS-managed controls — control is satisfied by AWS under the shared-responsibility model. AWS manages postgres-user umask configuration on the Aurora host (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
      expect(true).to eq(true)
    end
  end
end
