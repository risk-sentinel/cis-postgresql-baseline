# encoding: UTF-8

control 'C-6.1' do
  title 'Understanding attack vectors and runtime parameters'
  desc  "
    Understanding the vulnerability of PostgreSQL runtime parameters by the particular delivery method, or attack vector.

    There are as many ways of compromising a server as there are runtime parameters. A combination of any one or more of them executed at the right time under the right conditions has the potential to compromise the RDBMS. Mitigating risk is dependent upon one's understanding of the attack vectors and includes:

    1. Via user session: includes those runtime parameters that can be set by a ROLE that persists for the life of a server-client session.
    2. Via attribute: includes those runtime parameters that can be set by a ROLE during a server-client session that can be assigned as an attribute for an entity such as a table, index, database, or role.
    3. Via server reload: includes those runtime parameters that can be set by the superuser using a SIGHUP or configuration file reload command and affects the entire cluster.
    4. Via server restart: includes those runtime parameters that can be set and effected by restarting the server process and affects the entire cluster.
  "
  desc  'rationale', "
    Understanding the vulnerability of PostgreSQL runtime parameters by the particular delivery method, or attack vector.

    There are as many ways of compromising a server as there are runtime parameters. A combination of any one or more of them executed at the right time under the right conditions has the potential to compromise the RDBMS. Mitigating risk is dependent upon one's understanding of the attack vectors and includes:

    1. Via user session: includes those runtime parameters that can be set by a ROLE that persists for the life of a server-client session.
    2. Via attribute: includes those runtime parameters that can be set by a ROLE during a server-client session that can be assigned as an attribute for an entity such as a table, index, database, or role.
    3. Via server reload: includes those runtime parameters that can be set by the superuser using a SIGHUP or configuration file reload command and affects the entire cluster.
    4. Via server restart: includes those runtime parameters that can be set and effected by restarting the server process and affects the entire cluster.
  "
  desc  'check', "
    Review all configuration settings. Configure PostgreSQL logging to record all modifications and changes to the RDBMS.
  "
  desc  'fix', "
    In the case of a changed parameter, the value is returned back to its default value. In the case of a successful exploit of an already set runtime parameter then an analysis must be carried out to determine the best approach in mitigating the risk to prevent future exploitation.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 a']
  tag cci:                   ['CCI-000363']
  tag cis_number:            '6.1'
  tag cis_rid:               '6.1'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag cis_rule_id:           'SV-0601r1_rule'
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

  describe 'Understanding attack vectors and runtime parameters' do
    skip "Requires manual review and attestation provided for this control"
  end
end
