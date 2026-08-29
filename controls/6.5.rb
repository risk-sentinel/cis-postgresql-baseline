# encoding: UTF-8

control 'C-6.5' do
  title 'Ensure \'Superuser\' Runtime Parameters are Configured'
  desc  "
    PostgreSQL runtime parameters that can only be executed by the server's superuser, `postgres`.

    In order to improve and optimize server performance, the server's superuser has the privilege of setting these parameters which are found in the configuration file `postgresql.conf`. Alternatively, they can be changed in a PostgreSQL login session via the SQL command `ALTER SYSTEM` which writes its changes in the configuration file `postgresql.auto.conf`.
  "
  desc  'rationale', "
    PostgreSQL runtime parameters that can only be executed by the server's superuser, `postgres`.

    In order to improve and optimize server performance, the server's superuser has the privilege of setting these parameters which are found in the configuration file `postgresql.conf`. Alternatively, they can be changed in a PostgreSQL login session via the SQL command `ALTER SYSTEM` which writes its changes in the configuration file `postgresql.auto.conf`.
  "
  desc  'check', "
    The following parameters can only be set at server start by the owner of the PostgreSQL server process and cluster i.e. typically UNIX user account `postgres`. Therefore, all exploits require the successful compromise of either that UNIX account or the `postgres` superuser account itself.
    ```
    postgres=# SELECT name, setting FROM pg_settings WHERE context = 'superuser' ORDER BY 1;
                   name                |   setting   
    -----------------------------------+-------------
     allow_in_place_tablespaces        | off
     allow_system_table_mods           | off
     backtrace_functions               | 
     commit_delay                      | 0
     compute_query_id                  | auto
     deadlock_timeout                  | 1000
     debug_discard_caches              | 0
     dynamic_library_path              | $libdir
     event_triggers                    | on
     extension_control_path            | $system
     ignore_checksum_failure           | off
     jit_dump_bitcode                  | off
     lc_messages                       | en_US.UTF-8
     lo_compat_privileges              | off
     log_duration                      | off
     log_error_verbosity               | verbose
     log_executor_stats                | off
     log_lock_failures                 | off
     log_lock_waits                    | off
     log_min_duration_sample           | -1
     log_min_duration_statement        | -1
     log_min_error_statement           | error
     log_min_messages                  | warning
     log_parameter_max_length          | -1
     log_parser_stats                  | off
     log_planner_stats                 | off
     log_replication_commands          | off
     log_statement                     | ddl
     log_statement_sample_rate         | 1
     log_statement_stats               | off
     log_temp_files                    | -1
     log_transaction_sample_rate       | 0
     max_stack_depth                   | 2048
     passwordcheck.min_password_length | 8
     pgaudit.log                       | ddl,write
     pgaudit.log_catalog               | on
     pgaudit.log_client                | off
     pgaudit.log_level                 | log
     pgaudit.log_parameter             | off
     pgaudit.log_parameter_max_size    | 0
     pgaudit.log_relation              | off
     pgaudit.log_rows                  | off
     pgaudit.log_statement             | on
     pgaudit.log_statement_once        | off
     pgaudit.role                      | 
     session_preload_libraries         | 
     session_replication_role          | origin
     temp_file_limit                   | -1
     track_activities                  | on
     track_cost_delay_timing           | off
     track_counts                      | on
     track_functions                   | none
     track_io_timing                   | off
     track_wal_io_timing               | off
     update_process_title              | on
     wal_compression                   | off
     wal_consistency_checking          | 
     wal_init_zero                     | on
     wal_recycle                       | on
     zero_damaged_pages                | off
    (60 rows)
    ```
  "
  desc  'fix', "
    The exploit is made in the configuration files. These changes are effected upon server restart. Once detected, the unauthorized/undesired change can be made by editing the altered configuration file and executing a server restart. In the case where the parameter has been set on the command-line invocation of `pg_ctl` the `restart` invocation is insufficient and an explicit `stop` and `start` must instead be made.

    Detecting a change is possible by one of the following methods:
    1. Query the view `pg_settings` and compare with previous query outputs for any changes.
    2. Review the configuration files `postgreql.conf` and `postgreql.auto.conf` and compare with previously archived file copies for any changes
    3. Examine the process output and look for parameters that were used at server startup:
       ```
       ps aux | grep -E -- '[p]ost.*-[D]'
       ```
    4. Examine the contents of `$PGDATA/postmaster.opts`
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 a']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 a']
  tag cci:                   ['CCI-000363']
  tag cis_number:            '6.5'
  tag cis_rid:               '6.5'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag cis_rule_id:           'SV-0605r1_rule'
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

  # VERIFY-don't-trust: when the consumer declares the
  # security-relevant runtime params for this category (#cis_6_5_expected_params = a
  # {param => expected_value} hash), assert the ACTUAL parameter-group values
  # rather than trusting an attestation. Undeclared -> attestation floor.
  expected = input('cis_6_5_expected_params', value: {})
  if expected.respond_to?(:empty?) && !expected.empty?
    postgresql_parameter_groups.each do |target|
      next if target[:pg_name].nil?
      if target[:resource].respond_to?(:connection_error) && target[:resource].connection_error
        describe "RDS DB Parameter Group: #{target[:pg_name]}" do
          skip "pending-resource: parameter-group lookup failed for #{target[:id]} — #{target[:resource].connection_error}"
        end
        next
      end
      describe target[:resource] do
        expected.each do |param, val|
          its("parameter_value('#{param}')") { should cmp_pg_param(val.to_s) }
        end
      end
    end
  else
    uri = input('c_6_5_attestation_uri', value: '')
    uri = attestation_uri(:boundary, 'C-6.5') if uri.to_s.empty?
    max_age_days = input('attestation_max_age_days', value: 365)
    if uri.to_s.empty?
      describe 'CIS 6.5 — Superuser runtime parameter category review' do
        skip "Requires manual review and attestation provided for this control. CIS 6.5 covers the `superuser` runtime-parameter category (parameters changeable only by superuser at session level). On Aurora, the rds_superuser role abstracts the real superuser; operators attest that application roles don't escalate via SET commands on these parameters. [Lift: set boundary_docs_base / c_6_5_attestation_uri, or `saf attest apply`.] Declare cis_6_5_expected_params to VERIFY actual param values instead of attesting. [Lift: set boundary_docs_base / c_6_5_attestation_uri, or `saf attest apply`.]"
      end
    else
      doc = document_attestation(uri, max_age_days: max_age_days)
      describe "CIS 6.5 — Superuser runtime parameter category review (#{uri})" do
        it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
        it('exists') { expect(doc.exists?).to eq(true) }
        it("current within #{max_age_days}d") { expect(doc.current?).to eq(true) }
      end
    end
  end
end