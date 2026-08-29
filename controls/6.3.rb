# encoding: UTF-8

control 'C-6.3' do
  title 'Ensure \'Postmaster\' Runtime Parameters are Configured'
  desc  "
    PostgreSQL runtime parameters that are executed by the postmaster process.

    The `postmaster` process is the supervisory process that assigns a backend process to an incoming client connection. The `postmaster` manages key runtime parameters that are either shared by all backend connections or needed by the `postmaster` process itself to run.
  "
  desc  'rationale', "
    PostgreSQL runtime parameters that are executed by the postmaster process.

    The `postmaster` process is the supervisory process that assigns a backend process to an incoming client connection. The `postmaster` manages key runtime parameters that are either shared by all backend connections or needed by the `postmaster` process itself to run.
  "
  desc  'check', "
    The following parameters can only be set at server start by the owner of the PostgreSQL server process and cluster, typically the UNIX user account `postgres`. Therefore, all exploits require the successful compromise of either that UNIX account or the `postgres` superuser account itself.
    ```
    postgres=# SELECT name, setting FROM pg_settings WHERE context = 'postmaster' ORDER BY 1;
                    name                 |                 setting                  
    -------------------------------------+------------------------------------------
     archive_mode                        | off
     autovacuum_freeze_max_age           | 200000000
     autovacuum_multixact_freeze_max_age | 400000000
     autovacuum_worker_slots             | 16
     bonjour                             | off
     bonjour_name                        | 
     cluster_name                        | 
     commit_timestamp_buffers            | 32
     config_file                         | /var/lib/pgsql/18/data/postgresql.conf
     data_directory                      | /var/lib/pgsql/18/data
     data_sync_retry                     | off
     debug_io_direct                     | 
     dynamic_shared_memory_type          | posix
     event_source                        | PostgreSQL
     external_pid_file                   | 
     hba_file                            | /var/lib/pgsql/18/data/pg_hba.conf
     hot_standby                         | on
     huge_pages                          | try
     huge_page_size                      | 0
     ident_file                          | /var/lib/pgsql/18/data/pg_ident.conf
     ignore_invalid_pages                | off
     io_max_combine_limit                | 16
     io_max_concurrency                  | 64
     io_method                           | worker
     jit_provider                        | llvmjit
     listen_addresses                    | localhost
     logging_collector                   | on
     max_active_replication_origins      | 10
     max_connections                     | 100
     max_files_per_process               | 1000
     max_locks_per_transaction           | 64
     max_logical_replication_workers     | 4
     max_notify_queue_pages              | 1048576
     max_pred_locks_per_transaction      | 64
     max_prepared_transactions           | 0
     max_replication_slots               | 10
     max_wal_senders                     | 10
     max_worker_processes                | 8
     min_dynamic_shared_memory           | 0
     multixact_member_buffers            | 32
     multixact_offset_buffers            | 16
     notify_buffers                      | 16
     port                                | 5432
     recovery_target                     | 
     recovery_target_action              | pause
     recovery_target_inclusive           | on
     recovery_target_lsn                 | 
     recovery_target_name                | 
     recovery_target_time                | 
     recovery_target_timeline            | latest
     recovery_target_xid                 | 
     reserved_connections                | 0
     serializable_buffers                | 32
     shared_buffers                      | 16384
     shared_memory_type                  | mmap
     shared_preload_libraries            | pgaudit, set_user, $libdir/passwordcheck
     subtransaction_buffers              | 32
     superuser_reserved_connections      | 3
     trace_connection_negotiation        | off
     track_activity_query_size           | 1024
     track_commit_timestamp              | off
     transaction_buffers                 | 32
     unix_socket_directories             | /run/postgresql, /tmp
     unix_socket_group                   | 
     unix_socket_permissions             | 0777
     wal_buffers                         | 512
     wal_decode_buffer_size              | 524288
     wal_level                           | replica
     wal_log_hints                       | off
    (69 rows)

    ```
  "
  desc  'fix', "
    Once detected, the unauthorized/undesired change can be corrected by editing the altered configuration file and executing a server restart. In the case where the parameter has been specified on the command-line invocation of `pg_ctl` the `restart` invocation is insufficient and an explicit `stop` and `start` must instead be made.

    Detecting a change is possible by one of the following methods:
    1. Query the view `pg_settings` and compare with previous query outputs for any changes
    2. Review the configuration files `postgresql.conf` and `postgresql.auto.conf` and compare with previously archived file copies for any changes
    3. Examine the process output and look for parameters that were used at server startup:
       ```
       ps -few | grep -E -- '[p]ost.*-[D]'
       ```
    4. Examine the contents of `$PGDATA/postmaster.opts`
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 a']
  tag nist_r4:               ['CM-6 a']
  tag cci:                   ['CCI-000363']
  tag cis_number:            '6.3'
  tag cis_rid:               '6.3'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag cis_rule_id:           'SV-0603r1_rule'
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
  # security-relevant runtime params for this category (#cis_6_3_expected_params = a
  # {param => expected_value} hash), assert the ACTUAL parameter-group values
  # rather than trusting an attestation. Undeclared -> attestation floor.
  expected = input('cis_6_3_expected_params', value: {})
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
    uri = input('c_6_3_attestation_uri', value: '')
    uri = attestation_uri(:boundary, 'C-6.3') if uri.to_s.empty?
    max_age_days = input('attestation_max_age_days', value: 365)
    if uri.to_s.empty?
      describe 'CIS 6.3 — Postmaster runtime parameter category review' do
        skip "Requires manual review and attestation provided for this control. CIS 6.3 covers the `postmaster` runtime-parameter category (parameters that require a server restart). Aurora consumers manage these via the cluster parameter group; the implementable subset is already covered by CIS 3.1 / 3.2 / 6.8-6.10 (which assert specific parameter values). 6.3 itself is a category-review attestation — operators confirm they've reviewed the postmaster category for their workload. [Lift: set boundary_docs_base / c_6_3_attestation_uri, or `saf attest apply`.] Declare cis_6_3_expected_params to VERIFY actual param values instead of attesting. [Lift: set boundary_docs_base / c_6_3_attestation_uri, or `saf attest apply`.]"
      end
    else
      doc = document_attestation(uri, max_age_days: max_age_days)
      describe "CIS 6.3 — Postmaster runtime parameter category review (#{uri})" do
        it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
        it('exists') { expect(doc.exists?).to eq(true) }
        it("current within #{max_age_days}d") { expect(doc.current?).to eq(true) }
      end
    end
  end
end