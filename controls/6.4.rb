# encoding: UTF-8

control 'C-6.4' do
  title 'Ensure \'SIGHUP\' Runtime Parameters are Configured'
  desc  "
    PostgreSQL runtime parameters that are executed by the SIGHUP signal.

    In order to define server behavior and optimize server performance, the server's superuser has the privilege of setting these parameters which are found in the configuration files `postgresql.conf` and `pg_hba.conf`. Alternatively, those parameters found in `postgresql.conf` can also be changed using a server login session and executing the SQL command `ALTER SYSTEM` which writes its changes in the configuration file `postgresql.auto.conf`.
  "
  desc  'rationale', "
    PostgreSQL runtime parameters that are executed by the SIGHUP signal.

    In order to define server behavior and optimize server performance, the server's superuser has the privilege of setting these parameters which are found in the configuration files `postgresql.conf` and `pg_hba.conf`. Alternatively, those parameters found in `postgresql.conf` can also be changed using a server login session and executing the SQL command `ALTER SYSTEM` which writes its changes in the configuration file `postgresql.auto.conf`.
  "
  desc  'check', "
    The following parameters can be set at any time, without interrupting the server, by the owner of the `postmaster` server process and cluster (typically UNIX user account `postgres`).
    ```
    postgres=# SELECT name, setting FROM pg_settings WHERE context = 'sighup' ORDER BY 1;
                        name                     |                     setting                     
    ---------------------------------------------+-------------------------------------------------
     allow_alter_system                          | on
     archive_cleanup_command                     | 
     archive_command                             | (disabled)
     archive_library                             | 
     archive_timeout                             | 0
     authentication_timeout                      | 60
     autovacuum                                  | on
     autovacuum_analyze_scale_factor             | 0.1
     autovacuum_analyze_threshold                | 50
     autovacuum_max_workers                      | 3
     autovacuum_naptime                          | 60
     autovacuum_vacuum_cost_delay                | 2
     autovacuum_vacuum_cost_limit                | -1
     autovacuum_vacuum_insert_scale_factor       | 0.2
     autovacuum_vacuum_insert_threshold          | 1000
     autovacuum_vacuum_max_threshold             | 100000000
     autovacuum_vacuum_scale_factor              | 0.2
     autovacuum_vacuum_threshold                 | 50
     autovacuum_work_mem                         | -1
     bgwriter_delay                              | 200
     bgwriter_flush_after                        | 64
     bgwriter_lru_maxpages                       | 100
     bgwriter_lru_multiplier                     | 2
     checkpoint_completion_target                | 0.9
     checkpoint_flush_after                      | 32
     checkpoint_timeout                          | 300
     checkpoint_warning                          | 30
     file_extend_method                          | posix_fallocate
     fsync                                       | on
     full_page_writes                            | on
     gss_accept_delegation                       | off
     hot_standby_feedback                        | off
     idle_replication_slot_timeout               | 0
     io_workers                                  | 3
     krb_caseins_users                           | off
     krb_server_keyfile                          | FILE:/etc/sysconfig/pgsql/krb5.keytab
     log_autovacuum_min_duration                 | 600000
     log_checkpoints                             | on
     log_destination                             | csvlog
     log_directory                               | /var/log/postgres
     log_file_mode                               | 0600
     log_filename                                | postgresql-%Y%m%d.log
     log_hostname                                | off
     log_line_prefix                             | %m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h 
     log_recovery_conflict_waits                 | off
     log_rotation_age                            | 1440
     log_rotation_size                           | 1048576
     log_startup_progress_interval               | 10000
     log_timezone                                | UTC
     log_truncate_on_rotation                    | on
     max_parallel_apply_workers_per_subscription | 2
     max_pred_locks_per_page                     | 2
     max_pred_locks_per_relation                 | -2
     max_slot_wal_keep_size                      | -1
     max_standby_archive_delay                   | 30000
     max_standby_streaming_delay                 | 30000
     max_sync_workers_per_subscription           | 2
     max_wal_size                                | 1024
     min_wal_size                                | 80
     oauth_validator_libraries                   | 
     pre_auth_delay                              | 0
     primary_conninfo                            | 
     primary_slot_name                           | 
     recovery_end_command                        | 
     recovery_init_sync_method                   | fsync
     recovery_min_apply_delay                    | 0
     recovery_prefetch                           | try
     remove_temp_files_after_crash               | on
     restart_after_crash                         | on
     restore_command                             | 
     send_abort_for_crash                        | off
     send_abort_for_kill                         | off
     set_user.block_alter_system                 | on
     set_user.block_copy_program                 | on
     set_user.block_log_statement                | on
     set_user.exit_on_error                      | on
     set_user.nosuperuser_target_allowlist       | *
     set_user.superuser_allowlist                | *
     set_user.superuser_audit_tag                | AUDIT
     ssl                                         | off
     ssl_ca_file                                 | 
     ssl_cert_file                               | server.crt
     ssl_ciphers                                 | HIGH:MEDIUM:+3DES:!aNULL
     ssl_crl_dir                                 | 
     ssl_crl_file                                | 
     ssl_dh_params_file                          | 
     ssl_groups                                  | X25519:prime256v1
     ssl_key_file                                | server.key
     ssl_max_protocol_version                    | 
     ssl_min_protocol_version                    | TLSv1.2
     ssl_passphrase_command                      | 
     ssl_passphrase_command_supports_reload      | off
     ssl_prefer_server_ciphers                   | on
     ssl_tls13_ciphers                           | 
     summarize_wal                               | off
     synchronized_standby_slots                  | 
     synchronous_standby_names                   | 
     sync_replication_slots                      | off
     syslog_facility                             | local1
     syslog_ident                                | proddb
     syslog_sequence_numbers                     | on
     syslog_split_messages                       | on
     wal_keep_size                               | 0
     wal_receiver_create_temp_slot               | off
     wal_receiver_status_interval                | 10
     wal_receiver_timeout                        | 60000
     wal_retrieve_retry_interval                 | 5000
     wal_summary_keep_time                       | 14400
     wal_sync_method                             | fdatasync
     wal_writer_delay                            | 200
     wal_writer_flush_after                      | 128
    (111 rows)

    ```
  "
  desc  'fix', "
    Restore all values in the PostgreSQL configuration files and invoke the server to reload the configuration files.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 a']
  tag cci:                   ['CCI-000363']
  tag cis_number:            '6.4'
  tag cis_rid:               '6.4'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag cis_rule_id:           'SV-0604r1_rule'
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

  # VERIFY-don't-trust (sparc-validate Phase C): when the consumer declares the
  # security-relevant runtime params for this category (#cis_6_4_expected_params = a
  # {param => expected_value} hash), assert the ACTUAL parameter-group values
  # rather than trusting an attestation. Undeclared -> attestation floor.
  expected = input('cis_6_4_expected_params', value: {})
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
    uri = input('c_6_4_attestation_uri', value: '')
    uri = attestation_uri(:boundary, 'C-6.4') if uri.to_s.empty?
    max_age_days = input('attestation_max_age_days', value: 365)
    if uri.to_s.empty?
      describe 'CIS 6.4 — SIGHUP runtime parameter category review' do
        skip "Requires manual review and attestation provided for this control. CIS 6.4 covers the `sighup` runtime-parameter category (parameters that take effect on config reload). Same pattern as 6.3 — implementable subset is in CIS 3.x / 6.8-6.10; 6.4 itself is a category-review attestation. [Lift: set boundary_docs_base / c_6_4_attestation_uri, or `saf attest apply`.] Declare cis_6_4_expected_params to VERIFY actual param values instead of attesting. [Lift: set boundary_docs_base / c_6_4_attestation_uri, or `saf attest apply`.]"
      end
    else
      doc = document_attestation(uri, max_age_days: max_age_days)
      describe "CIS 6.4 — SIGHUP runtime parameter category review (#{uri})" do
        it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
        it('exists') { expect(doc.exists?).to eq(true) }
        it("current within #{max_age_days}d") { expect(doc.current?).to eq(true) }
      end
    end
  end
end