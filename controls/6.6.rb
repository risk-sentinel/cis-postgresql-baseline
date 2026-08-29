# encoding: UTF-8

control 'C-6.6' do
  title 'Ensure \'User\' Runtime Parameters are Configured'
  desc  "
    These PostgreSQL runtime parameters are managed at the user account (ROLE) level.

    In order to improve performance and optimize features, a `ROLE` has the privilege of setting numerous parameters in a transaction, session, or entity attribute. Any `ROLE` can alter any of these parameters.
  "
  desc  'rationale', "
    These PostgreSQL runtime parameters are managed at the user account (ROLE) level.

    In order to improve performance and optimize features, a `ROLE` has the privilege of setting numerous parameters in a transaction, session, or entity attribute. Any `ROLE` can alter any of these parameters.
  "
  desc  'check', "
    The method used to analyze the state of ROLE runtime parameters and to determine if they have been compromised is to inspect all catalogs and list attributes for database entities such as `ROLE`s and databases:
    ```
    postgres=# SELECT name, setting FROM pg_settings WHERE context = 'user' ORDER BY 1;
                     name                 |      setting       
    --------------------------------------+--------------------
     application_name                     | psql
     array_nulls                          | on
     backend_flush_after                  | 0
     backslash_quote                      | safe_encoding
     bytea_output                         | hex
     check_function_bodies                | on
     client_connection_check_interval     | 0
     client_encoding                      | UTF8
     client_min_messages                  | notice
     commit_siblings                      | 5
     constraint_exclusion                 | partition
     cpu_index_tuple_cost                 | 0.005
     cpu_operator_cost                    | 0.0025
     cpu_tuple_cost                       | 0.01
     createrole_self_grant                | 
     cursor_tuple_fraction                | 0.1
     DateStyle                            | ISO, MDY
     debug_logical_replication_streaming  | buffered
     debug_parallel_query                 | off
     debug_pretty_print                   | on
     debug_print_parse                    | off
     debug_print_plan                     | off
     debug_print_rewritten                | off
     default_statistics_target            | 100
     default_table_access_method          | heap
     default_tablespace                   | 
     default_text_search_config           | pg_catalog.english
     default_toast_compression            | pglz
     default_transaction_deferrable       | off
     default_transaction_isolation        | read committed
     default_transaction_read_only        | off
     effective_cache_size                 | 524288
     effective_io_concurrency             | 16
     enable_async_append                  | on
     enable_bitmapscan                    | on
     enable_distinct_reordering           | on
     enable_gathermerge                   | on
     enable_group_by_reordering           | on
     enable_hashagg                       | on
     enable_hashjoin                      | on
     enable_incremental_sort              | on
     enable_indexonlyscan                 | on
     enable_indexscan                     | on
     enable_material                      | on
     enable_memoize                       | on
     enable_mergejoin                     | on
     enable_nestloop                      | on
     enable_parallel_append               | on
     enable_parallel_hash                 | on
     enable_partition_pruning             | on
     enable_partitionwise_aggregate       | off
     enable_partitionwise_join            | off
     enable_presorted_aggregate           | on
     enable_self_join_elimination         | on
     enable_seqscan                       | on
     enable_sort                          | on
     enable_tidscan                       | on
     escape_string_warning                | on
     exit_on_error                        | off
     extra_float_digits                   | 1
     file_copy_method                     | copy
     from_collapse_limit                  | 8
     geqo                                 | on
     geqo_effort                          | 5
     geqo_generations                     | 0
     geqo_pool_size                       | 0
     geqo_seed                            | 0
     geqo_selection_bias                  | 2
     geqo_threshold                       | 12
     gin_fuzzy_search_limit               | 0
     gin_pending_list_limit               | 4096
     hash_mem_multiplier                  | 2
     icu_validation_level                 | warning
     idle_in_transaction_session_timeout  | 0
     idle_session_timeout                 | 0
     IntervalStyle                        | postgres
     io_combine_limit                     | 16
     jit                                  | on
     jit_above_cost                       | 100000
     jit_expressions                      | on
     jit_inline_above_cost                | 500000
     jit_optimize_above_cost              | 500000
     jit_tuple_deforming                  | on
     join_collapse_limit                  | 8
     lc_monetary                          | en_US.UTF-8
     lc_numeric                           | en_US.UTF-8
     lc_time                              | en_US.UTF-8
     local_preload_libraries              | 
     lock_timeout                         | 0
     logical_decoding_work_mem            | 65536
     log_parameter_max_length_on_error    | 0
     maintenance_io_concurrency           | 16
     maintenance_work_mem                 | 65536
     max_parallel_maintenance_workers     | 2
     max_parallel_workers                 | 8
     max_parallel_workers_per_gather      | 2
     md5_password_warnings                | on
     min_parallel_index_scan_size         | 64
     min_parallel_table_scan_size         | 1024
     parallel_leader_participation        | on
     parallel_setup_cost                  | 1000
     parallel_tuple_cost                  | 0.1
     password_encryption                  | scram-sha-256
     plan_cache_mode                      | auto
     quote_all_identifiers                | off
     random_page_cost                     | 4
     recursive_worktable_factor           | 10
     restrict_nonsystem_relation_kind     | 
     row_security                         | on
     scram_iterations                     | 4096
     search_path                          | \"$user\", public
     seq_page_cost                        | 1
     standard_conforming_strings          | on
     statement_timeout                    | 0
     stats_fetch_consistency              | cache
     synchronize_seqscans                 | on
     synchronous_commit                   | on
     tcp_keepalives_count                 | 0
     tcp_keepalives_idle                  | 0
     tcp_keepalives_interval              | 0
     tcp_user_timeout                     | 0
     temp_buffers                         | 1024
     temp_tablespaces                     | 
     TimeZone                             | UTC
     timezone_abbreviations               | Default
     trace_notify                         | off
     trace_sort                           | off
     transaction_deferrable               | off
     transaction_isolation                | read committed
     transaction_read_only                | off
     transaction_timeout                  | 0
     transform_null_equals                | off
     vacuum_buffer_usage_limit            | 2048
     vacuum_cost_delay                    | 0
     vacuum_cost_limit                    | 200
     vacuum_cost_page_dirty               | 20
     vacuum_cost_page_hit                 | 1
     vacuum_cost_page_miss                | 2
     vacuum_failsafe_age                  | 1600000000
     vacuum_freeze_min_age                | 50000000
     vacuum_freeze_table_age              | 150000000
     vacuum_max_eager_freeze_failure_rate | 0.03
     vacuum_multixact_failsafe_age        | 1600000000
     vacuum_multixact_freeze_min_age      | 5000000
     vacuum_multixact_freeze_table_age    | 150000000
     vacuum_truncate                      | on
     wal_sender_timeout                   | 60000
     wal_skip_threshold                   | 2048
     work_mem                             | 4096
     xmlbinary                            | base64
     xmloption                            | content
    (151 rows)
    ```
  "
  desc  'fix', "
    In the matter of a user session, the login sessions must be validated that it is not executing undesired parameter changes. In the matter of attributes that have been changed in entities, they must be manually reverted to their default value(s).
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 a']
  tag nist_r4:               ['CM-6 a']
  tag cci:                   ['CCI-000363']
  tag cis_number:            '6.6'
  tag cis_rid:               '6.6'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag cis_rule_id:           'SV-0606r1_rule'
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
  # security-relevant runtime params for this category (#cis_6_6_expected_params = a
  # {param => expected_value} hash), assert the ACTUAL parameter-group values
  # rather than trusting an attestation. Undeclared -> attestation floor.
  expected = input('cis_6_6_expected_params', value: {})
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
    uri = input('c_6_6_attestation_uri', value: '')
    uri = attestation_uri(:boundary, 'C-6.6') if uri.to_s.empty?
    max_age_days = input('attestation_max_age_days', value: 365)
    if uri.to_s.empty?
      describe 'CIS 6.6 — User runtime parameter category review' do
        skip "Requires manual review and attestation provided for this control. CIS 6.6 covers the `user` runtime-parameter category (parameters any user can set per-session). The implementable bar — the application doesn't override security-relevant defaults via SET commands — is a consumer-policy attestation. [Lift: set boundary_docs_base / c_6_6_attestation_uri, or `saf attest apply`.] Declare cis_6_6_expected_params to VERIFY actual param values instead of attesting. [Lift: set boundary_docs_base / c_6_6_attestation_uri, or `saf attest apply`.]"
      end
    else
      doc = document_attestation(uri, max_age_days: max_age_days)
      describe "CIS 6.6 — User runtime parameter category review (#{uri})" do
        it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
        it('exists') { expect(doc.exists?).to eq(true) }
        it("current within #{max_age_days}d") { expect(doc.current?).to eq(true) }
      end
    end
  end
end