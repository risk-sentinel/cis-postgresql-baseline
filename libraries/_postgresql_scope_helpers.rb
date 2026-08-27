# frozen_string_literal: true

# PostgresqlScopeHelpers provides the scope check for cis-postgresql's
# DB-connection controls (§4.3, §4.4, §4.5, §4.6, §4.7, §4.10, §5.5,
# §6.11). Replaces the previous "fail loudly on no-endpoint-configured"
# precheck with auto-detect-by-input-presence + a deny-list override.
#
# Resolution precedence (highest first):
#   1. excluded_engines includes 'postgresql' → false (N/A).
#   2. forced_engines   includes 'postgresql' → true  (evaluate even if
#                                                     endpoint is empty
#                                                     — useful for
#                                                     in-progress
#                                                     stand-ups).
#   3. Endpoint configured (postgresql_endpoint OR aurora_cluster_endpoint)
#                                              → true (evaluate).
#   4. Otherwise → false (N/A — operator hasn't pointed the profile at
#                              a database; do not assume the lack of
#                              configuration is a fail).
#
# Behaviour rationale: a missing endpoint is a configuration choice,
# not a failure mode. Consumers who want loud-fail-on-no-endpoint
# semantics can set `forced_engines: [postgresql]` — the existing
# connection-error precheck then re-asserts and fails visibly.
#
# AWS-API-side detection (querying aws_rds_clusters / aws_rds_instances)
# is intentionally NOT used here: it would re-introduce the "PostgreSQL
# is in the account but no endpoint configured → FAIL" mode that the
# user explicitly opted out of in 2026-05-18. If a consumer needs that
# behaviour, they should populate the endpoint or use `forced_engines`.
module PostgresqlScopeHelpers
  CACHE = {}

  def postgresql_in_scope?
    return CACHE[:scope] if CACHE.key?(:scope)

    excluded = Array(input('excluded_engines')).map { |e| e.to_s.downcase }
    return CACHE[:scope] = false if excluded.include?('postgresql')

    forced = Array(input('forced_engines')).map { |e| e.to_s.downcase }
    return CACHE[:scope] = true if forced.include?('postgresql')

    CACHE[:scope] = !postgresql_configured_endpoint.empty?
  end

  def postgresql_scope_reason
    if Array(input('excluded_engines')).map { |e| e.to_s.downcase }.include?('postgresql')
      'excluded_engines includes postgresql'
    elsif Array(input('forced_engines')).map { |e| e.to_s.downcase }.include?('postgresql')
      'forced_engines includes postgresql'
    elsif !postgresql_configured_endpoint.empty?
      'postgresql_endpoint configured'
    else
      'no postgresql endpoint configured'
    end
  end

  # Build the DB-connection resource with its settings resolved HERE, at
  # rule scope, and passed in as params.
  #
  # `input()` raises NoMethodError inside a resource class — verified on
  # cinc-auditor 7.0.107: a helper mixed into ::Inspec::Rule reads an input
  # fine, the identical call inside `Inspec.resource(1)` raises. The resource's
  # own `_input_or_default` fallback therefore never sees a value and reports a
  # correctly-configured endpoint as missing, which is indistinguishable from
  # it being unset. That cost real debugging time downstream
  # before the two contexts were compared directly.
  #
  # Resolving here also guarantees the connection uses the SAME endpoint the
  # scope check used. Previously `postgresql_in_scope?` (rule scope, worked)
  # and the resource (resource scope, did not) could disagree — controls came
  # into scope and then failed claiming no endpoint was set.
  #
  # The opts hash is passed POSITIONALLY: InSpec's `*args` dispatch raises
  # `given 2, expected 0..1` for kwargs under Ruby 3.
  def postgresql_query(overrides = {})
    opts = {
      cluster_endpoint: postgresql_configured_endpoint,
      database: _postgresql_first_present(
        %w[postgresql_database_name aurora_database_name], 'postgres'
      ),
      db_user: _postgresql_first_present(
        %w[postgresql_scanner_dbuser aurora_scanner_dbuser], 'inspec_scanner'
      ),
      port: _postgresql_first_positive(%w[postgresql_port aurora_port], 5432),
    }.merge(overrides)
    aws_rds_aurora_psql_query(opts)
  end

  # Ports use 0 as the "not set" sentinel — inspec.yml documents
  # postgresql_port as taking precedence "when non-zero", defaulting to 5432
  # when both port inputs are zero. Blank-vs-present is therefore the wrong
  # test here: a literal 0 is "unset" and must fall through to the next name.
  # Using the string test sent port 0 to PG, which rejects it with
  # `invalid port number: "0"` — caught only at exec.
  def _postgresql_first_positive(names, default)
    Array(names).each do |name|
      value = input(name).to_i
      return value if value.positive?
    end
    default
  end

  # First non-empty input from a chain of names, else the default. Mirrors the
  # engine-agnostic-name-wins precedence the resource documents, but evaluated
  # where inputs are actually readable.
  def _postgresql_first_present(names, default)
    Array(names).each do |name|
      value = input(name)
      return value unless value.to_s.strip.empty?
    end
    default
  end

  def postgresql_configured_endpoint
    primary = input('postgresql_endpoint').to_s.strip
    return primary unless primary.empty?
    input('aurora_cluster_endpoint').to_s.strip
  end
end

::Inspec::Rule.include(PostgresqlScopeHelpers)
