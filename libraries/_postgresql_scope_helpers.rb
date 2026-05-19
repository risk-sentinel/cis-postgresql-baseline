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

  def postgresql_configured_endpoint
    primary = input('postgresql_endpoint').to_s.strip
    return primary unless primary.empty?
    input('aurora_cluster_endpoint').to_s.strip
  end
end

::Inspec::Rule.include(PostgresqlScopeHelpers)
