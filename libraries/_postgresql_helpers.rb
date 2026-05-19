# Engine-agnostic dispatch helpers for cis-postgresql parameter-group
# controls. Lets controls iterate target databases without hard-coding
# either Aurora cluster shape or standalone RDS instance shape.
#
# Drives the choice via the `engine_deployment` input:
#   - 'rds_instance'   → iterate aws_rds_instances; use aws_db_parameter_group
#   - 'aurora_cluster' → iterate aws_rds_clusters; use aws_rds_cluster_parameter_group
#
# Default is 'rds_instance' because (a) standalone RDS PostgreSQL is the
# more common deployment (Aurora is opt-in for the elastic / multi-region
# benefits) and (b) the consumer's own runtime is standalone RDS.
#
# Usage from a control body:
#
#   postgresql_parameter_groups.each do |target|
#     next if target[:pg_name].nil?
#     describe target[:resource] do
#       its("parameter_value('log_destination')") { should match(/csvlog|stderr/) }
#     end
#   end
#
# Each target is a hash:
#   :id         — cluster identifier (Aurora) or instance identifier (RDS)
#   :engine     — 'aurora-postgresql' or 'postgres'
#   :pg_name    — parameter-group name to look up
#   :resource   — instantiated aws_*_parameter_group resource
#   :deployment — 'aurora_cluster' or 'rds_instance'
#
# The helper module is included into Inspec::Rule so `input(...)` and
# the resource DSL (aws_rds_clusters / aws_rds_instances /
# aws_rds_cluster_parameter_group / aws_db_parameter_group) are all in
# scope. Per the §6 module-and-include pattern (docs/dev/Vendored_Resource_Gaps.md).
#
# Depends on `_aws_backend_bootstrap.rb` having been loaded first.

module PostgresqlHelpers
  def postgresql_parameter_groups
    deployment = input('engine_deployment').to_s
    deployment = 'rds_instance' if deployment.empty?

    case deployment
    when 'aurora_cluster'
      _postgresql_aurora_targets
    when 'rds_instance'
      _postgresql_rds_instance_targets
    else
      Inspec::Log.warn("postgresql_parameter_groups: unknown engine_deployment=#{deployment}; expected 'aurora_cluster' or 'rds_instance'. Returning [].")
      []
    end
  end

  private

  def _postgresql_aurora_targets
    allowed = Array(input('postgresql_cluster_identifiers'))
    aws_rds_clusters.entries.select { |c| c[:engine] == 'aurora-postgresql' }.select do |c|
      allowed.empty? || allowed.include?(c[:db_cluster_identifier])
    end.map do |c|
      pg_name = c[:db_cluster_parameter_group]
      {
        id:         c[:db_cluster_identifier],
        engine:     c[:engine],
        pg_name:    pg_name,
        resource:   aws_rds_cluster_parameter_group(name: pg_name),
        deployment: 'aurora_cluster',
      }
    end
  end

  def _postgresql_rds_instance_targets
    allowed = Array(input('postgresql_instance_identifiers'))
    aws_rds_instances.entries.select { |i| i[:engine].to_s.start_with?('postgres') }.select do |i|
      allowed.empty? || allowed.include?(i[:db_instance_identifier])
    end.map do |i|
      pg_name = Array(i[:db_parameter_groups]).first&.dig(:db_parameter_group_name)
      {
        id:         i[:db_instance_identifier],
        engine:     i[:engine],
        pg_name:    pg_name,
        resource:   pg_name ? aws_db_parameter_group(name: pg_name) : nil,
        deployment: 'rds_instance',
      }
    end
  end
end

# cinc-auditor 7.x evaluates this file inside an anonymous-class scope
# (Inspec::ProfileContext#load_with_context uses instance_eval). Bare
# `Inspec::Rule` constant lookup is rooted at that anonymous class —
# fails with NameError, which is what surfaced in PR #86's first CI run.
# `if defined?(Inspec::Rule)` avoids the NameError but makes the include
# a silent no-op when the constant isn't visible — methods then never
# attach to Inspec::Rule and controls fail with "undefined local variable
# or method 'postgresql_parameter_groups'" at exec.
#
# The fix is the fully-qualified `::Inspec::Rule` form: `::` anchors the
# lookup at top-level, bypassing the anonymous-class scope. inspec-core
# loads `Inspec::Rule` as a top-level constant before profile libraries
# load, so this resolves at file-load time without a guard.
::Inspec::Rule.include(PostgresqlHelpers)
