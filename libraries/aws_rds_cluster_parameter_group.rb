# Custom resource wrapping `describe_db_cluster_parameters` so controls
# can assert on individual parameter values inside an RDS / Aurora
# cluster parameter group. Added for CIS AWS Database Services 2.3
# (rds.force_ssl for Aurora-Postgres; require_secure_transport for
# Aurora-MySQL); reusable for any future parameter-group check.
#
# Not in inspec-aws 1.83.63 — the vendored `aws_rds_cluster` resource
# only exposes the parameter group *name* as a dynamic method, not the
# parameter values themselves.
#
# Depends on `_aws_backend_bootstrap.rb` having been loaded first (its
# leading underscore sorts it before this file in InSpec's alphabetical
# library-load order).
#
# Uses @aws.rds_client (exposed directly by train-aws's AwsConnection,
# same accessor the vendored aws_rds_cluster resource uses). No need
# for the generic aws_client(klass) path.

class AwsRdsClusterParameterGroup < AwsResourceBase
  name "aws_rds_cluster_parameter_group"
  desc "RDS / Aurora cluster parameter group — inspect individual parameter values."
  example "
    describe aws_rds_cluster_parameter_group(name: 'default.aurora-postgresql15') do
      it { should exist }
      its('parameter_value(\"rds.force_ssl\")') { should eq '1' }
    end
  "

  attr_reader :group_name, :parameters, :family, :connection_error

  def initialize(opts = {})
    opts = { name: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: [:name])
    @group_name = opts[:name]
    @connection_error = nil
    @family = fetch_family
    # Same engine-default merge as aws_db_parameter_group — see that
    # file for the rationale. AWS's describe_db_cluster_parameters on
    # default cluster groups returns nil parameter_value for params
    # whose effective value lives in the engine-default set.
    @parameters = fetch_parameters_with_engine_defaults
  end

  def exists?
    !@parameters.nil? && !@parameters.empty?
  end

  # Returns the parameter's effective value (customer-set if present,
  # else the engine default for this family, else nil).
  def parameter_value(name)
    row = @parameters.find { |p| p[:parameter_name] == name }
    row && row[:parameter_value]
  end

  def parameter(name)
    @parameters.find { |p| p[:parameter_name] == name }
  end

  def force_ssl_enabled?
    parameter_value("rds.force_ssl") == "1"
  end

  def require_secure_transport_enabled?
    v = parameter_value("require_secure_transport").to_s.upcase
    v == "ON" || v == "1"
  end

  def to_s
    "RDS Cluster Parameter Group: #{@group_name}"
  end

  private

  def fetch_family
    family = nil
    begin
      resp = @aws.rds_client.describe_db_cluster_parameter_groups(db_cluster_parameter_group_name: @group_name)
      grp = Array(resp.db_cluster_parameter_groups).first
      family = grp && grp.db_parameter_group_family
    rescue Aws::Errors::ServiceError, NoMethodError => e
      @connection_error = "describe_db_cluster_parameter_groups(#{@group_name}) failed: #{e.class.name}: #{e.message}"
    end
    family
  end

  def fetch_parameters_with_engine_defaults
    customer = fetch_via(:describe_db_cluster_parameters,
                        db_cluster_parameter_group_name: @group_name)
    return customer if @family.nil? || @family.empty?
    defaults = fetch_via(:describe_engine_default_cluster_parameters,
                        db_parameter_group_family: @family)
    merge_with_defaults(customer, defaults)
  end

  def fetch_via(method, args)
    rows = []
    begin
      pagination = args.dup
      loop do
        resp = @aws.rds_client.public_send(method, pagination)
        params = if resp.respond_to?(:engine_defaults) && resp.engine_defaults
                   Array(resp.engine_defaults.parameters)
                 else
                   Array(resp.parameters)
                 end
        params.each { |p| rows << p.to_h }
        marker = if resp.respond_to?(:engine_defaults) && resp.engine_defaults
                   resp.engine_defaults.marker
                 else
                   resp.marker
                 end
        break unless marker
        pagination[:marker] = marker
      end
    rescue Aws::Errors::ServiceError, NoMethodError => e
      @connection_error ||= "#{method}(#{args.inspect}) failed: #{e.class.name}: #{e.message}"
    end
    rows
  end

  def merge_with_defaults(customer, defaults)
    by_name = {}
    Array(defaults).each { |p| by_name[p[:parameter_name]] = p }
    Array(customer).each do |p|
      existing = by_name[p[:parameter_name]]
      if !p[:parameter_value].nil?
        by_name[p[:parameter_name]] = p
      elsif existing
        by_name[p[:parameter_name]] = p.merge(parameter_value: existing[:parameter_value])
      else
        by_name[p[:parameter_name]] = p
      end
    end
    by_name.values
  end
end
