# Custom resource wrapping `describe_db_parameters` so controls can
# assert on individual parameter values inside a standalone RDS DB
# parameter group (instance-level, not Aurora cluster-level).
#
# Sibling to `aws_rds_cluster_parameter_group` (defined in
# cis-aws-database/libraries/) — same accessor surface
# (`parameter_value`, `force_ssl_enabled?`, `require_secure_transport_enabled?`).
# The two libraries cover the two AWS RDS deployment shapes:
#
#   - Aurora cluster:        describe_db_cluster_parameters
#   - Standalone RDS:        describe_db_parameters     <-- this library
#
# CIS PostgreSQL controls are deployment-agnostic at the SQL level
# (the same parameter names mean the same thing in either deployment),
# so the dispatcher pattern in `_postgresql_helpers.rb` picks which
# library to instantiate based on the `engine_deployment` input.
#
# Depends on `_aws_backend_bootstrap.rb` having been loaded first.
# Uses @aws.rds_client (same accessor train-aws's AwsConnection exposes).

class AwsDbParameterGroup < AwsResourceBase
  name "aws_db_parameter_group"
  desc "Standalone RDS DB parameter group — inspect individual parameter values."
  example "
    describe aws_db_parameter_group(name: 'default.postgres15') do
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
    # Merge engine-default parameter values under the user/system-set
    # values from the parameter group itself. AWS's describe_db_parameters
    # on default groups can return rows with parameter_value=nil — those
    # parameters' effective values live in the engine-default parameter
    # set, surfaced by describe_engine_default_parameters. Without this
    # merge, controls iterating default.postgres15 see nil for any param
    # that hasn't been customised, even though the engine has a real
    # working value at runtime.
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
    "RDS DB Parameter Group: #{@group_name}"
  end

  private

  def fetch_family
    family = nil
    begin
      resp = @aws.rds_client.describe_db_parameter_groups(db_parameter_group_name: @group_name)
      grp = Array(resp.db_parameter_groups).first
      family = grp && grp.db_parameter_group_family
    rescue Aws::Errors::ServiceError, NoMethodError => e
      @connection_error = "describe_db_parameter_groups(#{@group_name}) failed: #{e.class.name}: #{e.message}"
    end
    family
  end

  def fetch_parameters_with_engine_defaults
    customer = fetch_parameters_via(:describe_db_parameters,
                                    db_parameter_group_name: @group_name)
    return customer if @family.nil? || @family.empty?
    defaults = fetch_parameters_via(:describe_engine_default_parameters,
                                    db_parameter_group_family: @family)
    merge_with_defaults(customer, defaults)
  end

  def fetch_parameters_via(method, args)
    rows = []
    begin
      pagination = args.dup
      loop do
        resp = @aws.rds_client.public_send(method, pagination)
        # describe_engine_default_parameters wraps its parameters under
        # resp.engine_defaults.parameters; describe_db_parameters
        # exposes resp.parameters directly.
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

  # Customer-set parameter values (where parameter_value is non-nil)
  # take precedence over engine defaults. Engine defaults fill in any
  # parameter the customer hasn't explicitly set OR any parameter where
  # describe_db_parameters returned a nil value.
  def merge_with_defaults(customer, defaults)
    by_name = {}
    Array(defaults).each { |p| by_name[p[:parameter_name]] = p }
    Array(customer).each do |p|
      existing = by_name[p[:parameter_name]]
      # Customer row wins if it has a non-nil value; otherwise keep the
      # default's value but preserve the customer row's other metadata.
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
