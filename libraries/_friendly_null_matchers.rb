# frozen_string_literal: true

# Custom RSpec matchers that render InSpec's NullResponse / nil values
# as the literal string "null" in failure messages, instead of the
# default `#<NullResponse:0x00007f8…>` instance dump that operators
# misread as an errored fetch.
#
# The underlying check semantics are identical to the stock RSpec
# matchers (`match`, `cmp`, `be_nil`, `be_empty`, `>`, `>=`) — the
# only difference is the failure-message rendering when the actual
# value is a "null" sentinel.
#
# Use these specifically on `parameter_value(...)` describes for the
# 21 cis-postgresql parameter-group controls (§3.1.2, §3.1.7–9,
# §3.1.14–26, §3.2, §6.8–10), where AWS-managed default parameter
# groups return NullResponse for unset parameters. The user
# explicitly rejected PASS-on-null in May 2026 ("we should not
# assume the lack of evidence is a pass") — these matchers preserve
# the FAIL semantics but improve the rendering.

require 'rspec/expectations'

# rubocop:disable Style/ModuleFunction
module CisPostgresqlNullRender
  def self.null_value?(actual)
    return true if actual.nil?
    name = actual.class.name.to_s
    return true if name.match?(/NullResponse|NullStruct/)
    return true if actual.respond_to?(:resource_failed?) && actual.resource_failed?
    false
  end

  def self.render(actual)
    null_value?(actual) ? '"null"' : actual.inspect
  end
end
# rubocop:enable Style/ModuleFunction

RSpec::Matchers.define :match_pg_param do |expected_regex|
  match do |actual|
    !CisPostgresqlNullRender.null_value?(actual) &&
      actual.respond_to?(:match?) &&
      actual.match?(expected_regex)
  end
  failure_message do |actual|
    "expected: #{CisPostgresqlNullRender.render(actual)} to match #{expected_regex.inspect}"
  end
end

RSpec::Matchers.define :cmp_pg_param do |expected|
  match do |actual|
    !CisPostgresqlNullRender.null_value?(actual) &&
      actual.to_s.casecmp(expected.to_s).zero?
  end
  failure_message do |actual|
    "expected: #{CisPostgresqlNullRender.render(actual)} to equal #{expected.inspect}"
  end
end

RSpec::Matchers.define :be_pg_present do
  match do |actual|
    !CisPostgresqlNullRender.null_value?(actual) &&
      !(actual.respond_to?(:empty?) && actual.empty?)
  end
  failure_message do |actual|
    "expected: #{CisPostgresqlNullRender.render(actual)} to be present (non-null, non-empty)"
  end
end

RSpec::Matchers.define :be_pg_positive_numeric do
  match do |actual|
    !CisPostgresqlNullRender.null_value?(actual) &&
      actual.to_s.match?(/\A-?\d+(?:\.\d+)?\z/) &&
      actual.to_f > 0
  end
  failure_message do |actual|
    "expected: #{CisPostgresqlNullRender.render(actual)} to be a positive numeric value"
  end
end

RSpec::Matchers.define :be_pg_non_negative_numeric do
  match do |actual|
    !CisPostgresqlNullRender.null_value?(actual) &&
      actual.to_s.match?(/\A-?\d+(?:\.\d+)?\z/) &&
      actual.to_f >= 0
  end
  failure_message do |actual|
    "expected: #{CisPostgresqlNullRender.render(actual)} to be a non-negative numeric value"
  end
end
