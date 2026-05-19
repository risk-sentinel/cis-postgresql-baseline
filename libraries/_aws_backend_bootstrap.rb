# Ensures the vendored inspec-aws `libraries/` directory is on $LOAD_PATH
# so `require "aws_backend"` resolves before any sibling local library
# file is parsed. Without this, `cinc-auditor exec` fails at library-load
# time with `cannot load such file -- aws_backend (LoadError)`.
#
# Verbatim copy of sparc-aws-foundations / sparc-aws-database bootstrap
# files — InSpec evaluates libraries/ per profile, so each profile that
# ships local resources needs its own. See #24 for the full gotcha
# context (InSpec's instance_eval load path means __dir__ /
# require_relative can't locate the vendor tree; Dir.pwd-anchored globs
# are required).
#
# The leading underscore in the filename sorts this file first in
# InSpec's alphabetical library-load order, so sibling files can
# inherit `AwsResourceBase` directly.

vendor_patterns = [
  File.join(Dir.pwd, "vendor", "*", "libraries"),
  File.join(Dir.pwd, "profiles", "*", "vendor", "*", "libraries"),
]
vendor_patterns.flat_map { |p| Dir.glob(p) }.uniq.each do |dir|
  $LOAD_PATH.unshift(dir) unless $LOAD_PATH.include?(dir)
end

require "aws_backend"
