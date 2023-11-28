lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name    = "fluent-plugin-sdns-api"
  spec.version = "0.1.0"
  spec.authors = ["yinqiwei"]
  spec.email   = ["772006843@qq.com"]

  spec.summary       = %q{Input Plugin for Fluentd.}
  spec.description   = %q{Input Plugin for Fluentd.}
  spec.homepage      = "https://github.com/meimeitou/fluent-plugin-sdns-api"
  spec.license       = "Apache-2.0"

  test_files, files  = `git ls-files -z`.split("\x0").partition do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.files         = files
  spec.executables   = files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = test_files
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 2.4.10"
  spec.add_development_dependency "rake", "~> 13.1.0"
  spec.add_development_dependency "test-unit", "~> 3.6.1"
  spec.add_runtime_dependency "fluentd", [">= 0.14.10", "< 2"]
end