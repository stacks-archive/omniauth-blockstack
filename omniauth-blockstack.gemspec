# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/blockstack/version'

Gem::Specification.new do |spec|
  spec.name          = "omniauth-blockstack"
  spec.version       = Omniauth::Blockstack::VERSION
  spec.authors       = ["Larry Salibra"]
  spec.email         = ["rubygems@larrysalibra.com"]
  spec.description   = %q{An OmniAuth strategy to accept Blockstack Auth decentralized sign-on.}
  spec.summary       = %q{An OmniAuth strategy to accept Blockstack Auth decentralized sign-on.}
  spec.homepage      = "http://github.com/larrysalibra/omniauth-blockstack"
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.3"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec"
  spec.add_development_dependency "guard"
  spec.add_development_dependency "guard-rspec"
  spec.add_development_dependency "rack-test"

  spec.add_dependency "jwt"
  spec.add_dependency "bitcoin-ruby"
  spec.add_dependency "faraday"
  spec.add_dependency "omniauth", "~> 1.1"
end
