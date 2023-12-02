# frozen_string_literal: true

require_relative "lib/easy_pow/version"

Gem::Specification.new do |spec|
  spec.name          = "easy_pow"
  spec.version       = EasyPow::VERSION
  spec.authors       = ["nomeaning"]
  spec.email         = ["nomeaning777@gmail.com"]

  spec.summary       = %q{Simple PoW for CTF}
  spec.description   = %q{Simple PoW for CTF }
  spec.homepage      = "http://github.com/nomeaning777/easy_pow"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 2.6.0"
  spec.required_rubygems_version = ">= 3.3.11"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) || f.start_with?(*%w[bin/ test/ spec/ features/ .git .circleci appveyor])
    end
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.extensions = ["easy_pow_rb/Cargo.toml"]
end
