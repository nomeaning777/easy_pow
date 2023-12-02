# frozen_string_literal: true

require "rake/testtask"
require "rake/extensiontask"
require "bundler/gem_tasks"

task build: :compile
task default: :compile

Rake::ExtensionTask.new("easy_pow_rb") do |ext|
    ext.lib_dir = "lib/easy_pow"
    ext.ext_dir = "easy_pow_rb"
end
