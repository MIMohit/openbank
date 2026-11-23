require "bundler/setup"
require "rails"
require "action_controller/railtie"
require_relative "../lib/bench_log"
require_relative "../lib/bench_v2"

module BenchApp
  class Application < Rails::Application
    config.load_defaults 8.1
    config.root = File.expand_path("..", __dir__)
    config.eager_load = true
    config.secret_key_base = "bench-harness-not-a-secret"
    config.hosts.clear                       # requests carry Host: api.bench.test
    config.logger = ActiveSupport::Logger.new(nil)
    config.log_level = :warn
    config.consider_all_requests_local = false

    # Rack::MethodOverride is part of Rails' default middleware stack for non-API apps
    # (ActionDispatch default stack). OVERRIDE=off removes it with the documented
    # config.middleware.delete; OVERRIDE=on keeps the default.
    config.middleware.delete Rack::MethodOverride unless ENV["OVERRIDE"] == "on"

    # Outermost: raw capture + JSONL log + NOT_FOUND mapping.
    config.middleware.insert_before 0, BenchLog
  end
end
