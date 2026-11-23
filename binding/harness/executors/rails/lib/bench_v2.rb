# /api/v2 is a mountable Rails engine (config/routes.rb: mount BenchV2::Engine => "/api/v2").
module BenchV2
  class Engine < ::Rails::Engine
    isolate_namespace BenchV2
    # Without this the engine's root is inferred as the app root (the dir containing lib/),
    # and the app's config/routes.rb would be loaded twice. The engine's own routes live in
    # lib/bench_v2/config/routes.rb; its controller is autoloaded by the app
    # (app/controllers/bench_v2/accounts_controller.rb).
    config.root = File.expand_path("bench_v2", __dir__)
  end
end
