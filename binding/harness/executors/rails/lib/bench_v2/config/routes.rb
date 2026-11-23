# Engine routes, relative to the mount point: the engine sees PATH_INFO without /api/v2
# (moved to SCRIPT_NAME by the mount).
BenchV2::Engine.routes.draw do
  get "accounts/:id", to: "accounts#show"
end
