Rails.application.routes.draw do
  scope "/api/v1", controller: :bench do
    get "accounts", action: :listAccounts
    get "accounts/:id", action: :getAccount
    put "accounts/:id", action: :updateAccount
    delete "accounts/:id", action: :deleteAccount
    post "accounts/:id/actions", action: :accountAction
    post "transfers", action: :createTransfer
    post "graphql", action: :graphql
    get "me", action: :me
    get "admin/users", action: :adminListUsers
    delete "admin/users/:id", action: :adminDeleteUser
    get "health", action: :health
    # File names contain dots; Rails' default segment pattern ([^/.?]+) would split off
    # ".ext" as :format, so this one route uses the common filename constraint.
    get "public/:file", action: :publicFile, constraints: { file: %r{[^/]+} }

    # ROUTES=v2 (default off) adds the richer v1 route space (W15 ext-routes). Off => :latest.
    if ENV["ROUTES"] == "v2"
      post "accounts/:id", action: :postAccount                           # POST shares the GET/PUT/DELETE path
      get "accounts/:id/statements", action: :getStatements              # nested same-method route
      delete "accounts/:id/statements/:sid", action: :deleteStatement
      # Catch-all glob; format: false keeps dotted suffixes in :path instead of :format.
      get "files/*path", action: :catchAllFile, format: false
    end
  end
  mount BenchV2::Engine => "/api/v2"
end
