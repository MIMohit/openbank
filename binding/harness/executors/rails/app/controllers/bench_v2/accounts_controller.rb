module BenchV2
  class AccountsController < ::BenchController
    def show = op("getAccountV2", "/api/v2/accounts/{id}")
  end
end
