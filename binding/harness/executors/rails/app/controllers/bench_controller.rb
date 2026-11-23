require "net/http"
require "uri"

class BenchController < ActionController::API
  FRAMEWORK = ENV.fetch("FRAMEWORK_TAG", "rails")
  VERIFY_MODE = ENV.fetch("VERIFY_MODE", "off")
  VERIFIER_URL = URI(ENV.fetch("VERIFIER_URL", "http://verifier:9100/authz/orig"))

  def self.enc_segment(s)
    # interpretation #6: unreserved + sub-delims + ":" "@" literal (Python quote safe="-._~!$&'()*+,;=:@")
    s.to_s.b.gsub(%r{[^A-Za-z0-9\-._~!$&'()*+,;=:@]}n) { |c| format("%%%02X", c.ord) }
  end

  def listAccounts = op("listAccounts", "/api/v1/accounts")
  def getAccount = op("getAccount", "/api/v1/accounts/{id}")
  def updateAccount = op("updateAccount", "/api/v1/accounts/{id}")
  def deleteAccount = op("deleteAccount", "/api/v1/accounts/{id}")

  # G1 query dispatch, idiomatic params[:op] (Rails merges path, query and body params).
  def accountAction
    name = case params[:op]
           when "freeze" then "accountAction.freeze"
           when "close" then "accountAction.close"
           else "accountAction.unknown"
           end
    op(name, "/api/v1/accounts/{id}/actions")
  end

  def createTransfer = op("createTransfer", "/api/v1/transfers")

  # G1 body dispatch: the raw body is parsed as JSON whatever the Content-Type.
  def graphql
    name = begin
      obj = JSON.parse(request.raw_post.to_s)
      obj.is_a?(Hash) ? obj["operationName"] : nil
    rescue StandardError
      nil
    end
    op(case name
       when "getProfile" then "graphql.getProfile"
       when "deleteProfile" then "graphql.deleteProfile"
       else "graphql.unknown"
       end, "/api/v1/graphql")
  end

  def me = op("me", "/api/v1/me")
  def adminListUsers = op("adminListUsers", "/api/v1/admin/users")
  def adminDeleteUser = op("adminDeleteUser", "/api/v1/admin/users/{id}")
  def health = op("health", "/api/v1/health")
  def publicFile = op("publicFile", "/api/v1/public/{file}")

  # ROUTES=v2 actions (reachable only when the v2 routes are wired up; see config/routes.rb).
  def postAccount = op("postAccount", "/api/v1/accounts/{id}")
  def getStatements = op("getStatements", "/api/v1/accounts/{id}/statements")
  def deleteStatement = op("deleteStatement", "/api/v1/accounts/{id}/statements/{sid}")
  def catchAllFile = op("catchAllFile", "/api/v1/files/{path}")

  private

  def op(op_id, template)
    pp = request.path_parameters.except(:controller, :action, :format).transform_keys(&:to_s)
                .transform_values(&:to_s)
    env = request.env
    env["bench.op_id"] = op_id
    env["bench.route_template"] = template
    env["bench.path_params"] = pp
    unless VERIFY_MODE == "off" || verified?(template, pp)
      env["bench.denied"] = true
      return render(status: 401, json: { op_id: op_id, framework: FRAMEWORK, denied: true })
    end
    render json: { op_id: op_id, framework: FRAMEWORK, method: request.request_method, path_params: pp }
  end

  def verified?(template, pp)
    env = request.env
    if VERIFY_MODE == "origin-routed"
      method = env["REQUEST_METHOD"]       # effective, after Rack::MethodOverride
      uri = pp.reduce(template) { |u, (k, v)| u.gsub("{#{k}}", BenchController.enc_segment(v)) }
    else
      method = env["bench.raw_method"]
      uri = env["bench.raw_target"]
    end
    req = Net::HTTP::Get.new(VERIFIER_URL)
    req["X-Original-Method"] = method
    req["X-Original-URI"] = uri
    req["X-Original-Host"] = env["HTTP_HOST"].to_s
    req["Authorization"] = env["HTTP_AUTHORIZATION"] if env["HTTP_AUTHORIZATION"]
    req["DPoP"] = env["HTTP_DPOP"] if env["HTTP_DPOP"]
    res = Net::HTTP.start(VERIFIER_URL.host, VERIFIER_URL.port, open_timeout: 3, read_timeout: 5) { |h| h.request(req) }
    res.code.to_i.between?(200, 299)
  rescue StandardError
    false # fail closed
  end
end
