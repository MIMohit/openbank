require "json"
require "base64"
require "time"
require "fileutils"

# Outermost Rack middleware: captures the raw request, maps unmatched requests to
# 404 NOT_FOUND, and writes one JSON line per request (CONTRACT §3).
class BenchLog
  FRAMEWORK = ENV.fetch("FRAMEWORK_TAG", "rails")
  LOG_FILE = ENV.fetch("LOG_FILE", "/logs/executor.jsonl")
  TRUST_PREFIXES = %w[x-forwarded- x-original- x-verified- x-client-cert client-cert
                      x-forwarded-client-cert x-auth-].freeze
  LOCK = Mutex.new

  def initialize(app)
    @app = app
  end

  def self.jti(dpop)
    return nil if dpop.nil? || dpop.empty?
    parts = dpop.strip.split(".")
    return nil if parts.length < 2
    seg = parts[1].delete("=")
    seg += "=" * ((4 - seg.length % 4) % 4)
    obj = JSON.parse(Base64.urlsafe_decode64(seg))
    j = obj.is_a?(Hash) ? obj["jti"] : nil
    j.is_a?(String) ? j : nil
  rescue StandardError
    nil
  end

  def call(env)
    raw_method = env["REQUEST_METHOD"]
    # Puma sets REQUEST_URI to the request-target exactly as it appeared on the request line.
    raw_target = env["REQUEST_URI"] || (env["PATH_INFO"].to_s + (env["QUERY_STRING"].to_s.empty? ? "" : "?#{env['QUERY_STRING']}"))
    env["bench.raw_method"] = raw_method
    env["bench.raw_target"] = raw_target
    status, headers, body = @app.call(env)
    if env["bench.op_id"].nil? && [404, 405].include?(status.to_i)
      body.close if body.respond_to?(:close)
      payload = JSON.generate({ op_id: "NOT_FOUND", framework: FRAMEWORK, method: env["REQUEST_METHOD"], path_params: {} })
      status = 404
      headers = { "content-type" => "application/json; charset=utf-8" }
      body = [payload]
    end
    log(env, status.to_i, raw_method, raw_target)
    [status, headers, body]
  end

  def log(env, status, raw_method, raw_target)
    trust = {}
    env.each do |k, v|
      next unless k.start_with?("HTTP_")
      name = k.sub("HTTP_", "").downcase.tr("_", "-")
      trust[name] = v if TRUST_PREFIXES.any? { |p| name.start_with?(p) }
    end
    qi = raw_target.index("?")
    rec = {
      ts: Time.now.utc.iso8601(3),
      framework: FRAMEWORK,
      jti: BenchLog.jti(env["HTTP_DPOP"]),
      op_id: env["bench.op_id"] || "NOT_FOUND",
      route_template: env["bench.route_template"],
      raw_method: raw_method,
      effective_method: env["REQUEST_METHOD"],
      raw_target: raw_target,
      path_params: env["bench.path_params"] || {},
      query: qi ? raw_target[(qi + 1)..] : env["QUERY_STRING"].to_s,
      trust_headers: trust,
      denied: env["bench.denied"] ? true : false,
      status: status
    }
    line = JSON.generate(rec)
    LOCK.synchronize do
      $stdout.puts(line)
      $stdout.flush
      begin
        FileUtils.mkdir_p(File.dirname(LOG_FILE))
        File.open(LOG_FILE, "a") { |f| f.write(line + "\n") }
      rescue StandardError
        # /logs not mounted: stdout still has the line
      end
    end
  end
end
