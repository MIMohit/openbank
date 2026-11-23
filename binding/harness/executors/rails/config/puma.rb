bind "tcp://0.0.0.0:8080"
threads 4, 8
workers 0
environment ENV.fetch("RAILS_ENV", "production")
quiet
