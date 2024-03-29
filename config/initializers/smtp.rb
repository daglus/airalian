# ActionMailer::Base.smtp_settings = {
#   address: ENV['SMTP_ADDRESS'],
#   port: ENV['SMTP_PORT'],
#   domain: ENV['SMTP_DOMAIN'],
#   user_name: ENV['SMTP_USERNAME'],
#   password: ENV['SMTP_PASSWORD'],
#   authentication: :login,
#   enable_starttls_auto: true
# }

ActionMailer::Base.smtp_settings = {
  address: ENV['SMTP_ADDRESS'],
  port: ENV['SMTP_PORT'],
  user_name: ENV['SMTP_USERNAME'],
  password: ENV['SMTP_PASSWORD'],
  authentication: :plain,
  enable_starttls_auto: true
}
