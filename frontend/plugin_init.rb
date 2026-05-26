# frozen_string_literal: true

require_relative "lib/aspace_oauth"
oauth_definitions = AppConfig[:authentication_sources].find_all do |as|
  as[:model] == "ASOauth"
end
unless oauth_definitions.any?
  raise "OmniAuth plugin enabled but no definitions provided =("
end

if !AppConfig.has_key? :oauth_debug
  AppConfig[:oauth_debug] = true # TODO: default false
end

# oauth_shared_secret is used to authenticate internal login requests from the
# frontend to the backend. It needs to be explicitly specified if the backend is
# not running in the same JVM as the frontend. When they're in the same JVM the
# secret generated here is propagated between them automatically via the system
# property set here.
if !AppConfig.has_key? :oauth_shared_secret
  require "securerandom"
  AppConfig[:oauth_shared_secret] = SecureRandom.uuid
  java.lang.System.set_property(
    "aspace.config.oauth_shared_secret", AppConfig[:oauth_shared_secret]
  )
end

# also used for ui [refactor]
AppConfig[:oauth_definitions] = oauth_definitions
ArchivesSpace::Application.extend_aspace_routes(
  File.join(File.dirname(__FILE__), "routes.rb")
)
require "omniauth"

Rails.application.config.middleware.use OmniAuth::Builder do
  oauth_definitions.each do |oauth_definition|
    verify_ssl = oauth_definition.fetch(:verify_ssl, true)
    config = oauth_definition[:config]
    if oauth_definition.key? :metadata_parser_url
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      idp_metadata = idp_metadata_parser.parse_remote_to_hash(
        oauth_definition[:metadata_parser_url], verify_ssl
      )
      config = idp_metadata.merge(config)
    end
    if config.key? :security
      # replace strings with constants for *_method
      [:digest_method, :signature_method].each do |m|
        if config[:security].key? m
          config[:security][m] = config[:security][m].constantize
        end
      end
    end
    provider oauth_definition[:provider], config
    $stdout.puts "REGISTERED OAUTH PROVIDER WITH CONFIG: #{config}" if AspaceOauth.debug?
  end
end

Rails.application.config.after_initialize do
  # remove the option to start a login from the front end unless it goes through oauth controller
  # unless configured to allow standard login
  class SessionController < ApplicationController
  
    def login
      if AppConfig.has_key?(:aspace_oauth_override_standard_login) && AppConfig[:aspace_oauth_override_standard_login]
        backend_session = User.login(params[:username], params[:password])
      else
        backend_session = nil
      end
  
      if backend_session
        User.establish_session(self, backend_session, params[:username])
      end
  
      load_repository_list
  
      render :json => {:session => backend_session, :csrf_token => form_authenticity_token}
    end
    
  end

end