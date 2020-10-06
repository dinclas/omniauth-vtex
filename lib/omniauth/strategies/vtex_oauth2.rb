# frozen_string_literal: true

require "omniauth-oauth2"

module OmniAuth
  module Strategies
    # Strategy implementation for VTEX OAuth2
    class VtexOauth2 < OmniAuth::Strategies::OAuth2
      option :name, "vtex_oauth2"
      option :account
      option :client_options, authorization_url: "/_v/oauth2/auth",
                              token_url: "/_v/oauth2/token"

      option :setup, (lambda do |env|
        strategy = env["omniauth.strategy"]
        account = strategy.options[:account]

        env["omniauth.strategy"].options[:client_options]["site"] = "https://#{account}.myvtex.com"
      end)

      uid { access_token["user_id"] }

      info do
        {
          name: access_token["unique_name"],
          email: access_token["email"]
        }
      end
    end
  end
end
