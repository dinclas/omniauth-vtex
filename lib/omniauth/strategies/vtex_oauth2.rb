# frozen_string_literal: true

require "omniauth-oauth2"
require "json"

module OmniAuth
  module Strategies
    # Strategy implementation for VTEX OAuth2
    class VtexOauth2 < OmniAuth::Strategies::OAuth2
      option :name, "vtex_oauth2"
      option :account
      option :client_options, authorize_url: "/_v/oauth2/auth",
                              token_url: "/_v/oauth2/token"
      options :auth_token_params, parse: (proc do |body, _response|
                                            binding.pry
                                            obj = JSON.parse(body)

                                            #TODO: Add token validation(requires VTEX signing key)
                                            payload = JWT.decode(obj['access_token'], false, nil).first

                                            payload.merge({
                                              access_token: obj['access_token'],
                                              expires_at: payload['expt']
                                            })
                                          end)

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

      def callback_url
        full_host + script_name + callback_path
      end      
    end
  end
end
