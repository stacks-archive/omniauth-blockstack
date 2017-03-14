require 'omniauth'
require 'blockstack'

module OmniAuth
  module Strategies
    class Blockstack
      class ClaimInvalid < StandardError; end

      include OmniAuth::Strategy

      args [:app_name, :blockstack_api]

      option :uid_claim, 'iss'
      option :info_map, {"name" => "username"}
      option :leeway, nil
      option :valid_within, nil
      option :blockstack_api, nil
      option :app_name, nil
      option :app_description, ""
      option :app_icons, [{}]

      def decoded_token
        @decoded_token
      end

      def request_phase
        blockstack_js = File.open(File.join(File.dirname(__FILE__), "blockstack.js"), "rb").read

        auth_request_js = File.open(File.join(File.dirname(__FILE__), "auth-request.js"), "rb").read

        header_info = "<script>#{blockstack_js}</script>"
        app_data_js = <<~JAVASCRIPT
        var signingKey = null
        var appManifest = {
        name: "#{options.app_name}",
        start_url: "#{callback_url}",
        description: "#{options.app_description}",
        icons: #{options.app_icons.to_json}
        }
        JAVASCRIPT

        header_info << "<script>#{app_data_js}</script>"
        header_info << "<script>#{auth_request_js}</script>"
        form = OmniAuth::Form.new(:title => "Blockstack Auth Request Generator",
        :header_info => header_info,
        :url => callback_path)
        form.to_response
      end

      def callback_phase
        auth_response = request.params['authResponse']

        ::Blockstack.api = options.api
        ::Blockstack.leeway = options.leeway
        ::Blockstack.valid_within = options.valid_within
        @decoded_token = ::Blockstack.verify_auth_response auth_response
        puts "decoded_token: #{decoded_token}"
        super

      rescue ::Blockstack::InvalidAuthResponse => error
        fail! :invalid_auth_response, error
      end

      uid{ decoded_token[options.uid_claim] }

      extra do
        {:raw_info => decoded_token}
      end

      info do
        options.info_map.inject({}) do |h,(k,v)|
          h[k.to_s] = decoded_token[v.to_s]
          h
        end
      end

    end
  end
end
