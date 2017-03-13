require 'omniauth'
require 'jwt'

module OmniAuth
  module Strategies
    class Blockstack
      class ClaimInvalid < StandardError; end

      include OmniAuth::Strategy

      ALGORITHM = 'ES256k'
      option :uid_claim, 'iss'
      option :required_claims, %w(iss username)
      option :info_map, {"name" => "username"}
      option :valid_within, nil

      def request_phase
        blockstack_js = File.open(File.join(File.dirname(__FILE__), "blockstack.js"), "rb").read

        auth_request_js = File.open(File.join(File.dirname(__FILE__), "auth-request.js"), "rb").read

        header_info = "<script>#{blockstack_js}</script>"
        app_data_js = <<~JAVASCRIPT
        var signingKey = null
        var appManifest = {
        name: "Hello, Blockstack OmniAuth",
        start_url: "http://localhost:3888/auth/blockstack/callback",
        description: "A simple demo of Blockstack Auth",
        icons: [{
          src: "https://raw.githubusercontent.com/blockstack/blockstack-portal/master/app/images/app-hello-blockstack.png",
          sizes: "192x192",
          type: "image/png",
        }]
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
        token = request.params['authResponse']

        # decode & verify token without checking signature so we can extract
        # public keys
        public_key = nil
        verify = false
        decoded_token = JWT.decode token, public_key, verify, algorithm: ALGORITHM


        payload = decoded_token['payload']
        public_keys = payload['publicKeys']

        raise ClaimInvalid.new("Invalid publicKeys array: only 1 key is supported") unless public_keys.length == 1

        public_key = public_keys[0]
        verify = true

        # decode & verify
        decoded_token = JWT.decode token, public_key, verify, algorithm: ALGORITHM

        (options.required_claims || []).each do |field|
          raise ClaimInvalid.new("Missing required '#{field}' claim.") if !decoded_token.key?(field.to_s)
        end
        raise ClaimInvalid.new("Missing required 'iat' claim.") if options.valid_within && !decoded_token["iat"]
        raise ClaimInvalid.new("'iat' timestamp claim is skewed too far from present.") if options.valid_within && (Time.now.to_i - decoded_token["iat"]).abs > options.valid_within
        super
      rescue ClaimInvalid => error
        fail! :claim_invalid, error
      rescue JWT::VerificationError => error
        fail! :signature_invalid
      end

    end

  end
end
