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
        # TODO generate blockstack auth request
        # TODO redirect to user's auth endpoint
        redirect 'blockstack://abcdef'
      end

      def decoded
        @decoded ||= ::JWT.decode(request.params['jwt'], options.secret, ALGORITHM)[0]
        (options.required_claims || []).each do |field|
          raise ClaimInvalid.new("Missing required '#{field}' claim.") if !@decoded.key?(field.to_s)
        end

        @decoded
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
