require 'omniauth'
require 'jwt'
require 'bitcoin'

module OmniAuth
  module Strategies
    class Blockstack
      class ClaimInvalid < StandardError; end

      include OmniAuth::Strategy

      args [:app_name]

      ALGORITHM = 'ES256K'
      LEEWAY = 30 #seconds
      option :uid_claim, 'iss'
      option :required_claims, %w(iss username)
      option :info_map, {"name" => "username"}
      option :valid_within, nil
      option :app_name, nil
      option :app_description, ""
      option :app_icons, [{}]

      def decoded_token
        @decoded_token
      end

      def get_did_type(decentralized_id)
        did_parts = decentralized_id.split(':')
        raise 'Decentralized IDs must have 3 parts' if did_parts.length != 3
        raise 'Decentralized IDs must start with "did"' if did_parts[0].downcase != 'did'
        did_parts[1].downcase
      end

      def get_address_from_did(decentralized_id)
        did_type = get_did_type(decentralized_id)
        return nil if did_type != 'btc-addr'
        decentralized_id.split(':')[2]
      end

      def public_keys_match_issuer?(decoded_token)
        public_keys = decoded_token['publicKeys']
        address_from_issuer = get_address_from_did(decoded_token['iss'])

        raise 'Multiple public keys are not supported' unless public_keys.count == 1

        address_from_public_keys = Bitcoin::pubkey_to_address public_keys.first

        address_from_issuer == address_from_public_keys
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
        token = request.params['authResponse']

        # decode & verify token without checking signature so we can extract
        # public keys
        public_key = nil
        verify = false
        decoded_tokens = JWT.decode token, public_key, verify, algorithm: ALGORITHM

        public_keys = decoded_tokens[0]['publicKeys']
        Rails.logger.debug decoded_tokens
        raise ClaimInvalid.new("Invalid publicKeys array: only 1 key is supported") unless public_keys.length == 1

        compressed_hex_public_key = public_keys[0]
        bignum = OpenSSL::BN.new(compressed_hex_public_key, 16)
        group = OpenSSL::PKey::EC::Group.new 'secp256k1'
        public_key = OpenSSL::PKey::EC::Point.new(group, bignum)
        ecdsa_key = OpenSSL::PKey::EC.new 'secp256k1'
        ecdsa_key.public_key = public_key
        verify = true

        # decode & verify signature
        decoded_tokens = JWT.decode token, ecdsa_key, verify, algorithm: ALGORITHM, exp_leeway: LEEWAY
        @decoded_token = decoded_tokens[0]

        raise "Public keys don't match issuer address" unless public_keys_match_issuer?(decoded_token)

        (options.required_claims || []).each do |field|
          raise ClaimInvalid.new("Missing required '#{field}' claim.") if !decoded_token.key?(field.to_s)
        end
        raise ClaimInvalid.new("Missing required 'iat' claim.") if options.valid_within && !decoded_token["iat"]
        raise ClaimInvalid.new("'iat' timestamp claim is skewed too far from present.") if options.valid_within && (Time.now.to_i - decoded_token["iat"]).abs > options.valid_within
        super

      rescue ClaimInvalid => error
        fail! :claim_invalid, error
      rescue JWT::VerificationError => error
        fail! :signature_invalid, error
      rescue JWT::DecodeError => error
        fail! :decode_error, error
      rescue Exception => error
        fail! :error, error
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
