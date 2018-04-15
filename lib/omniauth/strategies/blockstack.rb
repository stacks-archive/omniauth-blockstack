require 'omniauth'
require 'blockstack'
require 'uri'

module OmniAuth
  module Strategies
    class Blockstack
      class ClaimInvalid < StandardError; end

      include OmniAuth::Strategy

      args [:app_name, :blockstack_api]

      option :uid_claim, 'iss'
      option :leeway, nil
      option :valid_within, nil
      option :blockstack_api, nil
      option :app_name, nil
      option :app_short_name, nil
      option :app_description, ""
      option :app_icons, [{}]

      def decoded_token
        @decoded_token
      end

      def request_phase
        app_manifest = {
          :name => options.app_name,
          :short_name => (options.app_short_name ? options.app_short_name : options.app_name),
          :start_url => callback_url,
          :display => "standalone",
          :background_color => "#fff",
          :description => options.app_description,
          :icons => options.app_icons
        }

        if request.params["manifest"]
          return Rack::Response.new(app_manifest.to_json,
                                    200,
                                    'content-type' => 'text/json',
                                    'Access-Control-Allow-Origin' => '*').finish
        end

        blockstack_js = File.open(File.join(File.dirname(__FILE__), "blockstack.js"), "rb").read

        auth_request_js = File.open(File.join(File.dirname(__FILE__), "auth-request.js"), "rb").read

        header_info = "<script>#{blockstack_js}</script>"
        app_data_js = <<~EOS
        var manifestURI = "#{callback_url.chomp("/callback") + "?manifest=true"}"
        var redirectURI = "#{callback_url}"
        var scopes = #{options.scope ? '['+options.scope.map {|s| "'#{s}'"}.join(',') + ']' : null}
        EOS

        header_info << "<script>#{app_data_js}</script>"
        header_info << "<script>#{auth_request_js}</script>"
        form = OmniAuth::Form.new(
          :title => "Blockstack Auth Request Generator",
          :header_info => header_info,
          :url => callback_path
        )
        form.to_response
      end

      def callback_phase
        auth_response = request.params['authResponse']

        ::Blockstack.api = options.blockstack_api
        ::Blockstack.leeway = options.leeway
        ::Blockstack.valid_within = options.valid_within
        @decoded_token = ::Blockstack.verify_auth_response auth_response

        super

      rescue ::Blockstack::InvalidAuthResponse => error
        fail! :invalid_auth_response, error
      end

      uid{ decoded_token[options.uid_claim] }

      extra do
        {:raw_info => decoded_token}
      end

      credentials do
        token = nil # In future store token to access Blockstack Core node/storage here
        {:token => token}
      end

      info do
        {
          :nickname => decoded_token["username"],
          :first_name => decoded_token["profile"].try(:[],"givenName"),
          :last_name => decoded_token["profile"].try(:[],"familyName"),
          :location => decoded_token["profile"].try(:[],"address").try(:[],"addressLocality"),
          :description => decoded_token["profile"].try(:[],"description"),
          :image => lambda {|images|
            return nil if images.nil?
            for image in images
              if image && image.try(:[],"name") == "avatar"
                avatar_url = image.try(:[],"contentUrl")
                if avatar_url && !avatar_url.blank?
                  return avatar_url
                end
              end
            end
            nil
          }.call(decoded_token["profile"].try(:[],"image")),
          :urls => lambda {|websites|
            urls = {}
            return urls if websites.nil?
            count = 0
            websites.each do |website|
              if website.try(:[],"@type") == "WebSite"
                if !website.try(:[],"url").nil?
                  count = count + 1
                  urls["site-#{count}"] = website["url"]
                end
              end
            end
            return urls
          }.call(decoded_token["profile"].try(:[],"website"))
        }
      end

    end
  end
end
