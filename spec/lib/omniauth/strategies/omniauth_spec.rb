require 'spec_helper'

describe OmniAuth::Strategies::Blockstack do
  let(:response_json){ MultiJson.load(last_response.body) }
  let(:args){ [{}] }

  let(:app){
    the_args = args
    Rack::Builder.new do |b|
      b.use Rack::Session::Cookie, secret: 'shushdonttell'
      b.use OmniAuth::Strategies::Blockstack, *the_args
      b.run lambda{|env| [200, {}, [(env['omniauth.auth'] || {}).to_json]]}
    end
  }

  context 'request phase' do
    it 'should generate a valid Blockstack auth request' do
      # TODO write this test
      fail :not_implemented
    end
    it 'should redirect to the configured portal url' do
      get '/auth/blockstack'
      expect(last_response.status).to eq(302)
      # TODO finish this test
      fail :not_implemented
      expect(last_response.headers['Location']).to eq("http://localhost:8888/auth?authRequest=#{auth_request}")
    end
  end

  context 'callback phase' do
    it 'should decode the response' do
      # TODO write this test
      fail :not_implemented
    end
  end
end
