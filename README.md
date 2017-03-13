# OmniAuth::Blockstack


## Installation

Add this line to your application's Gemfile:

    gem 'omniauth-blockstack'

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install omniauth-blockstack

## Usage

You use OmniAuth::Blockstack like you do any other OmniAuth strategy:

```ruby
use OmniAuth::Blockstack
```

### Authentication Process

When you authenticate through `omniauth-blockstack` you can send users to `/auth/blockstack` and it will redirect
them to their identity provider (typically the Blockstack Portal). From there, the provider must generate a signed authentication response
and send it to the `/auth/blockstack/callback` URL as a "authResponse" parameter:

    /auth/blockstack/callback?authResponse=AUTH_RESPONSE_GOES_HERE

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
