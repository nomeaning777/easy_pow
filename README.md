# EasyPow

Simple PoW System/Solver for CTFs.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'easy_pow'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install easy_pow

## Usage

### Client

```ruby
require 'easy_pow'
TCPSocket.open('127.0.0.1', '1234') do |s|
  s.puts EasyPow.solve(s.gets)
end
```

### Server

```ruby
require 'easy_pow'

# use STDIN / STDOUT
exit 0 unless EasyPow.easy_pow(27) # 27bit SHA256 PoW

# use TCPServer
TCPServer.open('0.0.0.0', 1234) do |socket|
    # ...
    exit unless EasyPow.easy_pow(25, socket) # 25bit SHA256 PoW with Socket
end
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/nomeaning777/easy_pow.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

