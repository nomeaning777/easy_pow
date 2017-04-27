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

### Solver

```
EasyPow.search_prefix(hash_type, prefix_bin, length, prefix, suffix = '', chars = '012...9ABC...Zabcd...z', parallel = true)
EasyPow.search_suffix(hash_type, suffix_bin, length, prefix, suffix = '', chars = '012...9ABC...Zabcd...z', parallel = true)

hash_type: :md5, :sha1, :sha224, :sha256, :sha384, :sha512
prefix_bin, suffix_bin: binary string of prefix or suffix (ex '0' * 24)
length: search string length ( except suffix and prefix length)
prefix: prefix string
suffix: suffix string
chars: search characters
parallel: use OpenMP

Example:
pry(main)> EasyPow.search_prefix(:md5, '1' * 24, 15, 'prefix', 'suffix', '0123456789')
=> "prefix200000000320050suffix"
pry(main)> Digest::MD5.hexdigest(_)
=> "ffffff75e679e4848069201dc511d302"

pry(main)> EasyPow.search_suffix(:sha256, '0' * 24, 15, 'prefix', 'suffix', '0123456789')
=> "prefix200000000637294suffix"
pry(main)> Digest::SHA256.hexdigest(_)
=> "54497d47f47496d82911a45f6bbfd4475f6d37502b9481006acbc9ca9a000000"
```

### Client

```ruby
require 'easy_pow'
TCPSocket.open('127.0.0.1', '1234') do |s|
  EasyPow.solve(s)
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

