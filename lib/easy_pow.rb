require 'easy_pow/version'
require 'easy_pow/ext'
require 'securerandom'
require 'digest/sha2'

module EasyPow
  @@hashes = [
    ['sha1', 160],
    ['md5', 128],
    ['sha224', 224],
    ['sha256', 256],
    ['sha384', 384],
    ['sha512', 512]
  ]

  def search_prefix(hash, bin, length, prefix, suffix = '', chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', parallel = true)
    len = @@hashes.select{|a|a[0] == hash.to_s.downcase}[0]
    raise ArgumentError.new('Unknown hash type: %s' % [hash.to_s.downcase]) unless len
    len = len[1] / 8
    raise ArgumentError.new('Too long prefix') if bin.size > len * 8
    target = Array.new(len){0}
    mask = Array.new(len){0}
    bin.each_char.with_index do |b, i|
      mask[i / 8] |= 1 << (7 - i % 8)
      target[i / 8] |= b.to_i << (7 - i % 8)
    end
    send 'search_' + hash.to_s.downcase + '_ext', prefix, suffix, length, target.pack("C*"), mask.pack("C*"), chars, parallel
  end

  def search_suffix(hash, bin, length, prefix, suffix = '', chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', parallel = true)
    len = @@hashes.select{|a|a[0] == hash.to_s.downcase}[0]
    raise ArgumentError.new('Unknown hash type: %s' % [hash.to_s.downcase]) unless len
    len = len[1] / 8
    raise ArgumentError.new('Too long prefix') if bin.size > len * 8
    target = Array.new(len){0}
    mask = Array.new(len){0}
    bin.each_char.with_index do |b, i|
      mask[-(i / 8) - 1] |= 1 << (i % 8)
      target[-(i / 8) - 1] |= b.to_i << (i % 8)
    end
    send 'search_' + hash.to_s.downcase + '_ext', prefix, suffix, length, target.pack("C*"), mask.pack("C*"), chars, parallel
  end

  def easy_pow(bits, socket = nil)
    in_s = out_s = socket
    if socket == nil
      in_s = STDIN
      out_s = STDOUT
    end
    prefix = SecureRandom.hex(8)
    out_s.print "Send me proof-of-work: The first #{bits}-bits of sha256(\"#{prefix}\" + input.rstrip) is \"111...1\"\n"
    out_s.flush
    input = in_s.gets.strip.force_encoding('ASCII-8BIT')
    digest = Digest::SHA256.digest(prefix + input.rstrip).unpack("C*")
    bits.times do |i|
      if (digest[i / 8] >> (7 - i % 8) & 1) == 0
        return false
      end
    end
    return true
  end

  def solve(input)
    if /The first (\d+)-bits of sha256\("(.{16})"/ =~ input
      search_prefix('sha256', '1' * $1.to_i, 12, $2)[16..-1]
    else
      raise ArgumentError.new("Invalid format")
    end
  end

  module_function :search_prefix, :search_suffix
  module_function :easy_pow, :solve
end
