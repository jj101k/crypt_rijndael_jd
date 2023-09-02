#!/usr/bin/ruby -w

# frozen_string_literal: true

require ARGV[0] || "#{__dir__}/core"
require "#{__dir__}/jdcrypt/rijndael"
require "#{__dir__}/jdcrypt/aes"
begin
  require "jdcrypt/cbc"
rescue LoadError
  # We will check this later
end

TestString1 = "0123456789\x9abc\xcde\xff"

puts "Testing simplest possible encryption"
cipher = JdCrypt::Rijndael.new("1" * 16)
raise unless cipher.encrypt("2" * 16)

puts "Ok"

real_key = [
  0x2b, 0x7e, 0x15, 0x16,
  0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88,
  0x09, 0xcf, 0x4f, 0x3c,
].pack("C*")

puts "Testing enc/dec... in other words, can I decrypt what I encrypt?\n"
test_string = "test\n123456789ab" # exactly 16 bytes

cipher = JdCrypt::Rijndael.new(real_key)

ctext = cipher.encrypt(test_string)

# % (echo test; echo -n 123456789ab) | openssl enc -aes-128-cbc -K
# 2b7e151628aed2a6abf7158809cf4f3c -iv 0000000000000000 | od -t x1
# 0000000    cf  21  3b  c0  38  6c  43  c0  cc  c8  f1  08  bb  50  83  54
# 0000020    a7  86  74  a6  6c  7f  09  2e  b2  8c  0c  97  75  fa  17  3d
# 0000040
# %

if ctext != ["cf213bc0386c43c0ccc8f108bb508354"].pack("H*")
  p ctext
  puts "Couldn't even encrypt correctly!\n"
  raise
end

if cipher.decrypt(ctext) == test_string
  puts "Apparently I can.\n"
else
  puts "Erk! Nope, something's broken.\n"
  raise
end

puts "Let's try some odd combinations...\n"

long_key = [
  0xa0, 0x88, 0x23, 0x2a,
  0xfa, 0x54, 0xa3, 0x6c,
  0x2b, 0x7e, 0x15, 0x16,
  0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88,
  0xfe, 0x2c, 0x39, 0x76,
  0x17, 0xb1, 0x39, 0x05,
  0x09, 0xcf, 0x4f, 0x3c,
].pack("C*")

long_iv = [
  0x4a, 0x07, 0x0e, 0x92,
  0xdc, 0xc6, 0x97, 0xa5,
  0xea, 0xf5, 0xe3, 0x49,
  0xf2, 0x63, 0x05, 0xc5,
  0x2b, 0x81, 0x0a, 0xca,
  0x7f, 0xf9, 0x39, 0x49,
  0x8d, 0x4a, 0x14, 0x59,
  0x38, 0x09, 0x52, 0xf0,
].pack("C*")

long_ptext = "0123456789abcdefABCDEFghijklmnop"

keys = {
  32 => long_key,
  24 => long_key[0..23],
  16 => long_key[0..15],
}
ivs = {
  32 => long_iv,
  24 => long_iv[0..23],
  16 => long_iv[0..15],
}
pts = {
  32 => long_ptext,
  24 => long_ptext[0..23],
  16 => long_ptext[0..15],
}

ctexts = { 16 => {}, 24 => {}, 32 => {} }

[16, 24, 32].each do |keylen|
  cipher = JdCrypt::Rijndael.new(keys[keylen])
  [16, 24, 32].each do |blocklen|
    puts "Block length #{blocklen * 8}, key length #{keylen * 8}\n"
    unless (cipher.blocksize = blocklen)
      puts "Uh-oh! I can't set a block size. Am I in AES mode?\n"
      next
    end
    ctexts[keylen][blocklen] = cipher.encrypt(pts[blocklen])
    if cipher.decrypt(ctexts[keylen][blocklen]) == pts[blocklen]
      puts "Works.\n"
    else
      puts "Failed.\n"
    end
  end
end
puts "Testing AES mode"

[16, 24, 32].each do |keylen|
  cipher = JdCrypt::AES.new(keys[keylen])
  blocklen = 16
  puts "Block length #{blocklen * 8}, key length #{keylen * 8}\n"
  unless (cipher.blocksize = blocklen)
    puts "Uh-oh! I can't set a block size. Am I in AES mode?\n"
    next
  end
  ctexts[keylen][blocklen] = cipher.encrypt(pts[blocklen])
  if cipher.decrypt(ctexts[keylen][blocklen]) == pts[blocklen]
    puts "Works.\n"
  else
    puts "Failed.\n"
  end
end

cipher_rd = JdCrypt::Rijndael.new(keys[16])
cipher_rd.blocksize = 32
cipher_aes = JdCrypt::AES.new(keys[16])
cipher_aes.blocksize = 16
begin
  cipher_aes.blocksize = 32
  puts "Failure"
  exit 0
rescue RuntimeError
  puts "Success"
end

c = JdCrypt::AES.new(["DBDBDBDBDBDBDBDBDBDBDBDBDBDBDBDBDBDBDBDBDBDBDBDB"].pack("H*"))

unless c.encrypt(["00000000000000000000000000000000"].pack("H*")).unpack1("H*") == "8d0fb61ad510df6d8f401b8ac01f19b6"
  raise "Failed to encrypt properly at 192k/128b"
end

sample_long =
  "This is some text that, well, basically exists only for the purpose of being long, \
  thus forcing the usage of a block mode.\n"

cipher = JdCrypt::Rijndael.new(keys[16])

if !defined? JdCrypt::CBC
  puts "No JdCrypt::CBC, skipping CBC tests"
  exit
else
  JdCrypt::CBC.new(cipher).encrypt(ivs[16], sample_long)
end

puts "Testing time-to-encrypt a big block of data (keeping it in core)...\n"

# Bug workaround for Linux
huge_ptext = File.open("bwulf10.txt", "r").read

cipher = JdCrypt::Rijndael.new(keys[16])

before = Time.new
huge_ctext = nil
if !defined? JdCrypt::CBC
  puts "No JdCrypt::CBC, skipping"
else
  huge_ctext = JdCrypt::CBC.new(cipher).encrypt(ivs[16], huge_ptext)
end
after = Time.new

diff = after - before
size = huge_ptext.length / 1024
puts sprintf("#{diff} seconds to encrypt a %.1fKiB file (%.1fKiB/s).\n", size, size / diff)

puts "Switching to JdCrypt::AES for decrypt"
cipher = JdCrypt::AES.new(keys[16])
before = Time.new
new_huge_ptext = nil
if !defined? JdCrypt::CBC
  puts "No JdCrypt::CBC, skipping"
else
  new_huge_ptext = JdCrypt::CBC.new(cipher).decrypt(ivs[16], huge_ctext)
end
after = Time.new

diff = after - before
puts sprintf("#{diff} seconds to decrypt (%.1fKiB/s).\n", size / diff)
if new_huge_ptext == huge_ptext
  puts "All seemed to work.\n"
else
  puts "Argh! Something went pear-shaped!\n"
  if new_huge_ptext.length != huge_ptext.length
    puts "Length mismatch: was #{huge_ptext.length}, is #{new_huge_ptext.length}"
  else
    0.upto(new_huge_ptext.length - 1) do |offset|
      if new_huge_ptext[offset] != huge_ptext[offset]
        if offset > 5
          p "Mismatch at #{offset}: '#{new_huge_ptext[offset - 5, 10]}' != '#{huge_ptext[offset - 5, 10]}'"
        else
          p "Mismatch at #{offset}: '#{new_huge_ptext[0, 10]}' != '#{huge_ptext[0, 10]}'"
        end
      end
    end
  end
end

puts "Here's (a snippet of) the result of the decryption:\n"
puts "\n...#{new_huge_ptext[40_960, 256]}...\n"
