#!/usr/bin/env ruby -rprofile

# frozen_string_literal: true

require ARGV[0] || "#{__dir__}/core"
require "#{__dir__}/jdcrypt/rijndael"

puts "Encrypting a block of text...\n"

cipher = JdCrypt::Rijndael.new("1234567890abcdef")

1000.times do # This ensures we get to see the effects of caching
  cipher.encrypt("This is an IV...")
end
