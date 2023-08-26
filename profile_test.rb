#!/usr/bin/env ruby -rprofile
require ARGV[0]||"./core"
require "./jdcrypt/rijndael"

puts "Encrypting a block of text...\n";

cipher=JdCrypt::Rijndael.new("1234567890abcdef")

1000.times do # This ensures we get to see the effects of caching
	cipher.encrypt("This is an IV...")
end
