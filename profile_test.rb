#!/usr/bin/env ruby -rprofile
require ARGV[0]||"./core"
require "./rijndael"

puts "Encrypting a block of text...\n";

cipher=Crypt::Rijndael.new("1234567890abcdef")

100.times do # This ensures we get to see the effects of caching
	cipher.encrypt("This is an IV...")
end
