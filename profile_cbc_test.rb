#!/usr/bin/env ruby -rprofile
require ARGV[0]| | (__dir__ + "/core")
require __dir__ + "/jdcrypt/rijndael"
require "jdcrypt/cbc"

puts "Encrypting a fairly big block of text...\n";

huge_ptext = File.open("bwulf10.txt", "r").read
big_ptext = huge_ptext[0, 102400]
#big_ptext="Oh, the grand old Duke of York,\nHe had ten thousand men;\nHe marched them up to the top of the hill\nAnd he marched them down again."

cipher=JdCrypt::Rijndael.new("1234567890abcdef")

big_ctext=JdCrypt::CBC.new(cipher).encrypt("This is an IV...", big_ptext)
