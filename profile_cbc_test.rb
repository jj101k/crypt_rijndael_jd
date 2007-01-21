#!/usr/bin/env ruby -rprofile
require ARGV[0]||"./core"
require "./rijndael"
require "crypt/cbc"

puts "Encrypting a fairly big block of text...\n";

huge_ptext = File.open("bwulf10.txt", "r").read
big_ptext = huge_ptext[0, 102400]
#big_ptext="Oh, the grand old Duke of York,\nHe had ten thousand men;\nHe marched them up to the top of the hill\nAnd he marched them down again."

cipher=Crypt::Rijndael.new("1234567890abcdef")

big_ctext=Crypt::CBC.new(cipher).encrypt("This is an IV...", big_ptext)
