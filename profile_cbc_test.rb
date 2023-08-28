#!/usr/bin/env ruby -rprofile

# frozen_string_literal: true

require ARGV[0] || "#{__dir__}/core"
require "#{__dir__}/jdcrypt/rijndael"
require "jdcrypt/cbc"

puts "Encrypting a fairly big block of text...\n"

huge_ptext = File.open("bwulf10.txt", "r").read
big_ptext = huge_ptext[0, 102_400]

cipher = JdCrypt::Rijndael.new("1234567890abcdef")

JdCrypt::CBC.new(cipher).encrypt("This is an IV...", big_ptext)
