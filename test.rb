#!/usr/bin/ruby -w
require "crypt/rijndael"

puts "Setting up caching..."
Crypt::Rijndael.make_shiftrow_map
puts "Done"

input, rkey=[
	0x32, 0x88, 0x31, 0xe0,
	0x43, 0x5a, 0x31, 0x37,
	0xf6, 0x30, 0x98, 0x07,
	0xa8, 0x8d, 0xa2, 0x34
].pack("C*"),[
	0x2b, 0x28, 0xab, 0x09,
	0x7e, 0xae, 0xf7, 0xcf,
	0x15, 0xd2, 0x15, 0x4f,
	0x16, 0xa6, 0x88, 0x3c
].pack("C*")

rkey=[ 
	0xa0, 0x88, 0x23, 0x2a,
	0xfa, 0x54, 0xa3, 0x6c,
	0xfe, 0x2c, 0x39, 0x76,
	0x17, 0xb1, 0x39, 0x05,
].pack("C*")

real_key=[ 
	0x2b, 0x7e, 0x15, 0x16 ,
	0x28, 0xae, 0xd2, 0xa6 ,
	0xab, 0xf7, 0x15, 0x88 ,
	0x09, 0xcf, 0x4f, 0x3c ,
].pack("C*")

puts "Testing enc/dec... in other words, can I decrypt what I encrypt?\n"
test_string="test\n123456789ab" # exactly 16 bytes

cipher=Crypt::Rijndael.new(real_key)

ctext=cipher.encrypt(test_string)
if(cipher.decrypt(ctext) == test_string)
	puts "Apparently I can.\n"
else
	puts "Erk! Nope, something's broken.\n"
end


puts "Let's try some odd combinations...\n"

long_key=[
	0xa0, 0x88, 0x23, 0x2a,
	0xfa, 0x54, 0xa3, 0x6c,
	0x2b, 0x7e, 0x15, 0x16,
	0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88,
	0xfe, 0x2c, 0x39, 0x76,
	0x17, 0xb1, 0x39, 0x05,
	0x09, 0xcf, 0x4f, 0x3c,
].pack("C*")

long_iv=[
		0x4a, 0x07, 0x0e, 0x92,
		0xdc, 0xc6, 0x97, 0xa5,
		0xea, 0xf5, 0xe3, 0x49,
		0xf2, 0x63, 0x05, 0xc5,
		0x2b, 0x81, 0x0a, 0xca,
		0x7f, 0xf9, 0x39, 0x49,
		0x8d, 0x4a, 0x14, 0x59,
		0x38, 0x09, 0x52, 0xf0
].pack("C*")

long_ptext="0123456789abcdefABCDEFghijklmnop"

keys=Hash.new
keys[32]=long_key
keys[24]=long_key[0 .. 23]
keys[16]=long_key[0 .. 15]
ivs=Hash.new
ivs[32]=long_iv
ivs[24]=long_iv[0 .. 23]
ivs[16]=long_iv[0 .. 15]
pts=Hash.new
pts[32]=long_ptext
pts[24]=long_ptext[0 .. 23]
pts[16]=long_ptext[0 .. 15]

ctexts={16=>{}, 24=>{}, 32=>{}}

[16, 24, 32].each do
	|keylen|
	cipher=Crypt::Rijndael.new(keys[keylen])
	[16, 24, 32].each do
		|blocklen|
		puts "Block length #{blocklen*8}, key length #{keylen*8}\n"
			unless(cipher.blocksize = blocklen)
				puts "Uh-oh! I can't set a block size. Am I in AES mode?\n"
				next
			end
			ctexts[keylen][blocklen]=cipher.encrypt(pts[blocklen])
			if(cipher.decrypt(ctexts[keylen][blocklen]) == pts[blocklen])
				puts "Works.\n"
			else
				puts "Failed.\n"
			end
	end	
end
	puts "Testing AES mode"
	cipher_rd=Crypt::Rijndael.new(keys[16])
	cipher_rd.blocksize=32
	cipher_aes=Crypt::AES.new(keys[16])
	cipher_aes.blocksize=16
	begin
		cipher_aes.blocksize=32
		puts "Failure"
	rescue RuntimeError
		puts "Success"
	end

	sample_long="This is some text that, well, basically exists only for the purpose of being long, thus forcing the usage of a block mode.\n"
	cipher=Crypt::Rijndael.new(keys[16])
	ctext_cbc=cipher.encrypt_CBC(ivs[16], sample_long)

	puts "Testing time-to-encrypt a big block of data (keeping it in core)...\n";
	huge_ptext=IO.readlines("bwulf10.txt", nil)[0]

	crypt=Crypt::Rijndael.new(keys[16])

	before=Time.new
	huge_ctext=crypt.encrypt_CBC(ivs[16], huge_ptext)
	after=Time.new

	diff=after-before
	size=huge_ptext.length/1024
	puts sprintf("#{diff} seconds to encrypt a %.1fKiB file (%.1fKiB/s).\n", size, size/diff)

  puts "Switching to Crypt::AES for decrypt"
	crypt=Crypt::AES.new(keys[16])
	before=Time.new
	new_huge_ptext=crypt.decrypt_CBC(ivs[16], huge_ctext)
	after=Time.new

	diff=after-before
	puts sprintf("#{diff} seconds to decrypt (%.1fKiB/s).\n", size/diff)
	if(new_huge_ptext == huge_ptext)
		puts "All seemed to work.\n"
	else
		puts "Argh! Something went pear-shaped!\n"
		if(new_huge_ptext.length!=huge_ptext.length)
			puts "Length mismatch: was #{huge_ptext.length}, is #{new_huge_ptext.length}"
		else
			(0 .. new_huge_ptext.length-1).each do
				|offset|
				if(new_huge_ptext[offset]!=huge_ptext[offset])
					if(offset>5)
						p "Mismatch at #{offset}: '#{new_huge_ptext[offset-5,10]}' != '#{huge_ptext[offset-5,10]}'" 
					else
						p "Mismatch at #{offset}: '#{new_huge_ptext[0,10]}' != '#{huge_ptext[0,10]}'" 
					end
				end
			end
		end
	end

	puts "Here's (a snippet of) the result of the decryption:\n"
	puts "\n..."+new_huge_ptext[40960, 256]+"...\n"
