unless(defined? Crypt::ByteStream)
	require "crypt/bytestream"
end
# This is to help testing
unless(defined? Crypt::Rijndael::Core)
	require "crypt/rijndael/core"
end

class Crypt
=begin rdoc
Crypt::Rijndael allows you to encrypt single blocks of data using the encrypt() and decrypt() methods
below.

You probably want to use some kind of CBC module with this.
=end
    class Rijndael

    
        @@rounds_by_block_size={
            4=>10,
            6=>12,
            8=>14
        }
        
        @@valid_blocksizes_bytes=[16, 24, 32]
        @@valid_keysizes_bytes=[16, 24, 32]

=begin rdoc
The new() function here takes only one argument: the key to use, as a String (or similar). Valid lengths
are 16, 24 or 32 bytes, and you should ensure that this value is sufficiently random. Most people will
choose 16-byte (128-bit) keys, but a longer key will take longer to crack if security is of unusually
high importance for you.
=end
        def initialize(new_key)
 						self.key = new_key
						@current_block_length = nil # This makes it easier to adjust in #block=
        end

				attr_reader :key

				# If you want to, you can assign a new key to an existing object.
				def key=(new_key)
					raise "Invalid key length: #{new_key.length}" unless(self.class.key_sizes_supported.find {|size| size==new_key.length})
					@key = new_key
					@key_words=@key.length/4
					@expanded_key = nil
					@round_count = nil
				end

				attr_reader :block
				def block=(new_block) #:nodoc:
					if(new_block.length != @current_block_length) then
						raise "Invalid block size: #{new_block.length}" unless(block_sizes_supported.find { |size| size==new_block.length })
						@current_block_length = new_block.length
						@block_words = @current_block_length / 4
						@expanded_key = nil
						@round_count = nil
					end
					@block = new_block
				end
				protected :block=, :block, :key

				# If you want to probe for supported block sizes, by all means use this method. It'll raise
				# if the value isn't supported.
				#
				# Don't use this: #block_sizes_supported is better.
        def blocksize=(block_size_bytes)
						self.block = "\x00" * block_size_bytes
						self
        end

				# This lets you know how big a block is currently being used.
				# There's probably no point using this.
        def blocksize
            return @block_words*4
        end

				# Provides a list of block sizes (bytes) which are supported
				def self.block_sizes_supported
					@@valid_blocksizes_bytes
				end

				# Provides a list of key sizes (bytes) which are supported
				def self.key_sizes_supported
					@@valid_keysizes_bytes
				end
        
				# This just calls the class' .block_sizes_supported method for you.
				def block_sizes_supported
					self.class.block_sizes_supported
				end
        
        
        def round_count #:nodoc:
						return @round_count if @round_count
            biggest_words=if(@block_words > @key_words)
                @block_words
            else
                @key_words
            end
            @round_count = @@rounds_by_block_size[biggest_words]
        end
				def round_constants #:nodoc:
						@@round_constants ||= {}
						@@round_constants[@block_words] ||= {}
						unless(@@round_constants[@block_words][@key_words]) then
							temp_v=1
							p_round_constant=[0,1].map {|i| [i, 0, 0, 0].pack("C*")}
							
							p_round_constant+=
							(2 .. (@block_words * (round_count + 1)/@key_words).to_i).to_a.map {
									#0x1000000<<($_-1)
									[(temp_v=Core.dot(02,temp_v)),0,0,0].pack("C*")
							}
							@@round_constants[@block_words][@key_words] = p_round_constant
						end
						@@round_constants[@block_words][@key_words]
				end
        
        def expand_key_le6 #:nodoc
					# For short (128-bit, 192-bit) keys this is used to expand the key to blocklen*(rounds+1) bits
            p "Expanding key" if $DEBUG
            
            #expanded_key=key;
            ek_words=key.unpack("N*").map {|number| Crypt::ByteStream.new([number].pack("N"))}
        
						p_round_constant = round_constants
        
            rounds=round_count
            
            if($DEBUG) 
                (0 .. @key_words-1).each do
                    |i|
                    p "w#{i} = #{ek_words[i].to_x}"
                end
            end
            
            (@key_words .. @block_words * (rounds + 1)-1).each do
                |i|
                p "i = #{i}" if $DEBUG

                p_temp=ek_words[i-1]
                
                p sprintf("%.8x (temp)", p_temp.to_x) if $DEBUG
                
                if(i % @key_words == 0) 
                    
                        t_byte=p_temp[0]
                        p_temp[0 .. 2]=p_temp[1 .. 3]
                        p_temp[3]=t_byte
                    p sprintf("%.8x (RotWord)", p_temp.to_x) if $DEBUG        
                    
                    # tr would be great here again.
                    p_temp=Crypt::ByteStream.new(Core.sbox_block(p_temp))
                    p sprintf("%.8x (SubWord)", p_temp.to_x) if $DEBUG    
                    p sprintf("%.8x (Rcon[i/Nk])", p_round_constant[(i/@key_words).to_i].to_x) if $DEBUG
                    p_temp^=p_round_constant[(i/@key_words).to_i]
                    p sprintf("%.8x (After XOR)", p_temp.to_x) if $DEBUG
                end
                p sprintf("%.8x (w[i-Nk])", ek_words[i-@key_words].to_x) if $DEBUG
                ek_words[i]=p_temp^ek_words[i-@key_words]
                p sprintf("%.8x (w[i]=temp XOR w[i-Nk])", ek_words[i].to_x) if $DEBUG
                i+=1
            end
            #puts ek_words.to_s
            expanded_key=Array(rounds+1)
            (0 .. rounds).each do
                |round|
                expanded_key[round]=Crypt::ByteStream.new(ek_words[round*@block_words, @block_words].to_s)
            end
            return expanded_key; 
        end
                
        def expand_key_gt6 #:nodoc:
					# For long (256-bit) keys this is used to expand the key to blocklen*(rounds+1) bits
            p "Expanding key (large)" if $DEBUG
            
            #expanded_key=key
            ek_words=key.unpack("N*").map {|number| Crypt::ByteStream.new([number].pack("N"))}
        
						p_round_constant = round_constants

            rounds=round_count

            if($DEBUG) 
                (0 .. @key_words-1).each do
                    |i|
                    p "w#{i} = #{ek_words[i].to_x}"
                end
            end
        
            (@key_words .. @block_words * (rounds + 1)-1).each do 
                |i|
                p "i = #{i}" if $DEBUG

                p_temp=ek_words[i-1]
                p sprintf("%.8x (temp)", p_temp.to_x) if $DEBUG
                if(i % @key_words == 0) 
                    
                        t_byte=p_temp[0]
                        p_temp[0 .. 2]=p_temp[1 .. 3]
                        p_temp[3]=t_byte
                    p sprintf("%.8x (RotWord)", p_temp.to_x) if $DEBUG
        
                    # tr would be great here again.
                    p_temp=Crypt::ByteStream.new(Core.sbox_block(p_temp))
                    p sprintf("%.8x (SubWord)", p_temp.to_x) if $DEBUG
                    p sprintf("%.8x (Rcon[i/Nk])", p_round_constant[(i/@key_words).to_i].to_x) if $DEBUG
                    p_temp^=p_round_constant[(i/@key_words).to_i]
                    p sprintf("%.8x (After XOR)", p_temp.to_x) if $DEBUG
                  
                elsif(i % @key_words == 4) 
                    p_temp=Core.sbox_block(p_temp)
                    p sprintf("%.8x (SubWord)", p_temp.to_x) if $DEBUG
                end
                p sprintf("%.8x (w[i-Nk])", ek_words[i-@key_words].to_x) if $DEBUG
                ek_words[i]=ek_words[i-@key_words]^p_temp
                p sprintf("%.8x (w[i]=temp XOR w[i-Nk])", ek_words[i].to_x) if $DEBUG
            end
            expanded_key=Array(rounds+1)
            (0 .. rounds).each do
                |round|
                expanded_key[round]=Crypt::ByteStream.new(ek_words[round*@block_words, @block_words].to_s)
            end
            return expanded_key;
        end

        def expand_key #:nodoc:
            return @expanded_key if(@expanded_key)
            @expanded_key=(@key_words>6)?expand_key_gt6:
                expand_key_le6
            return @expanded_key
        end

protected :round_count, :round_constants, :expand_key_le6, :expand_key_gt6, :expand_key
        
=begin rdoc
Your main entry point. You must provide an input string of a valid length - if not, it'll +raise+.
Valid lengths are 16, 24 or 32 bytes, and it will pick the block size based on the length of the input.

The output is a Crypt::ByteStream object, which is to say more-or-less a String.
=end
        def encrypt(plaintext)
						self.block = plaintext

            rounds=round_count
            expanded_key=expand_key()
            
            blockl_b=@block_words*4
            #puts "m #{block.length}"
            self.block=Core.round0(block, expanded_key[0])
            (1 .. rounds-1).each do 
                |current_round|
                puts "n #{current_round}" if $DEBUG
                p expanded_key[current_round] if $DEBUG
                self.block=Core.roundn(block, expanded_key[current_round])
            end
            return Core.roundl(block, expanded_key[rounds])
        end
        
=begin rdoc
Your other main entry point. You must provide an input string of a valid length - if not, it'll +raise+.
Valid lengths are 16, 24 or 32 bytes, and it will pick the block size based on the length of the input.
Of course, if the string to decrypt is of invalid length then you've got other problems...

The output is a Crypt::ByteStream object, which is to say more-or-less a String.
=end
        def decrypt(ciphertext)
						self.block = ciphertext
            rounds=round_count
            expanded_key=expand_key()
            
            blockl_b=@block_words*4
            self.block=Core.inv_roundl(block, expanded_key[rounds])
            (1 .. rounds-1).to_a.reverse.each do 
                |current_round|
                #puts "n #{current_round}"
                self.block=Core.inv_roundn(block, expanded_key[current_round])
            end
            decrypted=Core.round0(block, expanded_key[0])
            #p "decrypted: #{decrypted}" if $VERBOSE
            return decrypted
        end
    end

=begin rdoc
This is exactly the same as Crypt::Rijndael except that the only allowed block size is 128-bit (16 bytes
), which affects possible IV (for CBC and other block-chaining algorithms) and plaintext block lengths.

Given the effort that went into standardising on AES, you may well want to use this instead of 
Crypt::Rijndael for encryption if you're interoperating with another party. Of course, you *can* safely
use Crypt::Rijndael for decryption in that circumstance.

The spec for this is in an US government standards document named FIPS-197. Google for it.
=end
    class AES < Rijndael
        AES_BLOCKSIZE_BYTES=16

				# Only one block size is supported for real AES: 16 bytes.
				def self.block_sizes_supported
					[AES_BLOCKSIZE_BYTES]
				end
    end
end
