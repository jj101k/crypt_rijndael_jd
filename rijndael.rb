require "bytestream"
require "crypt/rijndael/core"

class Crypt
    class Rijndael

=begin rdoc
Crypt::Rijndael allows you to encrypt single blocks of data using the encrypt() and decrypt() methods
below. For convenience, there are also simple CBC encryption wrappers here, although they don't really
belong in this class.
=end
    
        DEFAULT_KEYSIZE_BYTES=16
        DEFAULT_BLOCKSIZE_BYTES=16
        
        @@valid_blocksizes_bytes=[16, 24, 32]
        @@valid_keysizes_bytes=[16, 24, 32]

=begin rdoc
The new() function here takes only one argument: the key to use, as a String (or similar). Valid lengths
are 16, 24 or 32 bytes, and you should ensure that this value is sufficiently random. Most people will
choose 16-byte (128-bit) keys, but a longer key will take longer to crack if security is of unusually
high importance for you.
=end
        def initialize(key)
            raise "Invalid key length" unless(@@valid_keysizes_bytes.find {|size| size==key.length})
            @key=key
            @key_words=@key.length/4
            @block_words=DEFAULT_BLOCKSIZE_BYTES/4
        end
        
        def blocksize=(isize) #:nodoc:
            if(@@valid_blocksizes_bytes.find { |size| size==isize })
                @block_words=isize/4
                @expanded_key=nil
                return self
            else
                raise "Invalid block size selected: #{isize}"
            end
        end
        
        def keysize #:nodoc:
            return @key.length
        end
        
        def blocksize #:nodoc:
            return @block_words*4
        end
        
        
        def Rijndael.pad_pkcs5(string, to_length) #:nodoc:
            diff= to_length - (string.length % to_length)
            string+=[diff].pack("C") * diff
            return string
        end
        
        def Rijndael.unpad_pkcs5(string) #:nodoc:
            return unless string.length > 0
            
            pad_len=string[-1]
            string.slice!(-pad_len .. -1)
            return string
        end
        
        @@shift_for_block_len={
          4=>[0,1,2,3],
          6=>[0,1,2,3],
          8=>[0,1,3,4],
        };
              

        def Rijndael.make_shiftrow_map  #:nodoc:
            @@inv_shiftrow_map=(0 .. 0xff).map {Array.new}
            @@shiftrow_map=(0 .. 0xff).map {Array.new}  
            @@shift_for_block_len.keys.each do
                |block_len|
                row_len=block_len;
                state_b=(0 .. (row_len*4)-1).to_a;
                col_len=4;
                c=@@shift_for_block_len[block_len];
                (0 .. c.length-1).each do
                    |row_n| 
                    # Grab the lossage first
                    next unless c[row_n] > 0;
                    d1=Array.new
                    d2=Array.new
                    (row_len-c[row_n] .. row_len-1).map {|col| row_n+col_len*col}.each do
                        |offset|
                        d1+=state_b[offset,1]
                    end 
                    (0 .. row_len-c[row_n]-1).map {|col| row_n+col_len*col}.each do
                        |offset|
                        d2+=state_b[offset,1]
                    end  
                    
            	(0 .. row_len-1).map {|col| row_n+col_len*col}.each do
                        |offset|
                        state_b[offset]=d1.shift||d2.shift
                    end
                end
                @@inv_shiftrow_map[block_len]=state_b;
                (0 .. state_b.length-1).each do
                    |offset|
                    @@shiftrow_map[block_len][state_b[offset]]=offset;
                end
            end
        end
        
        make_shiftrow_map
        
        def shift_rows(state_b) #:nodoc:
          row_len=state_b.length/4
          
		  state_o=@@shiftrow_map[row_len].map do
				|offset|
				state_b[offset]
		  end
		  return state_o.pack("C*")
        end
        
        def inv_shift_rows(state_b) #:nodoc:
          col_len=4;
          row_len=state_b.length/4;
          
            state_o=@@inv_shiftrow_map[row_len].map do
                |offset|
                state_b[offset]
            end
            return state_o.pack("C*")
        end
        
        def round0(input, round_key) #:nodoc:
            return round_key^input;
        end
        
        def roundn(input, round_key) #:nodoc:
            row_len=@block_words;
        
            input=Core.sbox_block(input)
            input=shift_rows(input)       
            # Tune this - jim
            input=Core.mix_column(input)
            
            return round_key^input;
        end
        
        def inv_roundn(input, round_key) #:nodoc:
            
            input=round_key^input
            row_len=@block_words
            input=Core.inv_mix_column(input)

            
            input=inv_shift_rows(input)
            # convert to use tr for the s-box ?
            input=Core.inv_sbox_block(input)
            
            return input
        end
        
        def roundl(input, round_key) #:nodoc:
            # convert to use tr for the s-box

            input=Core.sbox_block(input)
            input=shift_rows(input)
            return round_key^input;
        end
        
        def inv_roundl(input, round_key) #:nodoc:
            # convert to use tr for the s-box
            input=round_key^input
            input=Core.inv_sbox_block(input)
            input=inv_shift_rows(input)
            #input=bytes_n.pack("C*")  
            return input
        end

        ROUNDS_BY_BLOCK_SIZE={
            4=>10,
            6=>12,
            8=>14
        }
        
        def _round_count #:nodoc:
            biggest_words=if(@block_words > @key_words)
                @block_words
            else
                @key_words
            end
            return ROUNDS_BY_BLOCK_SIZE[biggest_words]
        end
        
        def expand_key_le6 #:nodoc
					# For short (128-bit, 192-bit) keys this is used to expand the key to blocklen*(rounds+1) bits
            p "Expanding key" if $DEBUG
            
            #expanded_key=@key;
            ek_words=@key.unpack("N*").map {|number| ByteStream.new([number].pack("N"))}
        
            rounds=_round_count();
        
        # cache this FIXME
        
            temp_v=1;
            p_round_constant=Array.new
            p_round_constant=[0,1].map {|i| [i, 0, 0, 0].pack("C*")}
            
            p_round_constant+=
            (2 .. (@block_words * (rounds + 1)/@key_words).to_i).to_a.map {
                [(temp_v=Core.dot(02,temp_v)),0,0,0].pack("C*")
            }
            
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
                    p_temp=ByteStream.new(Core.sbox_block(p_temp))
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
                expanded_key[round]=ByteStream.new(ek_words[round*@block_words, @block_words].to_s)
            end
            return expanded_key; 
        end
                
        def expand_key_gt6 #:nodoc:
					# For long (256-bit) keys this is used to expand the key to blocklen*(rounds+1) bits
            p "Expanding key (large)" if $DEBUG
            
            #expanded_key=@key
            ek_words=@key.unpack("N*").map {|number| ByteStream.new([number].pack("N"))}
        
            rounds=_round_count();
        
        # cache this FIXME
        
            temp_v=1
            p_round_constant=[0,1].map {|i| [i, 0,0,0].pack("C*")}
            p_round_constant+=(2 .. (@block_words * (rounds + 1)/@key_words).to_i).to_a.map { 
                #0x1000000<<($_-1)
                [temp_v=Core.dot(02,temp_v) ,0,0,0].pack("C*")
            }

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
                    p_temp=ByteStream.new(Core.sbox_block(p_temp))
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
                expanded_key[round]=ByteStream.new(ek_words[round*@block_words, @block_words].to_s)
            end
            return expanded_key;
        end

        def expand_key #:nodoc:
            return @expanded_key if(defined? @expanded_key and @expanded_key)
            @expanded_key=(@key_words>6)?expand_key_gt6:
                expand_key_le6
            return @expanded_key
        end
        
=begin rdoc
Your main entry point. You must provide an input string of a valid length - if not, it'll +raise+.
Valid lengths are 16, 24 or 32 bytes, and it will pick the block size based on the length of the input.

The output is a ByteStream object, which is to say more-or-less a String.
=end
        def encrypt(plaintext)
						if(plaintext.length!=@block_words*4)
							raise "Not a valid block size: #{plaintext.length}" unless self.blocksize=plaintext.length
						end
            rounds=_round_count()
            expanded_key=expand_key()
            state=plaintext
            
            blockl_b=@block_words*4
            #puts "m #{state.length}"
            state=round0(state, expanded_key[0])
            (1 .. rounds-1).each do 
                |current_round|
                #puts "n #{current_round}"
                #p expanded_key[current_round]
                state=roundn(state, expanded_key[current_round])
            end
            return roundl(state, expanded_key[rounds])
        end
        
=begin rdoc
Your other main entry point. You must provide an input string of a valid length - if not, it'll +raise+.
Valid lengths are 16, 24 or 32 bytes, and it will pick the block size based on the length of the input.
Of course, if the string to decrypt is of invalid length then you've got other problems...

The output is a ByteStream object, which is to say more-or-less a String.
=end
        def decrypt(ciphertext)
						if(ciphertext.length!=@block_words*4)
							raise "Not a valid block size: #{ciphertext.length}" unless self.blocksize=ciphertext.length
						end
            rounds=_round_count()
            expanded_key=expand_key()
            state=ciphertext
            
            blockl_b=@block_words*4
            state=inv_roundl(state, expanded_key[rounds])
            (1 .. rounds-1).to_a.reverse.each do 
                |current_round|
                #puts "n #{current_round}"
                state=inv_roundn(state, expanded_key[current_round])
            end
            decrypted=round0(state, expanded_key[0])
            #p "decrypted: #{decrypted}" if $VERBOSE
            return decrypted
        end
        
=begin rdoc
The first of the shouldn't-be-here functions, which will probably disappear once a well-working 
Crypt::CBC class is made. Like the key in new(), +iv+ has to be of a specific size, but please note
(see Crypt::AES) that it has to be a valid _block_ size (16, 24 or 32 bytes in this case).

Like encrypt(), the block size will be set for you, and the plaintext can be of any length at all.

IV generation is a less critical issue than key generation, it being of much greater importance that it
be unique than that it be unpredictable.
=end
        def encrypt_CBC(iv, plaintext)
            raise "Invalid block size: #{iv.length}" unless self.blocksize=iv.length
                    
            last_block_e=ByteStream.new(iv);
            
            blockl_b=@block_words*4;
            
            r_data="";
            plaintext=Rijndael.pad_pkcs5(plaintext, blockl_b);
            
            pt_l=plaintext.length;
            #p pt_l/blockl_b
            (0 .. (pt_l/blockl_b)-1).each do
                |i|
                current_block=plaintext[
                    i*blockl_b .. (blockl_b*(i+1))-1
                ];
                #warn "Working on \"$current_block\"";
                to_encrypt=last_block_e^current_block;
                last_block_e=encrypt(to_encrypt);
                r_data+=last_block_e;
            end
            return r_data;
        end
        
=begin rdoc
The second of the shouldn't-be-here functions, which will probably disappear once a well-working 
Crypt::CBC class is made.

Like decrypt(), the block size will be set for you. The ciphertext and iv will have come from a previous
encryption; a plaintext value (of the correct length) will be returned.

Note that the nature of the padding provides a high (over 87%) chance that a failed decryption
(due to the wrong key or IV) could, theoretically, be detected, but no such detection is performed here
currently.
=end
        def decrypt_CBC(iv, ciphertext)
						# TODO: Failure detection.
            raise "Invalid block size: #{iv.length}" unless self.blocksize=iv.length
        
            last_block_e=ByteStream.new(iv);
            
            blockl_b=@block_words*4;
        
            return unless ciphertext.length % blockl_b==0;
            
            ct_l=ciphertext.length;
            
            r_data="";
            (0 .. (ct_l/blockl_b)-1).each do
                |i|
                current_block=ciphertext[i*blockl_b .. (blockl_b*(i+1))-1]

                pt_block=decrypt(current_block)
                decrypted=last_block_e^pt_block
                last_block_e=ByteStream.new(current_block)
                r_data+=decrypted
            end
            # We assume PKCS5 padding.
            r_data=Rijndael.unpad_pkcs5(r_data)
            return r_data;
        end
    
    
    end

    class AES < Rijndael
=begin rdoc
This is exactly the same as Crypt::Rijndael except that the only allowed block size is 128-bit (16 bytes
), which affects possible IV (for CBC and other block-chaining algorithms) and plaintext block lengths.

Given the effort that went into standardising on AES, you may well want to use this instead of 
Crypt::Rijndael for encryption if you're interoperating with another party. Of course, you *can* safely
use Crypt::Rijndael for decryption in that circumstance.

The spec for this is in an US government standards document named FIPS-197. Google for it.
=end
        AES_BLOCKSIZE_BYTES=16

        def blocksize=(isize) #:nodoc:
            if(AES_BLOCKSIZE_BYTES==isize)
                # Nothing to do
                return self
            else
               raise "Invalid block size '#{isize}': only #{AES_BLOCKSIZE_BYTES} is valid" 
            end
        end
    end
end
