class Crypt
    class Rijndael
					class Core

						def self.make_shiftrow_map  #:nodoc:
							shift_for_block_len={
								4=>[0,1,2,3],
								6=>[0,1,2,3],
								8=>[0,1,3,4],
							}
								@@inv_shiftrow_map=(0 .. 0xff).map {Array.new}
								@@shiftrow_map=(0 .. 0xff).map {Array.new}  
								shift_for_block_len.keys.each do
										|block_len|
										row_len=block_len;
										state_b=(0 .. (row_len*4)-1).to_a;
										col_len=4;
										c=shift_for_block_len[block_len];
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

						def self.shift_rows(state_b) #:nodoc:
							row_len=state_b.length/4
							
							state_o=@@shiftrow_map[row_len].map do
								|offset|
								state_b[offset]
							end
							return state_o.pack("C*")
						end
						
						def self.inv_shift_rows(state_b) #:nodoc:
							col_len=4;
							row_len=state_b.length/4;
							
								state_o=@@inv_shiftrow_map[row_len].map do
										|offset|
										state_b[offset]
								end
								return state_o.pack("C*")
						end
						

            POLYNOMIAL_SPACE=0x11b
						COLUMN_SIZE=4

            def Core.sbox_block(input)
                return input.unpack("C*").map do
                    |byte| 
                    @@sbox[byte]
                end.pack("C*")
            end
    
            def Core.inv_sbox_block(input)
                return input.unpack("C*").map do
                    |byte| 
                    @@inv_sbox[byte]
                end.pack("C*")
            end
                    
            def Core.mix_column(col)
								block_words=col.length/COLUMN_SIZE
                r_col=Array.new
                (0 .. (block_words-1)).each {
                    |current_word|
                    r_col+=[
                    (@@dot_cache[02][col[(current_word*4)+0]] ^ 
                        @@dot_cache[03][col[(current_word*4)+1]] ^ 
                            col[(current_word*4)+2] ^ 
                                col[(current_word*4)+3] ),
                    ( col[(current_word*4)+0] ^ 
                        @@dot_cache[02][col[(current_word*4)+1]] ^ 
                            @@dot_cache[03][col[(current_word*4)+2]] ^ 
                                col[(current_word*4)+3] ),
                    ( col[(current_word*4)+0] ^ 
                        col[(current_word*4)+1] ^ 
                            @@dot_cache[02][col[(current_word*4)+2]] ^ 
                                @@dot_cache[03][col[(current_word*4)+3]]),
                    (@@dot_cache[03][col[(current_word*4)+0]] ^ 
                        col[(current_word*4)+1] ^ 
                            col[(current_word*4)+2] ^ 
                                @@dot_cache[02][col[(current_word*4)+3]])]
                }
                return r_col.pack("C*")
            end
            
            # The inverse of the above
            
            def Core.inv_mix_column(col)
								block_words=col.length/COLUMN_SIZE
                r_col=Array.new
                (0 .. (block_words-1)).each { |current_block|
                    r_col+=[
                    (@@dot_cache[0x0e][col[(current_block*4)+0]] ^ 
                        @@dot_cache[0x0b][col[(current_block*4)+1]] ^ 
                            @@dot_cache[0x0d][col[(current_block*4)+2]] ^ 
                                @@dot_cache[0x09][col[(current_block*4)+3]]),
                    (@@dot_cache[0x09][col[(current_block*4)+0]] ^ 
                        @@dot_cache[0x0e][col[(current_block*4)+1]] ^ 
                            @@dot_cache[0x0b][col[(current_block*4)+2]] ^ 
                                @@dot_cache[0x0d][col[(current_block*4)+3]]),
                    (@@dot_cache[0x0d][col[(current_block*4)+0]] ^ 
                        @@dot_cache[0x09][col[(current_block*4)+1]] ^ 
                            @@dot_cache[0x0e][col[(current_block*4)+2]] ^ 
                                @@dot_cache[0x0b][col[(current_block*4)+3]]),
                    (@@dot_cache[0x0b][col[(current_block*4)+0]] ^ 
                        @@dot_cache[0x0d][col[(current_block*4)+1]] ^ 
                            @@dot_cache[0x09][col[(current_block*4)+2]] ^ 
                                @@dot_cache[0x0e][col[(current_block*4)+3]])
                ]}     
                return r_col.pack("C*")
            end
                
            def Core.xtime(a)
                a*=2
                if( a & 0x100 > 0 )
                    a^=0x1b
                end
                a&=0xff
                return a
            end            
            
            def Core.dot(a, b)
                return 0 unless(a > 0 and b > 0)
                
                result=0
                tv=a
                (0 .. 7).each do
                    |i|
                    if(b & (1<<i) > 0)
                        result^=tv
                    end
                    tv=xtime(tv)
                end
                return result
            end
            

            # _Not_ the same as dot()
            # Multiplies a by b. In polynomial space. Without capping the value.
            def Core.mul(a, b)
                result=0
                tv=a
                (0 .. 7).each do
                    |i|
                    if(b & (1<<i) > 0)
                        result^=tv
                    end
                    tv<<=1
                end
                return result
            end
            
            # The inverse of mul() above.
            
            def Core.div(a, b)
                acc=a
                tv=b
                result=0
                (0 .. 7).to_a.reverse.each do
                    | i |
                    tv=b<<i
    
                    if( (tv&~acc) < acc  or (acc^tv) <= (1<<i))
                        result|=(1<<i)
                        acc^=tv
                    end
                end
                return result
            end

            # 8-bit number in, 8-bit number out
            def Core.mult_inverse(num)
                return 0 unless num > 0
                remainder=[POLYNOMIAL_SPACE, num]
                auxiliary=[0,1]
            
                if(remainder[1]==1)
                   return 1
                end
                i=2
                while remainder[i-1]!=1
                    quotient=div(remainder[i-2], remainder[i-1])
                    multiplied=mul(remainder[i-1], quotient)
                    
                    remainder[i]=remainder[i-2]^multiplied
                    auxiliary[i]=mul(quotient,auxiliary[i-1]) ^ auxiliary[i-2]
                    if (i>10)
                        raise "BUG: Multiplicative inverse should never exceed 10 iterations"
                    end
                    i+=1
                end
                return auxiliary[i-1]
            end

            def Core.sbox(b)
                c=0x63
                b=mult_inverse(b)
                result=b
                (1 .. 4).each do
                    |i|
                    b_t=((b<<i)&0xff)|(b>>(8-i))
                    result^=b_t
                end
                return result^c
            end

            # Startup caching follows
            
            unless(defined? @@all_cached)
                @@sbox=(0 .. 255).to_a.map { |input| sbox(input)}
                @@inv_sbox=Array.new(256)
                (0 .. 255).each do
                    |input| 
                    @@inv_sbox[@@sbox[input]]=input
                end
                @@dot_cache=(0 .. 0xf).map {Array.new(256)}
                [0x2, 0x3, 0x9, 0xb, 0xd, 0xe].each do 
                    # These are the only numbers we need.
                    |a|
                    (0 .. 0xff).each do
                        |b|
                        @@dot_cache[a][b]=dot(a, b)
                    end
                end
								@@all_cached=1
            end

        end
        
    end
end
