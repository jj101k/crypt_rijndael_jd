# frozen_string_literal: true

class JdCrypt
  class Rijndael
    # This class is used by JdCrypt::Rijndael to handle most of the encryption work,
    # if you don't have the binary core installed.
    class Core
      COLUMN_SIZE = 4

      POLYNOMIAL_SPACE = 0x11b

      @@rounds_by_block_size = {
        4 => 10,
        6 => 12,
        8 => 14,
      }

      # The inverse of mul()
      def self.div(a, b)
        acc = a
        tv = b
        result = 0
        7.downto(0) do |i|
          tv = b << i

          if (tv & ~acc) < acc || (acc ^ tv) <= (1 << i)
            result |= (1 << i)
            acc ^= tv
          end
        end
        result
      end

      def self.dot(a, b)
        return 0 unless a.positive? && b.positive?

        result = 0
        tv = a
        0.upto(7) do |i|
          result ^= tv if (b & (1 << i)).positive?
          tv = xtime(tv)
        end
        result
      end

      def self.expand_key_gt6(key, block_words) # :nodoc:
        # For long (256-bit) keys this is used to expand the key to blocklen*(rounds+1) bits

        ek_words = key.unpack("N*").map { |number| JdCrypt::ByteStream.new([number].pack("N")) }

        key_words = key.length / 4
        p_round_constant = round_constants(block_words, key_words)

        rounds = round_count(block_words, key_words)

        key_words.upto(block_words * (rounds + 1) - 1) do |i|
          p_temp = ek_words[i - 1]
          if (i % key_words).zero?
            p_temp = JdCrypt::ByteStream.new(p_temp)
            t_byte = p_temp.byte_at(0)
            p_temp[0..2] = p_temp[1..3]
            p_temp.byte_at(3, t_byte)

            # tr would be great here again.
            p_temp = JdCrypt::ByteStream.new(sbox_block(p_temp))
            p_temp ^= p_round_constant[(i / key_words).to_i]
          elsif i % key_words == 4
            p_temp = sbox_block(p_temp)
          end
          ek_words[i] = ek_words[i - key_words] ^ p_temp
        end
        expanded_key = Array(rounds + 1)
        0.upto(rounds) do |round|
          expanded_key[round] = JdCrypt::ByteStream.new(ek_words[round * block_words, block_words].join(""))
        end
        expanded_key
      end

      def self.expand_key_le6(key, block_words) # :nodoc:
        # For short (128-bit, 192-bit) keys this is used to expand the key to blocklen*(rounds+1) bits

        ek_words = key.unpack("N*").map { |number| JdCrypt::ByteStream.new([number].pack("N")) }

        key_words = key.length / 4
        p_round_constant = round_constants(block_words, key_words)

        rounds = round_count(block_words, key_words)

        key_words.upto(block_words * (rounds + 1) - 1) do |i|
          p_temp = ek_words[i - 1]

          if (i % key_words).zero?
            p_temp = JdCrypt::ByteStream.new(p_temp)
            t_byte = p_temp.byte_at(0)
            p_temp[0..2] = p_temp[1..3]
            p_temp.byte_at(3, t_byte)

            # tr would be great here again.
            p_temp = JdCrypt::ByteStream.new(sbox_block(p_temp))
            p_temp ^= p_round_constant[(i / key_words).to_i]
          end
          ek_words[i] = p_temp ^ ek_words[i - key_words]
        end
        expanded_key = Array(rounds + 1)
        0.upto(rounds) do |round|
          expanded_key[round] = JdCrypt::ByteStream.new(ek_words[round * block_words, block_words].join(""))
        end
        expanded_key
      end

      # The inverse of mix_column
      def self.inv_mix_column(col)
        block_words = col.length / COLUMN_SIZE
        r_col = []
        0.upto(block_words - 1) do |current_block|
          r_col += [
            (@@dot_cache[0x0e][col.byte_at((current_block * 4) + 0)] ^
             @@dot_cache[0x0b][col.byte_at((current_block * 4) + 1)] ^
             @@dot_cache[0x0d][col.byte_at((current_block * 4) + 2)] ^
             @@dot_cache[0x09][col.byte_at((current_block * 4) + 3)]),
            (@@dot_cache[0x09][col.byte_at((current_block * 4) + 0)] ^
             @@dot_cache[0x0e][col.byte_at((current_block * 4) + 1)] ^
             @@dot_cache[0x0b][col.byte_at((current_block * 4) + 2)] ^
             @@dot_cache[0x0d][col.byte_at((current_block * 4) + 3)]),
            (@@dot_cache[0x0d][col.byte_at((current_block * 4) + 0)] ^
             @@dot_cache[0x09][col.byte_at((current_block * 4) + 1)] ^
             @@dot_cache[0x0e][col.byte_at((current_block * 4) + 2)] ^
             @@dot_cache[0x0b][col.byte_at((current_block * 4) + 3)]),
            (@@dot_cache[0x0b][col.byte_at((current_block * 4) + 0)] ^
             @@dot_cache[0x0d][col.byte_at((current_block * 4) + 1)] ^
             @@dot_cache[0x09][col.byte_at((current_block * 4) + 2)] ^
             @@dot_cache[0x0e][col.byte_at((current_block * 4) + 3)]),
          ]
        end
        JdCrypt::ByteStream.new(r_col.pack("C*"))
      end

      def self.inv_roundl(input, round_key) # :nodoc:
        # convert to use tr for the s-box
        pre_invsbox = round0(input, round_key)
        pre_shiftrows = inv_sbox_block(pre_invsbox)
        inv_shift_rows(pre_shiftrows)
      end

      def self.inv_roundn(input, round_key) # :nodoc:
        pre_invmixcolumn = round0(input, round_key)
        pre_invshiftrows = inv_mix_column(pre_invmixcolumn)
        pre_sbox = inv_shift_rows(pre_invshiftrows)
        # convert to use tr for the s-box ?
        inv_sbox_block(pre_sbox)
      end

      def self.inv_sbox_block(input)
        JdCrypt::ByteStream.new(input.unpack("C*").map do |byte|
          @@inv_sbox[byte]
        end.pack("C*"))
      end

      def self.inv_shift_rows(state_b) # :nodoc:
        row_len = state_b.length / 4

        state_o = @@inv_shiftrow_map[row_len].map do |offset|
          state_b.byte_at(offset)
        end
        JdCrypt::ByteStream.new(state_o.pack("C*"))
      end

      def self.make_shiftrow_map # :nodoc:
        shift_for_block_len = {
          4 => [0, 1, 2, 3],
          6 => [0, 1, 2, 3],
          8 => [0, 1, 3, 4],
        }
        @@inv_shiftrow_map = (0..0xff).map { [] }
        @@shiftrow_map = (0..0xff).map { [] }
        shift_for_block_len.each_key do |block_len|
          row_len = block_len
          state_b = (0..(row_len * 4) - 1).to_a
          col_len = 4
          c = shift_for_block_len[block_len]
          0.upto(c.length - 1) do |row_n|
            # Grab the lossage first
            next unless c[row_n].positive?

            d1 = []
            d2 = []
            (row_len - c[row_n]).upto(row_len - 1) do |col|
              offset = row_n + col_len * col
              d1 += state_b[offset, 1]
            end
            0.upto(row_len - c[row_n] - 1) do |col|
              offset = row_n + col_len * col
              d2 += state_b[offset, 1]
            end

            0.upto(row_len - 1) do |col|
              offset = row_n + col_len * col
              state_b[offset] = d1.shift || d2.shift
            end
          end
          @@inv_shiftrow_map[block_len] = state_b
          0.upto(state_b.length - 1) do |offset|
            @@shiftrow_map[block_len][state_b[offset]] = offset
          end
        end
      end

      def self.mix_column(col)
        block_words = col.length / COLUMN_SIZE
        r_col = []
        0.upto(block_words - 1) do |current_word|
          r_col += [
            (@@dot_cache[02][col.byte_at((current_word * 4) + 0)] ^
             @@dot_cache[03][col.byte_at((current_word * 4) + 1)] ^
             col.byte_at((current_word * 4) + 2) ^
             col.byte_at((current_word * 4) + 3)),
            (col.byte_at((current_word * 4) + 0) ^
             @@dot_cache[02][col.byte_at((current_word * 4) + 1)] ^
             @@dot_cache[03][col.byte_at((current_word * 4) + 2)] ^
             col.byte_at((current_word * 4) + 3)),
            (col.byte_at((current_word * 4) + 0) ^
             col.byte_at((current_word * 4) + 1) ^
             @@dot_cache[02][col.byte_at((current_word * 4) + 2)] ^
             @@dot_cache[03][col.byte_at((current_word * 4) + 3)]),
            (@@dot_cache[03][col.byte_at((current_word * 4) + 0)] ^
             col.byte_at((current_word * 4) + 1) ^
             col.byte_at((current_word * 4) + 2) ^
             @@dot_cache[02][col.byte_at((current_word * 4) + 3)]),
          ]
        end
        JdCrypt::ByteStream.new(r_col.pack("C*"))
      end

      # _Not_ the same as dot()
      # Multiplies a by b. In polynomial space. Without capping the value.
      def self.mul(a, b)
        result = 0
        tv = a
        0.upto(7) do |i|
          result ^= tv if (b & (1 << i)).positive?
          tv <<= 1
        end
        result
      end

      # 8-bit number in, 8-bit number out
      def self.mult_inverse(num)
        return 0 unless num.positive?

        remainder = [POLYNOMIAL_SPACE, num]

        return 1 if remainder[1] == 1

        auxiliary = [0, 1]

        i = 2
        while remainder[i - 1] != 1
          quotient = div(remainder[i - 2], remainder[i - 1])
          multiplied = mul(remainder[i - 1], quotient)

          remainder[i] = remainder[i - 2] ^ multiplied
          auxiliary[i] = mul(quotient, auxiliary[i - 1]) ^ auxiliary[i - 2]

          raise "BUG: Multiplicative inverse should never exceed 10 iterations" if i > 10

          i += 1
        end
        auxiliary[i - 1]
      end

      def self.round0(input, round_key) # :nodoc:
        round_key ^ input
      end

      def self.round_constants(block_words, key_words) # :nodoc:
        @@round_constants ||= {}
        @@round_constants[block_words] ||= {}
        unless @@round_constants[block_words][key_words]
          temp_v = 1
          p_round_constant = [0, 1].map { |i| [i, 0, 0, 0].pack("C*") }

          round_count_needed = round_count(block_words, key_words)
          round_constants_needed = (block_words * (round_count_needed + 1) / key_words).to_i

          p_round_constant +=
            (2..round_constants_needed).to_a.map do
              [(temp_v = dot(02, temp_v)), 0, 0, 0].pack("C*")
            end
          @@round_constants[block_words][key_words] = p_round_constant
        end
        @@round_constants[block_words][key_words]
      end

      def self.round_count(block_words, key_words) # :nodoc:
        biggest_words =
          if block_words > key_words
            block_words
          else
            key_words
          end
        @@rounds_by_block_size[biggest_words]
      end

      def self.roundl(input, round_key) # :nodoc:
        # convert to use tr for the s-box
        pre_shiftrows = sbox_block(input)
        pre_round0 = shift_rows(pre_shiftrows)
        round0(pre_round0, round_key)
      end

      def self.roundn(input, round_key) # :nodoc:
        pre_shiftrows = sbox_block(input)
        pre_mixcolumn = shift_rows(pre_shiftrows)
        # Tune this - jim
        pre_round0 = mix_column(pre_mixcolumn)

        round0(pre_round0, round_key)
      end

      def self.roundn_times(block, expanded_key, rounds, direction) # :nodoc:
        case direction
        when :forward
          1.upto(rounds - 1) do |current_round|
            block = roundn(block, expanded_key[current_round])
          end
        when :reverse
          (rounds - 1).downto(1) do |current_round|
            block = inv_roundn(block, expanded_key[current_round])
          end
        else
          raise "Unsupported round direction"
        end
        block
      end

      def self.sbox(byte)
        c = 0x63
        bytei = mult_inverse(byte)
        result = bytei
        1.upto(4) do |i|
          b_t = ((bytei << i) & 0xff) | (bytei >> (8 - i))
          result ^= b_t
        end
        result ^ c
      end

      def self.sbox_block(input)
        JdCrypt::ByteStream.new(input.unpack("C*").map do |byte|
          @@sbox[byte]
        end.pack("C*"))
      end

      def self.shift_rows(state_b) # :nodoc:
        row_len = state_b.length / 4

        state_o = @@shiftrow_map[row_len].map do |offset|
          state_b.byte_at(offset)
        end
        JdCrypt::ByteStream.new(state_o.pack("C*"))
      end

      def self.xtime(a)
        a *= 2
        a ^= 0x1b if (a & 0x100).positive?
        a & 0xff
      end

      # Startup caching follows

      make_shiftrow_map

      unless defined? @@all_cached
        @@sbox = (0..255).to_a.map { |input| sbox(input) }
        @@inv_sbox = Array.new(256)
        0.upto(255) do |input|
          @@inv_sbox[@@sbox[input]] = input
        end
        @@dot_cache = (0..0xf).map { Array.new(256) }
        [0x2, 0x3, 0x9, 0xb, 0xd, 0xe].each do |a|
          # These are the only numbers we need.
          0.upto(0xff) do |b|
            @@dot_cache[a][b] = dot(a, b)
          end
        end
        @@all_cached = 1
      end

      private_class_method :dot, :inv_roundn, :inv_sbox_block, :roundn, :sbox_block
    end
  end
end
