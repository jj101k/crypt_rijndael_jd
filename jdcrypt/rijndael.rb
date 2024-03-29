# frozen_string_literal: true

require "jdcrypt/bytestream"

# This is to help testing
require "jdcrypt/rijndael/core" unless defined? JdCrypt::Rijndael::Core

class JdCrypt
  # JdCrypt::Rijndael allows you to encrypt single blocks of data using the encrypt() and decrypt() methods
  # below.
  #
  # You probably want to use some kind of CBC module with this.
  class Rijndael
    BlocksizesBytes = [16, 24, 32].freeze
    KeysizesBytes = [16, 24, 32].freeze
    WordLength = 4

    @@valid_blocksizes_bytes = BlocksizesBytes
    @@valid_keysizes_bytes = KeysizesBytes

    # Provides a list of block sizes (bytes) which are supported
    def self.block_sizes_supported
      @@valid_blocksizes_bytes
    end

    # Provides a list of key sizes (bytes) which are supported
    def self.key_sizes_supported
      @@valid_keysizes_bytes
    end

    attr_reader :key, :block, :blocksize

    # The new() function here takes only one argument: the key to use, as a String (or similar). Valid lengths
    # are 16, 24 or 32 bytes, and you should ensure that this value is sufficiently random. Most people will
    # choose 16-byte (128-bit) keys, but a longer key will take longer to crack if security is of unusually
    # high importance for you.
    def initialize(new_key)
      self.key = new_key
      @blocksize = nil # This makes it easier to adjust in #block=
    end

    def block=(new_block) # :nodoc:
      if new_block.length != @blocksize
        unless block_sizes_supported.any? { |size| size == new_block.length }
          raise "Invalid block size: #{new_block.length}"
        end

        @blocksize = new_block.length
        @block_words = @blocksize / WordLength
        @expanded_key = nil
        @round_count = nil
      end
      @block = new_block
    end

    # If you want to probe for supported block sizes, by all means use this method. It'll raise
    # if the value isn't supported.
    #
    # Don't use this: #block_sizes_supported is better.
    def blocksize=(block_size_bytes)
      self.block = "\x00" * block_size_bytes
    end

    # This just calls the class' .block_sizes_supported method for you.
    def block_sizes_supported
      self.class.block_sizes_supported
    end

    # Your other main entry point. You must provide an input string of a valid length - if not, it'll +raise+.
    # Valid lengths are 16, 24 or 32 bytes, and it will pick the block size based on the length of the input.
    # Of course, if the string to decrypt is of invalid length then you've got other problems...
    #
    # The output is a JdCrypt::ByteStream object, which is to say more-or-less a String.
    def decrypt(ciphertext)
      self.block = ciphertext
      rounds = round_count
      expanded_key = expand_key

      pre_roundn = Core.inv_roundl(block, expanded_key[rounds])
      pre_round0 = Core.roundn_times(pre_roundn, expanded_key, rounds, :reverse)
      Core.round0(pre_round0, expanded_key[0])
    end

    # Your main entry point. You must provide an input string of a valid length - if not, it'll +raise+.
    # Valid lengths are 16, 24 or 32 bytes, and it will pick the block size based on the length of the input.
    #
    # The output is a JdCrypt::ByteStream object, which is to say more-or-less a String.
    def encrypt(plaintext)
      self.block = plaintext

      rounds = round_count
      expanded_key = expand_key

      pre_roundn = Core.round0(block, expanded_key[0])
      pre_roundl = Core.roundn_times(pre_roundn, expanded_key, rounds, :forward)
      Core.roundl(pre_roundl, expanded_key[rounds])
    end

    def expand_key # :nodoc:
      return @expanded_key if @expanded_key

      @expanded_key =
        if @key_words > 6
          Core.expand_key_gt6(key, @block_words)
        else
          Core.expand_key_le6(key, @block_words)
        end

      @expanded_key
    end

    # If you want to, you can assign a new key to an existing object.
    def key=(new_key)
      unless self.class.key_sizes_supported.any? { |size| size == new_key.length }
        raise "Invalid key length: #{new_key.length}"
      end

      @key = new_key
      @key_words = @key.length / 4
      @expanded_key = nil
      @round_count = nil
    end

    def round_count # :nodoc:
      return @round_count if @round_count

      @round_count = Core.round_count(@block_words, @key_words)
    end

    protected :block, :block=, :expand_key, :key, :round_count
  end
end
