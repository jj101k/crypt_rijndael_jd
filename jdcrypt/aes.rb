# This is to help testing
unless (defined? JdCrypt::Rijndael)
  require "jdcrypt/rijndael"
end

class JdCrypt
=begin rdoc
This is exactly the same as JdCrypt::Rijndael except that the only allowed block size is 128-bit (16 bytes
), which affects possible IV (for CBC and other block-chaining algorithms) and plaintext block lengths.

Given the effort that went into standardising on AES, you may well want to use this instead of
JdCrypt::Rijndael for encryption if you're interoperating with another party. Of course, you *can* safely
use JdCrypt::Rijndael for decryption in that circumstance.

The spec for this is in an US government standards document named FIPS-197. Google for it.
=end
  class AES < Rijndael
    AES_BLOCKSIZE_BYTES = 16

    # Only one block size is supported for real AES: 16 bytes.
    def self.block_sizes_supported
      [AES_BLOCKSIZE_BYTES]
    end
  end
end
