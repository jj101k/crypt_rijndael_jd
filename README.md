# JdCrypt::Rijndael & JdCrypt::AES

**Important Advice**: you should probably use the OpenSSL extension instead.

This is a from-scratch implementation of the Rijndael (AES) encryption cipher as a C
Ruby extension (as well as a pure-Ruby counterpart).

## Usage

This package requires Ruby 2.6 or above.

```ruby
require 'jdcrypt/rijndael'
key = "xxxxxxxxxxxxxxxx"
cipher = JdCrypt::Rijndael.new(key)

# For a single block

plaintext = "hello world....."
ciphertext = cipher.encrypt(plaintext)
plaintext = cipher.decrypt(ciphertext)

# For a stream, using CBC (not provided here)

require "jdcrypt/cbc"
cbc = JdCrypt::CBC.new(cipher)

long_ciphertext = cbc.encrypt(iv, long_plaintext)
```

Some things to note, though:

- This is a block encryption cipher, only encrypting to blocks of
  particular sizes. If you try to put text in that is not of the
  correct block size, it will refuse it.

- Key generation is outside the scope of this module - please be
  sure to generate suitably random keys from a reliable random
  source.  Encrypting to a predictable key makes no sense.

- JdCrypt::AES is a subclass of JdCrypt::Rijndael, the only difference
  being that it only supports only one block size(128 bit). It still supports
  all the same key sizes (128, 192, 256).

# NOTES

## Installing

If you "build" the pure-ruby core, it'll always be what the test
script uses.

You can uninstall if you need to, via `sudo ruby uninstall.rb`

## COMPATIBILITY AND PERFORMANCE

Ruby 2.6: works on universal.arm64e-darwin22 (note: the binary should also work
on other architectures). On the test machine, it can encrypt/decrypt at around
6-8MiB/s. When using the pure-ruby core (using the _binary_ JdCrypt::ByteStream) it
gets around 200KiB/s.

# COPYRIGHT

This files in this distribution (with the exception of bwulf10.txt)
are copyright 2005-2023 Jim Driscoll <jim.a.driscoll@gmail.com>; please see
the included file COPYING for details.
