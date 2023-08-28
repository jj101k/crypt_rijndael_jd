# frozen_string_literal: true

require "rbconfig"
include RbConfig
require "fileutils"
include FileUtils::Verbose

top_dir = "#{CONFIG["sitelibdir"]}/jdcrypt"

mkdir_p(top_dir)
install("jdcrypt/rijndael.rb", top_dir, mode: 0o644)
install("jdcrypt/aes.rb", top_dir, mode: 0o644)
if File.exist? "Makefile"
  system("#{ENV["MAKE"] || "make"} install")
else
  bottom_dir = "#{top_dir}/rijndael"
  mkdir_p(bottom_dir)
  install("core.rb", bottom_dir, mode: 0o644)
end
