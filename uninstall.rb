# frozen_string_literal: true

require "rbconfig"
include RbConfig
require "fileutils"
include FileUtils::Verbose

top_dir = "#{CONFIG["sitelibdir"]}/jdcrypt"

rm("#{top_dir}/rijndael.rb")
rm("#{top_dir}/aes.rb")

rm("#{top_dir}/rijndael/core.rb") if File.exist? "#{top_dir}/rijndael/core.rb"

top_arch_dir = "#{CONFIG["sitearchdir"]}/jdcrypt"

rm("#{top_arch_dir}/rijndael/core.bundle") if File.exist? "#{top_arch_dir}/rijndael/core.bundle"