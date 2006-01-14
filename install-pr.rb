require "rbconfig.rb"
include Config
require "fileutils"
include FileUtils::Verbose

mkdir_p(CONFIG["sitelibdir"]+"/crypt/rijndael")
install("core.rb", CONFIG["sitelibdir"]+"/crypt/rijndael/")
