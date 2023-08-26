require "rbconfig.rb"
include RbConfig
require "fileutils"
include FileUtils::Verbose

mkdir_p(CONFIG["sitelibdir"]+"/jdcrypt")
install("jdcrypt/rijndael.rb", CONFIG["sitelibdir"]+"/jdcrypt", :mode=>0644)
if(File.exists? "Makefile")
	system((ENV["MAKE"]||"make")+' install')
else
	mkdir_p(CONFIG["sitelibdir"]+"/jdcrypt/rijndael")
	install("core.rb", CONFIG["sitelibdir"]+"/jdcrypt/rijndael/", :mode=>0644)
end
