require "rbconfig.rb"
include Config
require "fileutils"
include FileUtils::Verbose

mkdir_p(CONFIG["sitelibdir"]+"/crypt")
install("rijndael.rb", CONFIG["sitelibdir"]+"/crypt")
if(File.exists? "Makefile")
	system((ENV["MAKE"]||"make")+' install')
else
	mkdir_p(CONFIG["sitelibdir"]+"/crypt/rijndael")
	install("core.rb", CONFIG["sitelibdir"]+"/crypt/rijndael/")
end
