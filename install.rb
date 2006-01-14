require "rbconfig.rb"
include Config
require "fileutils"
include FileUtils::Verbose

mkdir_p(CONFIG["sitelibdir"]+"/crypt")
install("rijndael.rb", CONFIG["sitelibdir"]+"/crypt")
loop do
	puts "Do you want to install the binary (b) or pure-ruby (r) core? (b/r)?"

	answer=STDIN.gets
	if(answer=~/^b/i)
			require "./extconf.rb"
			exit
	elsif(answer=~/^r/i)
			require "./install-pr.rb"
			exit
	end

end
