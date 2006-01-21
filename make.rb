require "rbconfig.rb"
include Config
require "fileutils"
include FileUtils::Verbose

loop do
	puts "Do you want to install the binary (b) or pure-ruby (r) core? (b/r)?"

	answer=STDIN.gets
	if(answer=~/^b/i)
			require "./extconf.rb"
			exit system(ENV["MAKE"]||"make")
	elsif(answer=~/^r/i)
			File.rm("Makefile")
			File.copy("pr-core.rb", "core.rb")
			exit
	end

end
