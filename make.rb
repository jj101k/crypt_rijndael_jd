require "rbconfig.rb"
include RbConfig
require "fileutils"
include FileUtils::Verbose

loop do
	puts "Do you want to install the binary (b) or pure-ruby (r) core? (b/r)?"

	answer=STDIN.gets
	if(answer=~/^b/i)
			begin
			File.unlink("core.rb")
			rescue Errno::ENOENT
			end
			require __dir__ + "/extconf.rb"
			exit system(ENV["MAKE"]||"make")
	elsif(answer=~/^r/i)
			begin
			File.unlink("Makefile")
			rescue Errno::ENOENT
			end
			FileUtils.cp("pr-core.rb", "core.rb")
			exit
	end

end
