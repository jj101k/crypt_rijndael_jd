require "rbconfig.rb"
include Config
require "fileutils"
include FileUtils::Verbose
require "generate-initial-keys.rb"

loop do
	puts "Do you want to install the binary (b) or pure-ruby (r) core? (b/r)?"

	answer=STDIN.gets
	if(answer=~/^b/i)
			begin
			File.rm("core.rb")
			rescue Errno::ENOENT
			end
			require "./extconf.rb"
			exit system(ENV["MAKE"]||"make")
	elsif(answer=~/^r/i)
			begin
			File.rm("Makefile")
			rescue Errno::ENOENT
			end
			File.copy("pr-core.rb", "core.rb")
			exit
	end

end
