require 'rubygems'
require 'uglifier'
require 'coffee-script'

task :default do |t|   
  data = ""
  Dir.glob("*.js.coffee").sort.each do |f|
   data = data + File.read(f)
  end

  File.open("application.js", "w") do |f|
    f.puts Uglifier.new.compile(CoffeeScript.compile(data))
  end
end
