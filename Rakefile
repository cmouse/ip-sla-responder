require 'rubygems'
require 'uglifier'
require 'coffee-script'
require 'erb'

class TemplateBinding 
   attr_accessor :content
   attr_accessor :page

   def get_binding
     binding
   end

   def active(page)
     if self.page == page.to_s 
       return ' class="active"'
     end
     return ''
   end
end

task :default do |t|
  data = ""
  Dir.glob("*.js.coffee").sort.each do |f|
   data = data + File.read(f)
  end

  File.open("application.js", "w") do |f|
    f.puts Uglifier.new.compile(CoffeeScript.compile(data))
  end

  header = ERB.new(File.read("header.erb.html"))

  # create pages
  Dir.glob("*.erb.html").each do |fn|
    bn = File.basename fn, ".erb.html"
    next if bn == "header" or bn == "footer"
    File.open("#{bn}.html","w") do |f|
        tp = TemplateBinding.new
        tp.page = bn
        tp.content = ERB.new(File.read(fn)).result
        f.puts header.result(tp.get_binding)
    end
  end
end
