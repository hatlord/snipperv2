#!/usr/bin/env ruby
#Snipperv2 is a Nipper FW config parsing script. V2 uses the Nipper XML output whereas V1 uses CSV.

require 'nokogiri'
require 'csv'
require 'colorize'

class Parsexml

  attr_reader :rule_array, :device

  def initialize
    @fwpol = Nokogiri::XML(File.read(ARGV[0]))
    @rule_array = []
    @device = {}
  end

  def device_type
    @fwpol.xpath('//document').each do |intro|
      @device[:name]     = intro.xpath("./information/devices/device/@name").text
      @device[:type]     = intro.xpath("./information/devices/device/@type").text
      @device[:os]       = intro.xpath("./information/devices/device/@os").text
      @device[:version]  = intro.xpath("./information/devices/device/@osversion").text
      # puts "#{@device[:name]}\t#{@device[:type]}\t#{@device[:os]}\t#{@device[:version]}".red.bold
    end
  end

  def cisco
    if @device[:type] =~ /Cisco Adaptive Security Appliance Firewall/i
      @fwpol.xpath('//document/report/part/section').each do |title|
        rules = {}
        rules[:title]  = title.xpath('@title').text
      
        title.xpath('./section/table').each do |info|

          rules[:table]    = info.xpath('@title').text
          rules[:ref]      = info.xpath('@ref').text

        info.xpath('./tablebody/tablerow').each do |item|

          if rules[:ref] =~ /FILTER\./
            rules[:name]   = item.xpath('./tablecell[1]/item').text
            rules[:active] = item.xpath('./tablecell[2]/item').text
            rules[:action] = item.xpath('./tablecell[3]/item').text
            rules[:proto]  = item.xpath('./tablecell[4]/item').map(&:text)
            rules[:src]    = item.xpath('./tablecell[5]/item').map(&:text)
            rules[:srcprt] = item.xpath('./tablecell[6]/item').map(&:text)
            rules[:dst]    = item.xpath('./tablecell[7]/item').map(&:text)
            rules[:dport]  = item.xpath('./tablecell[8]/item').map(&:text)
            rules[:srvc]   = item.xpath('./tablecell[9]/item').map(&:text)
            rules[:log]    = item.xpath('./tablecell[10]/item').text

            @rule_array << rules.dup
            #cisco appears to populate EITHER dport or srvc. Need to write logic when we print to say print the other if empty
          end
        end
      end
    end
  end
    # @rule_array.each { |r| puts "#{r[:title]},#{r[:table]},#{r[:name]},#{r[:active]},#{r[:action]},#{r[:src]},#{r[:srcprt]},#{r[:dst]},#{r[:dport]},#{r[:srvc]},#{r[:log]}"}
  end


  def other
    if @device[:type] !~ /Cisco Adaptive Security Appliance Firewall/i
      @fwpol.xpath('//document/report/part/section').each do |title|
        rules = {}
        rules[:title]  = title.xpath('@title').text
      
        title.xpath('./section/table').each do |info|

          rules[:table]    = info.xpath('@title').text
          rules[:ref]      = info.xpath('@ref').text

        info.xpath('./tablebody/tablerow').each do |item|

          if rules[:ref] =~ /FILTER\./
            rules[:name]   = item.xpath('./tablecell[1]/item').text
            rules[:action] = item.xpath('./tablecell[2]/item').text
            rules[:src]    = item.xpath('./tablecell[3]/item').map(&:text)
            rules[:dst]    = item.xpath('./tablecell[4]/item').map(&:text)
            rules[:srvc]   = item.xpath('./tablecell[5]/item').map(&:text)
            rules[:log]    = item.xpath('./tablecell[6]/item').text

            @rule_array << rules.dup    
          end
        end
      end
    end
  end
    # @rule_array.each { |r| puts "#{r[:title]},#{r[:table]},#{r[:name]},#{r[:action]},#{r[:src]}#{r[:dst]},#{r[:srvc]},#{r[:log]}"}
  end

  def rules
    @rule_array
  end

end

class Sort_data

  def initialize(fwparse)
    @fwparse = fwparse
    # @admin = []
  end

  # def administrative
  #   @fwparse.rules.each do |rule|
  #     if rule[:title] =~ /Allow Access To Administrative Services/i
  #       @admin << rule
  #       p @admin
  #     end
  #   end
  # end

  def administrative
    #This works perfectly. Will need to decice where I am manipulating this date. In this class or the parser?
    @admin  = @fwparse.rules.select { |r| r[:title] =~ /Allow Access To Administrative Services/i }
    @plain  = @fwparse.rules.select { |r| r[:title] =~ /Access To Clear-Text Protocol/i }
    @permit = @fwparse.rules.select { |r| r[:title] =~ /Allow Packets From Any Source To Any Destination And Any Port/i }
    @over_permissive
    # puts @fwparse.rules
    # puts @permit
  end

  def plaintext
  end

  def permitany
  end

  def overly_permissive
  end

  def sensitive
  end

  def legacy
  end
#This class will sort through the data built by the parser and shit out stuff for the report. 
end

#This class will deal with output to other classes
class Output

  def initialize(fwparse)
    @fwparse = fwparse
  end

  def printme
    #This works but needs to change given that we aren't printing much/anything to console
    puts "#{@fwparse.device[:name]}\t#{@fwparse.device[:type]}\t#{@fwparse.device[:os]}\t#{@fwparse.device[:version]}".red.bold
  end

end


fwparse = Parsexml.new
fwparse.device_type
fwparse.cisco
fwparse.other

sortme = Sort_data.new(fwparse)
sortme.administrative

# printer = Output.new(fwparse)
# printer.printme