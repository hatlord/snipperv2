#!/usr/bin/env ruby
#Snipperv2 is a Nipper FW config parsing script. V2 uses the Nipper XML output whereas V1 uses CSV.

require 'nokogiri'
require 'csv'
require 'colorize'

class Parse_xml

  def initialize
    @fwpol = Nokogiri::XML(File.read(ARGV[0]))
    @rule_array = []
    @device = {}
  end

  def device
    @fwpol.xpath('//document').each do |intro|
      @device[:name]     = intro.xpath("./information/devices/device/@name").text
      @device[:type]     = intro.xpath("./information/devices/device/@type").text
      @device[:os]       = intro.xpath("./information/devices/device/@os").text
      @device[:version]  = intro.xpath("./information/devices/device/@osversion").text
      puts "#{@device[:name]}\t#{@device[:type]}\t#{@device[:os]}\t#{@device[:version]}".red.bold
    end
  end

  def cisco
    if @device[:type] =~ /Cisco Adaptive Security Appliance Firewall/i
      @fwpol.xpath('//document/report/part/section').each do |title|
        rules = {}
        rules[:title]  = title.xpath('@title').text
      
      title.xpath('./section/table').each do |info|
      # rules = {}
      
      rules[:table]    = info.xpath('@title').text
      rules[:ref]      = info.xpath('@ref').text

      #need to add another loop above this to pull in <section title="Filter Rules Allow Packets From Any Source To Any Destination And Any Port"></section>

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
    @rule_array.each { |r| puts "#{r[:title]},#{r[:table]},#{r[:name]},#{r[:active]},#{r[:action]},#{r[:src]},#{r[:srcprt]},#{r[:dst]},#{r[:dport]},#{r[:srvc]},#{r[:log]}"}
    # @rule_array.each { |r| puts r[:title]}
  end


  end

  def other
    if @device[:type] !~ /Cisco Adaptive Security Appliance Firewall/i
    @fwpol.xpath('//document/report/part/section/section/table').each do |info|
    rules = {}
      
      rules[:table]    = info.xpath('@title').text
      rules[:ref]      = info.xpath('@ref').text

      #need to add another loop above this to pull in <section title="Filter Rules Allow Packets From Any Source To Any Destination And Any Port"></section>
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
    # @rule_array.each { |r| puts "#{r[:table]},#{r[:name]},#{r[:action]},#{r[:src]}#{r[:dst]},#{r[:srvc]},#{r[:log]}"}
    @rule_array.each { |r| puts r[:table]}
  end

end

fwparse = Parse_xml.new
fwparse.device
fwparse.cisco
fwparse.other
# fwparse.print_test

# class Munge
# end

# class Output
# end



# fwpol = Nokogiri::XML(File.read(ARGV[0]))
# rule_array = []

#device info

# fwpol.xpath('//document').each do |intro|
#   device = {}

#   device[:name]     = intro.xpath("./information/devices/device/@name").text
#   device[:type]     = intro.xpath("./information/devices/device/@type").text
#   device[:os]       = intro.xpath("./information/devices/device/@os").text
#   device[:version]  = intro.xpath("./information/devices/device/@osversion").text
#   puts "#{device[:name]}\t#{device[:type]}\t#{device[:os]}\t#{device[:version]}".red.bold
# end

#need to add in table name and other relevant details

#this is basically working
#need to add another loop above this to pull in <section title="Filter Rules Allow Packets From Any Source To Any Destination And Any Port"></section>
#Then I can use this to filter results for the final report
#Need to pull headers for tables out too, then I can add them to the CSV/HTML/OUTPUT when im done



# fwpol.xpath('//document/report/part/section/section/table').each do |info|
#   rules = {}

#   rules[:table]    = info.xpath('@title').text
#   rules[:ref]      = info.xpath('@ref').text


# info.xpath('./tablebody/tablerow').each do |item|

#   if rules[:ref] =~ /FILTER\./
#   rules[:name]   = item.xpath('./tablecell[1]/item').text
#   rules[:action] = item.xpath('./tablecell[2]/item').text
#   rules[:src]    = item.xpath('./tablecell[3]/item').map(&:text)
#   rules[:dst]    = item.xpath('./tablecell[4]/item').map(&:text)
#   rules[:srvc]   = item.xpath('./tablecell[5]/item').map(&:text)
#   rules[:log]    = item.xpath('./tablecell[6]/item').text

#   rule_array << rules
#     end
#   end
# end

# rule_array.each do |rule|
#   puts "#{rule[:table]}\t#{rule[:name]}\t#{rule[:action]}\t#{rule[:src]}\t#{rule[:dst]}\t#{rule[:srvc]}\t#{rule[:log]}"
# end








# rule_array.each { |r| puts r if r[:title] =~ /Filter Allow Rules Were Configured Without Logging/}

# puts rule_array

# rule_array.each {|e| puts e[:head] }