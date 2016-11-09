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

  def users
    @fwpol.xpath('//document/report/part/section/section/section').each do |title|
      @userinfo = {}
      @userinfo[:title]  = title.xpath('@title').text

      title.xpath('./table/tablebody/tablerow').each do |user|
        if @userinfo[:title] == "Local Users"
          @userinfo[:user]   = user.xpath('./tablecell/item').map(&:text)
            #userid, username, password, privileges
        end
      end
    end
  end

  def net_services
    @fwpol.xpath('//document/report/part/section/section').each do |title|
      @services = {}
      @services[:title]  = title.xpath('@title').text

      title.xpath('./table/tablebody/tablerow').each do |service|
        if @services[:title] == "Network Services"
          @services[:network] = service.xpath('./tablecell/item').map(&:text)
        end
      end
    end
  end

  def auditrec
    #audit recommendations
  end

  def vulns
  end

  def cisco
    if @device[:type] =~ /Cisco Adaptive Security Appliance Firewall/i
      @fwpol.xpath('//document/report/part/section').each do |title|
        rules = {}
        rules[:title]  = title.xpath('@title').text
        #Device name in here so we can do multi device reviews?
      
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
        #Device name in here so we can do multi device reviews?

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

  def build_arrays

    @adminsrv        = @fwparse.rules.select { |r| r[:title] =~ /Allow Access To Administrative Services/i } #remove case insensitivity?
    @plaintext       = @fwparse.rules.select { |r| r[:title] =~ /Access To Clear-Text Protocol/i } #remove case insensitivity?
    @permitall       = @fwparse.rules.select { |r| r[:title] =~ /Allow Packets From Any Source To Any Destination And Any Port/i }
    @over_permissive = @fwparse.rules.select { |r| r[:table] =~ /rule allowing|rules allowing/ } #test this works with both types
    @sensitive       = @fwparse.rules.select { |r| r[:title] =~ /Potentially Sensitive Services/ }
    @nologging       = @fwparse.rules.select { |r| r[:title] =~ /Configured Without Logging/ }
    @legacy          = @fwparse.rules.select { |r| r[:title] =~ /Potentially Unnecessary Services/ }
    @norules         = @fwparse.rules.select { |r| r[:title] =~ /No Network Filtering Rules Were Configured/ } #Need to find a config that this will work on

    # @fwparse.rules.each { |r| puts r[:title]}
    # puts @over_permissive
    # puts @permit
  end

  def afunction

  end

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
fwparse.users
fwparse.net_services


sortme = Sort_data.new(fwparse)
sortme.build_arrays
sortme.afunction

# printer = Output.new(fwparse)
# printer.printme