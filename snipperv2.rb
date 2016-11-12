#!/usr/bin/env ruby
#Snipperv2 is a Nipper FW config parsing script. V2 uses the Nipper XML output whereas V1 uses CSV.

require 'nokogiri'
require 'csv'
require 'colorize'

class Parsexml

  attr_reader :rule_array, :device, :vuln_array, :user_array
  attr_reader :netw_srvc, :audit_rec

  def initialize
    @fwpol = Nokogiri::XML(File.read(ARGV[0]))
    @rule_array = []
    @vuln_array = []
    @user_array = []
    @netw_srvc  = []
    @audit_rec  = []
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
      @userinfo[:title] = title.xpath('@title').text

      title.xpath('./table/tablebody/tablerow').each do |user|
        if @userinfo[:title] == "Local Users"
          @userinfo[:user]   = user.xpath('./tablecell[1]/item').text
          @userinfo[:pass]   = user.xpath('./tablecell[2]/item').text
          @userinfo[:priv]   = user.xpath('./tablecell[3]/item').text

          @user_array << @userinfo.dup

        end
      end
    end
  end

  def net_services
    @fwpol.xpath('//document/report/part/section/section').each do |title|
      @services = {}
      @services[:title] = title.xpath('@title').text

      title.xpath('./table/tablebody/tablerow').each do |service|
        if @services[:title] == "Network Services"
          @services[:name]   = service.xpath('./tablecell[1]/item').text
          @services[:status] = service.xpath('./tablecell[2]/item').text
          @services[:proto]  = service.xpath('./tablecell[3]/item').text
          @services[:port]   = service.xpath('./tablecell[4]/item').text
            
          @netw_srvc << @services.dup
            
        end
      end
    end
  end

  def auditrec
    @fwpol.xpath('//document/report/part/section').each do |title|
      @audit = {}
      @audit[:title] = title.xpath('@title').text
      
      title.xpath('./table/tablebody/tablerow').each do |rec|
        if @audit[:title] == "Recommendations"
          @audit[:issue]     = rec.xpath('./tablecell[1]/item').text
          @audit[:rating]    = rec.xpath('./tablecell[2]/item').text
          @audit[:recommend] = rec.xpath('./tablecell[3]/item').text
          @audit[:device]    = rec.xpath('./tablecell[4]/item').text
          @audit[:section]   = rec.xpath('./tablecell[5]/item').text
            
          @audit_rec << @audit.dup

        end
      end
    end
  end

  def vulns
    @fwpol.xpath('//document/report/part/section').each do |ref|
      @vuln = {}
      @vuln[:ref] = ref.xpath('@ref').text

      ref.xpath('./table[2]/tablebody/tablerow').each do |issue|
        if @vuln[:ref] == "VULNAUDIT.CONCLUSIONS"
          @vuln[:cve]        = issue.xpath('./tablecell[1]/item').text
          @vuln[:cvss]       = issue.xpath('./tablecell[2]/item').text
          @vuln[:severity]   = issue.xpath('./tablecell[3]/item').text
          @vuln[:advisory]   = issue.xpath('./tablecell[6]/item').text
          @vuln[:references] = issue.xpath('./tablecell[7]/item').text

          @vuln_array << @vuln.dup

        end
      end
    end 
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
    #don't like this, find a better way?
    @rule_array
  end

end

class Sort_data

  def initialize(fwparse)
    @fwparse = fwparse
    # @admin = []
  end

  def build_arrays

    @adminsrv        = @fwparse.rules.select { |r| r[:title] =~ /Allow Access To Administrative Services/ }
    @plaintext       = @fwparse.rules.select { |r| r[:title] =~ /Access To Clear-Text Protocol/ }
    @permitall       = @fwparse.rules.select { |r| r[:title] =~ /Allow Packets From Any Source To Any Destination And Any Port/ }
    @over_permissive = @fwparse.rules.select { |r| r[:table] =~ /rule allowing|rules allowing/ }
    @sensitive       = @fwparse.rules.select { |r| r[:title] =~ /Potentially Sensitive Services/ }
    @nologging       = @fwparse.rules.select { |r| r[:title] =~ /Configured Without Logging/ }
    @legacy          = @fwparse.rules.select { |r| r[:title] =~ /Potentially Unnecessary Services/ }
    @norules         = @fwparse.rules.select { |r| r[:title] =~ /No Network Filtering Rules Were Configured/ } #Need to find a config that this will work on
    # puts @fwparse.vuln_array
    # @fwparse.rules.each { |r| puts r[:title]}
    # puts @fwparse.rules
    # puts @over_permissive
    puts @permitall
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
fwparse.auditrec
fwparse.vulns


sortme = Sort_data.new(fwparse)
sortme.build_arrays
sortme.afunction

# printer = Output.new(fwparse)
# printer.printme