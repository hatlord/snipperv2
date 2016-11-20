#!/usr/bin/env ruby
#Snipperv2 is a Nipper FW config parsing script. V2 uses the Nipper XML output whereas V1 uses CSV.

require 'nokogiri'
require 'csv'
require 'colorize'

class Parsexml

  attr_reader :rule_array, :device, :vuln_array, :user_array
  attr_reader :netw_srvc, :audit_rec

  def initialize
    @fwpol      = Nokogiri::XML(File.read(ARGV[0]))
    @rule_array = []
    @vuln_array = []
    @user_array = []
    @netw_srvc  = []
    @audit_rec  = []
    @device     = {}
  end

  def device_type
    @fwpol.xpath('//document').each do |intro|
      @device[:name]     = intro.xpath("./information/devices/device/@name").text
      @device[:type]     = intro.xpath("./information/devices/device/@type").text
      @device[:os]       = intro.xpath("./information/devices/device/@os").text
      @device[:version]  = intro.xpath("./information/devices/device/@osversion").text
      puts "#{@device[:name]}\t#{@device[:type]}\t#{@device[:os]}\t#{@device[:version]}".light_blue.bold
    end
  end

  def device_supported
    if @device[:type] =~ /Cisco|Checkpoint|Alteon|Juniper|Watchguard|Fortigate|Dell|Palo/
      puts "#{@device[:type].upcase} SUPPORTED - CONTINUING....".green.bold
    else
      puts "#{@device[:type].upcase} UNSUPPORTED - EXITING :( - Speak to Rich".red.bold
      exit
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
    if @device[:type] =~ /Cisco/
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
                rules[:proto]  = item.xpath('./tablecell[4]/item').map(&:text).join("\r")
                rules[:src]    = item.xpath('./tablecell[5]/item').map(&:text).join("\r")
                rules[:srcprt] = item.xpath('./tablecell[6]/item').map(&:text).join("\r")
                rules[:dst]    = item.xpath('./tablecell[7]/item').map(&:text).join("\r")
                rules[:dport]  = item.xpath('./tablecell[8]/item').map(&:text).join("\r")
                rules[:srvc]   = item.xpath('./tablecell[9]/item').map(&:text).join("\r")
                rules[:log]    = item.xpath('./tablecell[10]/item').text
                rules[:combo]  = rules[:dport] + rules [:srvc]
                if !rules[:proto].empty? and rules[:dport] !~ /[Group]/
                  rules[:combo] = rules[:proto] + "/" + rules[:dport] 
                end

                @rule_array << rules.dup

            end
          end
        end
      end
    end
  end

  def checkpoint
    if @device[:type] =~ /Checkpoint|Alteon/
      @fwpol.xpath('//document/report/part/section').each do |title|
        rules = {}
        rules[:title]  = title.xpath('@title').text

        title.xpath('./section/table').each do |info|
          rules[:table]    = info.xpath('@title').text
          rules[:ref]      = info.xpath('@ref').text

            info.xpath('./tablebody/tablerow').each do |item|
              if rules[:ref] =~ /FILTER\./
                rules[:name]      = item.xpath('./tablecell[1]/item').text
                rules[:active]    = item.xpath('./tablecell[2]/item').text
                rules[:action]    = item.xpath('./tablecell[3]/item').text
                rules[:src]       = item.xpath('./tablecell[4]/item').map(&:text).join("\r")
                rules[:dst]       = item.xpath('./tablecell[5]/item').map(&:text).join("\r")
                rules[:srvc]      = item.xpath('./tablecell[6]/item').map(&:text).join("\r")
                rules[:time]      = item.xpath('./tablecell[7]/item').map(&:text).join("\r")
                rules[:install]   = item.xpath('./tablecell[8]/item').map(&:text).join("\r")
                rules[:through]   = item.xpath('./tablecell[9]/item').map(&:text).join("\r")
                rules[:log]       = item.xpath('./tablecell[10]/item').map(&:text).join("\r")
                rules[:combo]     = rules[:srvc]

                @rule_array << rules.dup 

            end
          end
        end
      end
    end
  end

  def paloalto
    if @device[:type] =~ /Palo Alto/
      @fwpol.xpath('//document/report/part/section').each do |title|
        rules = {}
        rules[:title]  = title.xpath('@title').text

        title.xpath('./section/table').each do |info|
          rules[:table]    = info.xpath('@title').text
          rules[:ref]      = info.xpath('@ref').text

            info.xpath('./tablebody/tablerow').each do |item|
              if rules[:ref] =~ /FILTER\./
                rules[:name]      = item.xpath('./tablecell[1]/item').text
                rules[:active]    = item.xpath('./tablecell[2]/item').text
                rules[:action]    = item.xpath('./tablecell[3]/item').text
                rules[:src]       = item.xpath('./tablecell[4]/item').map(&:text).join("\r")
                rules[:dst]       = item.xpath('./tablecell[5]/item').map(&:text).join("\r")
                rules[:srvc]      = item.xpath('./tablecell[6]/item').map(&:text).join("\r")
                rules[:combo]     = rules[:srvc]

                @rule_array << rules.dup

            end
          end
        end
      end
    end
  end

  def other
    if @device[:type] !~ /Cisco|Alteon|Checkpoint|Palo/i
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
                rules[:src]    = item.xpath('./tablecell[3]/item').map(&:text).join("\r")
                rules[:dst]    = item.xpath('./tablecell[4]/item').map(&:text).join("\r")
                rules[:srvc]   = item.xpath('./tablecell[5]/item').map(&:text).join("\r")
                rules[:log]    = item.xpath('./tablecell[6]/item').map(&:text).join("\r")
                rules[:combo]  = rules[:srvc]

                @rule_array << rules.dup 

            end
          end
        end
      end
    end
  end

  def norules
    if @fwpol.xpath('//document/report/part/section/@title').text =~ /No Network Filtering Rules Were Configured/
      puts "NO FIREWALL RULES WERE CONFIGURED - DID SOMETHING GO WRONG?".red.bold
    end
  end

  def rules
    @rule_array
  end

end

class Output

  def initialize(fwparse)
    @fwparse = fwparse
  end

  def build_arrays  
    @adminsrv        = @fwparse.rules.select { |r| r[:title] =~ /Allow Access To Administrative Services/ }
    @plaintext       = @fwparse.rules.select { |r| r[:title] =~ /Access To Clear-Text Protocol/ }
    @permitall       = @fwparse.rules.select { |r| r[:title] =~ /Allow Packets From Any Source To Any Destination And Any Port/ }
    @over_permissive = @fwparse.rules.select { |r| r[:table] =~ /rule allowing|rules allowing/ }
    @sensitive       = @fwparse.rules.select { |r| r[:title] =~ /Potentially Sensitive Services/ }
    @nologging       = @fwparse.rules.select { |r| r[:title] =~ /Configured Without Logging/ }
    @legacy          = @fwparse.rules.select { |r| r[:title] =~ /Potentially Unnecessary Services/ }
  end

  def permitall_fix
    @permitall.each { |r| r[:aclname] = r[:table].match(/(?<=ACL )(.*)(?= rule)/)}
  end

  def admin_fix
    @adminsrv.delete_if { |r| r[:combo] == "Any" }
    @adminsrv.delete_if { |r| r[:combo] == "[Host] Any" }
    @adminsrv.each { |r| r[:aclname] = r[:ref].gsub(/FILTER.BLACKLIST.ADMIN/, '')}
  end

  def plain_fix
    @plaintext.delete_if { |r| r[:combo] == "Any" }
    @plaintext.delete_if { |r| r[:combo] == "[Host] Any" }
    @plaintext.each { |r| r[:aclname] = r[:ref].gsub(/FILTER.BLACKLIST.CLEARTEXT/, '')}
  end

  def over_permissive_fix
    @over_permissive.delete_if { |r| r[:title] =~ /Filter Rules Allow Packets From Any Source To Any Destination And Any Port/ } #removes permit all, which will be in another function
    @over_permissive.each { |r| r[:aclname] = r[:table].match(/(?<=ACL )(.*)(?= rule)/)} #regex matches everything between 'ACL ' and ' rule' = ACLNAME
  end

  def create_file
    Dir.mkdir("#{Dir.home}/Documents/Snipper_Out/") unless File.exists?("#{Dir.home}/Documents/Snipper_Out/")
    @file    = "#{@fwparse.device[:type]}_#{Time.now.strftime("%d%b%Y_%H%M%S")}"
    @csvfile = File.new("#{Dir.home}/Documents/Snipper_Out/#{@file}.csv", 'w+')
    puts "\nOutput written to #{@csvfile.path}".light_blue.bold
  end

  def headers
    @headers = ['NipperTable', 'ACL/Zone/Interface/Policy', 'RuleNo/Name', 'Source', 'Destination', 'DestPort/Service']
  end

  def generate_data
    if @fwparse.rules
      @permitallstring = CSV.generate do |csv|
        @permitall.each { |row| csv << [row[:table], row[:aclname], row[:name], row[:src], row[:dst], row[:combo]] }
      end
      @adminstring = CSV.generate do |csv|
        csv << @headers
          @adminsrv.each { |row| csv << [row[:table], row[:aclname], row[:name], row[:src], row[:dst], row[:combo]] }
      end
      @plainstring = CSV.generate do |csv|
        csv << @headers
          @plaintext.each { |row| csv << [row[:table], row[:aclname], row[:name], row[:src], row[:dst], row[:combo]] }
      end
      @permissivestring = CSV.generate do |csv|
        csv << @headers
          @over_permissive.each { |row| csv << [row[:table], row[:aclname], row[:name], row[:src], row[:dst], row[:combo]] }
      end
    end   
  end

  def write_data
    if !@permitall.empty?
      @csvfile.puts "@@@@@@@@@@RULES ALLOWING ALL TRAFFIC@@@@@@@@@@"
      @csvfile.puts(@permitallstring)
    end
    if !@over_permissive.empty?
      @csvfile.puts "\n\n\n\n@@@@@@@@@@OVERLY PERMISSIVE RULES@@@@@@@@@@"
      @csvfile.puts(@permissivestring)
    end
    if !@plaintext.empty?
      @csvfile.puts "\n\n\n\n@@@@@@@@@@PLAINTEXT SERVICES@@@@@@@@@@"
      @csvfile.puts(@plainstring)
    end
    if !@adminsrv.empty?
      @csvfile.puts "\n\n\n\n@@@@@@@@@@Administrative Service Rules@@@@@@@@@@"
      @csvfile.puts(@adminstring)
    end
    @csvfile.close
  end

end


fwparse = Parsexml.new
fwparse.device_type
fwparse.device_supported
fwparse.cisco
fwparse.checkpoint
fwparse.paloalto
fwparse.other
fwparse.norules
fwparse.users
fwparse.net_services
fwparse.auditrec
fwparse.vulns

output = Output.new(fwparse)
output.build_arrays
output.permitall_fix
output.admin_fix
output.plain_fix
output.over_permissive_fix
output.create_file
output.headers
output.generate_data
output.write_data