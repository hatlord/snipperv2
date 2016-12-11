#!/usr/bin/env ruby
#Snipperv2 is a Nipper FW config parsing script. V2 uses the Nipper XML output whereas V1 uses CSV.

require 'nokogiri'
require 'csv'
require 'colorize'

class Parsexml

  attr_reader :rule_array, :device, :vuln_array, :user_array
  attr_reader :netw_srvc, :audit_rec, :dev_array, :fwpol

  def initialize
    @fwpol      = Nokogiri::XML(File.read(ARGV[0]))
    @rule_array = []
    @vuln_array = []
    @user_array = []
    @netw_srvc  = []
    @audit_rec  = []
    @dev_array  = []
    @device     = {}
  end

  def device_type
    @fwpol.xpath('//document').each do |intro|
      @device[:name]     = intro.xpath("./information/devices/device/@name").text
      @device[:type]     = intro.xpath("./information/devices/device/@type").text
      @device[:os]       = intro.xpath("./information/devices/device/@os").text
      @device[:version]  = intro.xpath("./information/devices/device/@osversion").text
      @device[:fullos]   = @device[:os].to_s + " " + @device[:version].to_s
      puts "#{@device[:name]}\t#{@device[:type]}\t#{@device[:os]}\t#{@device[:version]}".light_blue.bold

      @dev_array << @device.dup
    end
  end

  def device_supported
    if @device[:type] =~ /Cisco|Checkpoint|Alteon|Juniper|Watchguard|Fortigate|Dell|Palo/i
      puts "#{@device[:type].upcase} IS SUPPORTED - CONTINUING....".green.bold
    else
      puts "#{@device[:type].upcase} IS UNSUPPORTED - EXITING :( - Speak to Rich".red.bold
      exit
    end
  end

  def users
    if @device[:type] !~ /Fortigate/i
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
  end

  def fortiusers
    if @device[:type] =~ /Fortigate/i
    @fwpol.xpath('//document/report/part/section/section/section').each do |title|
      @userinfo = {}
      @userinfo[:title] = title.xpath('@title').text

      title.xpath('./table/tablebody/tablerow').each do |user|
        if @userinfo[:title] == "Local Users"
          @userinfo[:user]   = user.xpath('./tablecell[1]/item').text
          @userinfo[:group]  = user.xpath('./tablecell[2]/item').text
          @userinfo[:pass]   = user.xpath('./tablecell[3]/item').text
          @userinfo[:priv]   = user.xpath('./tablecell[4]/item').text

          @user_array << @userinfo.dup

          end
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
          @vuln[:advisory]   = issue.xpath('./tablecell[6]/item').map(&:text).join("\r")
          @vuln[:references] = issue.xpath('./tablecell[7]/item').map(&:text).join("\r")
          @vuln[:allrefs]    = @vuln[:advisory] + "\r" + @vuln[:references]

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
                rules[:nine]   = item.xpath('./tablecell[9]/item').map(&:text).join("\r") #could be service or log
                rules[:ten]    = item.xpath('./tablecell[10]/item').map(&:text).join("\r") #could be log or empty

                @rule_array << rules.dup

            end
          end
        end
      end
    end
  end

  def cisco_fix
    if @device[:type] =~ /Cisco/
      @rule_array.each do |rule|
        if (rule[:nine] != "N/A") and (rule[:nine] != "No")
          rule[:combo] = rule[:dport].to_s + rule[:nine].to_s
        else
          rule[:combo] = rule[:dport]
        end
      end
    end
  end

  def proto
    if @device[:type] =~ /Cisco/
      @rule_array.each do |rule|
        if rule[:combo].empty?
          rule[:combo] = rule[:proto]
        end
      end
    end
  end

  def proto_port
    if @device[:type] =~ /Cisco/
      @rule_array.each do |rule|
        if !rule[:combo].start_with?('[Group]', 'ICMP', 'GRE', 'Any', 'ESP', 'AHP', 'AH' )
          rule[:combo] = rule[:proto].to_s + "/" + rule[:dport].to_s
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
    @permitall       = @fwparse.rules.select { |r| r[:title] =~ /Packets From Any Source To Any Destination And Any Port/i }
    @over_permissive = @fwparse.rules.select { |r| r[:table] =~ /rule allowing|rules allowing/ }
    @plaintext       = @fwparse.rules.select { |r| r[:title] =~ /Access To Clear-Text Protocol/ }
    @adminsrv        = @fwparse.rules.select { |r| r[:title] =~ /Allow Access To Administrative Services/ }
    @sensitive       = @fwparse.rules.select { |r| r[:title] =~ /Potentially Sensitive Services/ }
    @nologging       = @fwparse.rules.select { |r| r[:title] =~ /Configured Without Logging/ }
    @legacy          = @fwparse.rules.select { |r| r[:title] =~ /Potentially Unnecessary Services/ }
  end


  def permitall_fix
    if @fwparse.device[:type] =~ /Cisco/
      @permitall.each { |r| r[:aclname] = r[:table].match(/(?<=ACL |List )(.*)(?= rule)/) }
    elsif @fwparse.device[:type] =~ /Checkpoint|Alteon/
      @permitall.each { |r| r[:aclname] = r[:table].match(/(?<=Collections )(.*)(?=rule)/) }
    elsif @fwparse.device[:type] =~ /Palo/
      @permitall.each { |r| r[:aclname] = r[:table].match(/(.*)(?=rule)/) }
    else
      @permitall.each { |r| r[:aclname] = r[:table].match(/(?<=from )(.*)(?= rule)/) }
    end
  end

  def over_permissive_fix
    @over_permissive.delete_if { |r| r[:title] =~ /Packets From Any Source To Any Destination And Any Port/i }
    if @fwparse.device[:type] =~ /Cisco/
      @over_permissive.each { |r| r[:aclname] = r[:table].match(/(?<=ACL |List )(.*)(?= rule)/) }
    elsif @fwparse.device[:type] =~ /Checkpoint|Alteon/
      @over_permissive.each { |r| r[:aclname] = r[:table].match(/(?<=Collections )(.*)(?=rule)/) }
    elsif @fwparse.device[:type] =~ /Palo/
      @over_permissive.each { |r| r[:aclname] = r[:table].match(/(.*)(?=rule)/) }
    else
      @over_permissive.each { |r| r[:aclname] = r[:table].match(/(?<=from )(.*)(?= rule)/) }
    end
  end

  def plain_fix
    if @fwparse.device[:type] =~ /Cisco/
      @plaintext.each { |r| r[:aclname] = r[:table].match(/(?<=ACL |List )(.*)(?= clear)/) }
    elsif @fwparse.device[:type] =~ /Checkpoint|Alteon/
      @plaintext.each { |r| r[:aclname] = r[:table].match(/(?<=Collections )(.*)(?=clear)/) }
    elsif @fwparse.device[:type] =~ /Palo/
      @plaintext.each { |r| r[:aclname] = r[:table].match(/(.*)(?=rule)/) }
    elsif @fwparse.device[:type] =~ /Dell|Sonicwall/i
      @plaintext.each { |r| r[:aclname] = r[:table].match(/(?<=from )(.*)(?= clear-text)/i) }
    else
      @plaintext.each { |r| r[:aclname] = r[:table].match(/(?<=from )(.*)(?= rule)/) }
    end
      @plaintext.delete_if { |r| r[:combo] == "Any" }
      @plaintext.delete_if { |r| r[:combo] == "[Host] Any" }
  end

  def admin_fix
    if @fwparse.device[:type] =~ /Cisco/
      @adminsrv.each { |r| r[:aclname] = r[:table].match(/(?<=ACL |List )(.*)(?= administrative)/) }
    elsif @fwparse.device[:type] =~ /Checkpoint|Alteon/
      @adminsrv.each { |r| r[:aclname] = r[:table].match(/(?<=Collections )(.*)(?=administrative)/) }
    elsif @fwparse.device[:type] =~ /Palo/
      @adminsrv.each { |r| r[:aclname] = r[:table].match(/(.*)(?=rule)/) }
    elsif @fwparse.device[:type] =~ /Dell|Sonicwall/i
      @adminsrv.each { |r| r[:aclname] = r[:table].match(/(?<=from )(.*)(?= administrative)/) }
    else
      @adminsrv.each { |r| r[:aclname] = r[:table].match(/(?<=from )(.*)(?= rule)/) }
    end
      @adminsrv.delete_if { |r| r[:combo] == "Any" }
      @adminsrv.delete_if { |r| r[:combo] == "[Host] Any" }
  end

  def sensitive_fix
    if @fwparse.device[:type] =~ /Cisco/
      @sensitive.each { |r| r[:aclname] = r[:table].match(/(?<=ACL |List )(.*)(?= sensitive)/) }
    elsif @fwparse.device[:type] =~ /Checkpoint|Alteon/
      @sensitive.each { |r| r[:aclname] = r[:table].match(/(?<=Collections )(.*)(?=sensitive)/) }
    elsif @fwparse.device[:type] =~ /Palo/
      @sensitive.each { |r| r[:aclname] = r[:table].match(/(.*)(?=rule)/) }
    elsif @fwparse.device[:type] =~ /Dell|Sonicwall/i
      @sensitive.each { |r| r[:aclname] = r[:table].match(/(?<=from )(.*)(?= sensitive)/) }
    else
      @sensitive.each { |r| r[:aclname] = r[:table].match(/(?<=from )(.*)(?= rule)/) }
    end
      @sensitive.delete_if { |r| r[:combo] == "Any" }
      @sensitive.delete_if { |r| r[:combo] == "[Host] Any" }
  end

  def nolog_fix
    if @fwparse.device[:type] =~ /Cisco/
      @nologging.each { |r| r[:aclname] = r[:table].match(/(?<=ACL |List )(.*)(?= rule)/) }
    elsif @fwparse.device[:type] =~ /Checkpoint|Alteon/
      @nologging.each { |r| r[:aclname] = r[:table].match(/(?<=Collections )(.*)(?=rule)/) }
    elsif @fwparse.device[:type] =~ /Palo/
      @nologging.each { |r| r[:aclname] = r[:table].match(/(.*)(?=rule)/) }
    else
      @nologging.each { |r| r[:aclname] = r[:table].match(/(?<=from )(.*)(?= rule)/) }
    end
  end

  def legacy_fix
    if @fwparse.device[:type] =~ /Cisco/
      @legacy.each { |r| r[:aclname] = r[:table].match(/(?<=ACL |List )(.*)(?= rule)/) }
    elsif @fwparse.device[:type] =~ /Checkpoint|Alteon/
      @legacy.each { |r| r[:aclname] = r[:table].match(/(?<=Collections )(.*)(?=rule)/) }
    elsif @fwparse.device[:type] =~ /Palo/
      @legacy.each { |r| r[:aclname] = r[:table].match(/(.*)(?=rule)/) }
    else
      @legacy.each { |r| r[:aclname] = r[:table].match(/(?<=from )(.*)(?= rule)/) }
    end
  end

  def create_file
    Dir.mkdir("#{Dir.home}/Documents/Snipper_Out/") unless File.exists?("#{Dir.home}/Documents/Snipper_Out/")
    @file    = "#{@fwparse.device[:type].gsub(" ", "_")}_#{Time.now.strftime("%d%b%Y_%H%M%S")}"
    @csvfile = File.new("#{Dir.home}/Documents/Snipper_Out/#{@file}.csv", 'w+')
    puts "Output written to #{@csvfile.path}".light_blue.bold
  end

  def headers
    @headers = ['NipperTable', 'ACL/Zone/Interface/Policy', 'RuleNo/Name', 'Source', 'Destination', 'DestPort/Service']
  end

  def generate_data
    if @fwparse.user_array
      @fwparse.dev_array.each { |dev| @device = dev[:type]}
        @userstring = CSV.generate do |csv|
          if @device !~ /Fortigate/i
            csv << ['Username', 'Password', 'Privileges']
              @fwparse.user_array.each { |row| csv << [row[:user], row[:pass], row[:priv]] }
          else
            csv << ['Username', 'Group', 'Password', 'Privilege']
              @fwparse.user_array.each { |row| csv << [row[:user], row[:group], row[:pass], row[:priv]] }
          end
        end
      end
    if @fwparse.netw_srvc
      @servicestring = CSV.generate do |csv|
        csv << ['Name', 'Status', 'Protocol', 'Port']
          @fwparse.netw_srvc.each { |row| csv << [row[:name], row[:status], row[:proto], row[:port]] }
        end
      end
    if @fwparse.vuln_array
      @vulnstring = CSV.generate do |csv|
        csv << ['CVE', 'Severity', 'CVSS', 'Advisorys/Refs']
          @fwparse.vuln_array.each { |row| csv << [row[:cve], row[:severity], row[:cvss], row[:allrefs]] }
        end
      end
    if @fwparse.audit_rec
      @auditstring = CSV.generate do |csv|
        csv << ['Issue', 'Rating', 'Recommendations', 'Device', 'Nipper Section']
          @fwparse.audit_rec.each { |row| csv << [row[:issue], row[:rating], row[:recommend], row[:device], row[:section]] }
        end
      end
    if @fwparse.dev_array 
      @devicestring = CSV.generate do |csv|
        csv << ['Name', 'Type', 'OS']
          @fwparse.dev_array.each { |row| csv << [row[:name], row[:type], row[:fullos]] }
        end
      end
    if @fwparse.rules #need to add similar statements for each type to ensure no nil errors
      @permitallstring = CSV.generate do |csv|
        csv << @headers
          @permitall.each { |row| csv << [row[:table], row[:aclname], row[:name], row[:src], row[:dst], row[:combo]] }
      end
      @permissivestring = CSV.generate do |csv|
        csv << @headers
          @over_permissive.each { |row| csv << [row[:table], row[:aclname], row[:name], row[:src], row[:dst], row[:combo]] }
      end
      @plainstring = CSV.generate do |csv|
        csv << @headers
          @plaintext.each { |row| csv << [row[:table], row[:aclname], row[:name], row[:src], row[:dst], row[:combo]] }
      end
      @adminstring = CSV.generate do |csv|
        csv << @headers
          @adminsrv.each { |row| csv << [row[:table], row[:aclname], row[:name], row[:src], row[:dst], row[:combo]] }
      end
      @sensitivestring = CSV.generate do |csv|
        csv << @headers
          @sensitive.each { |row| csv << [row[:table], row[:aclname], row[:name], row[:src], row[:dst], row[:combo]] }
      end
      @nologstring = CSV.generate do |csv|
        csv << @headers
          @nologging.each { |row| csv << [row[:table], row[:aclname], row[:name], row[:src], row[:dst], row[:combo]] }
      end
      @legacystring = CSV.generate do |csv|
        csv << @headers
         @legacy.each { |row| csv << [row[:table], row[:aclname], row[:name], row[:src], row[:dst], row[:combo]] }
       end
    end   
  end

  def write_data
    if !@fwparse.dev_array.empty?
      @csvfile.puts "*********DEVICE DETAILS*********"
      @csvfile.puts(@devicestring)
    end
    if !@fwparse.audit_rec.empty?
      @csvfile.puts "\n\n\n\n*********Identified Issues*********"
      @csvfile.puts(@auditstring)
    end
    if !@permitall.empty?
      @csvfile.puts "\n\n\n\n*********RULES ALLOWING ALL TRAFFIC*********"
      @csvfile.puts(@permitallstring)
    end
    if !@over_permissive.empty?
      @csvfile.puts "\n\n\n\n*********OVERLY PERMISSIVE RULES*********"
      @csvfile.puts(@permissivestring)
    end
    if !@plaintext.empty?
      @csvfile.puts "\n\n\n\n*********PLAINTEXT SERVICES*********"
      @csvfile.puts(@plainstring)
    end
    if !@adminsrv.empty?
      @csvfile.puts "\n\n\n\n*********ADMINISTRATIVE SERVICE RULES*********"
      @csvfile.puts(@adminstring)
    end
    if !@sensitive.empty?
      @csvfile.puts "\n\n\n\n*********SENSITIVE SERVICE RULES*********"
      @csvfile.puts(@sensitivestring)
    end
    if !@nologging.empty?
      @csvfile.puts "\n\n\n\n*********RULES CONFIGURED WITHOUT LOGGING*********"
      @csvfile.puts(@nologstring)
    end
    if !@fwparse.vuln_array.empty?
      @csvfile.puts "\n\n\n\n*********VULNERABILITIES*********"
      @csvfile.puts(@vulnstring)
    end
    if !@fwparse.netw_srvc.empty?
      @csvfile.puts "\n\n\n\n********NETWORK SERVICES*********"
      @csvfile.puts(@servicestring)
    end
    if !@fwparse.user_array.empty?
      @csvfile.puts "\n\n\n\n*********USERS*********"
      @csvfile.puts(@userstring)
    end
    @csvfile.close
  end

end


fwparse = Parsexml.new
fwparse.device_type
fwparse.device_supported
fwparse.cisco
fwparse.cisco_fix
fwparse.proto
fwparse.proto_port
fwparse.checkpoint
fwparse.paloalto
fwparse.other
fwparse.norules
fwparse.users
fwparse.fortiusers
fwparse.net_services
fwparse.auditrec
fwparse.vulns

output = Output.new(fwparse)
output.build_arrays
output.permitall_fix
output.over_permissive_fix
output.plain_fix
output.admin_fix
output.sensitive_fix
output.nolog_fix
output.legacy_fix
output.create_file
output.headers
output.generate_data
output.write_data