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

  def users
    @fwpol.xpath('//document/report/part/section/section/section').each do |title|
      @userinfo = {}
      @userinfo[:title] = title.xpath('@title').text

      title.xpath('./table/headings').each do |header|
        headings = header.xpath('./heading').map(&:text)

          title.xpath('./table/tablebody/tablerow').each do |user|
            if @userinfo[:title] == "Local Users"
              headings.each do |head|
                val = headings.index(head).to_i + 1
                @userinfo[head.to_sym] = user.xpath("./tablecell[#{val}]/item").map(&:text).join("\r")
              end  
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

      title.xpath('./table/headings').each do |header|
        headings = header.xpath('./heading').map(&:text)

          title.xpath('./table/tablebody/tablerow').each do |service|
            if @services[:title] == "Network Services"
              headings.each do |head|
                val = headings.index(head).to_i + 1
                @services[head.to_sym] = service.xpath("./tablecell[#{val}]/item").map(&:text).join("\r")
              end
              @netw_srvc << @services.dup
          end
        end
      end
    end
  end

  def auditrec
    @fwpol.xpath('//document/report/part/section').each do |title|
      @audit = {}
      @audit[:title] = title.xpath('@title').text

      title.xpath('./table/headings').each do |header|
        headings = header.xpath('./heading').map(&:text)
      
          title.xpath('./table/tablebody/tablerow').each do |rec|
            if @audit[:title] == "Recommendations"
              headings.each do |head|
                val = headings.index(head).to_i + 1
                @audit[head.to_sym] = rec.xpath("./tablecell[#{val}]/item").map(&:text).join("\r")
              end
            @audit_rec << @audit.dup
          end
        end
      end
    end
  end

  def vulns
    @fwpol.xpath('//document/report/part/section').each do |ref|
      @vuln = {}
      @vuln[:ref] = ref.xpath('@ref').text

      ref.xpath('./table').each do |title|
        @vuln[:title] = title.xpath('@title')

        title.xpath('./headings').each do |header|
          headings = header.xpath('./heading').map(&:text)

            ref.xpath('./table[2]/tablebody/tablerow').each do |issue|
              if @vuln[:title].to_s == "Vulnerability audit summary findings"
                headings.each do |head|
                  val = headings.index(head).to_i + 1
                  @vuln[head.to_sym] = issue.xpath("./tablecell[#{val}]/item").map(&:text).join("\r")
                  @vuln[:allrefs]    = @vuln[:'Security Advisory'].to_s + "\r" + @vuln[:References].to_s
                end
              @vuln_array << @vuln.dup
            end
          end
        end
      end
    end 
  end

  def parse_rules
    @fwpol.xpath('//document/report/part/section').each do |title|
      rules = {}
        rules[:title]  = title.xpath('@title').text
      
        title.xpath('./section/table').each do |info|
          rules[:table]    = info.xpath('@title').text
          rules[:ref]      = info.xpath('@ref').text
          headings = info.xpath('./headings/heading').map(&:text) #creates an array for each set of table headings

            info.xpath('./tablebody/tablerow').each do |item|
              if rules[:ref] =~ /FILTER\./
                headings.each do |head|
                  val = headings.index(head).to_i + 1
                  rules[head.to_sym] = item.xpath("./tablecell[#{val}]/item").map(&:text).join("\r") #assigns table headers as keys (symbols) and each xml 'item' (rule element) as a value, src, dst, port etc.
                end
              @rule_array << rules.dup
          end
        end
      end
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

  def output_data

    #Populate device info
    csv << ["\n\n"] << ["***DEVICE INFO***"]
    csv << ['Name', 'Type', 'Full OS Version']
      @fwparse.dev_array.each do |device|
        csv << [device[:name], device[:type], device[:fullos]]
    end
    
    #Populate Audit Recommendations (This should go before rules and after device info)
    csv << ["\n\n"] << ["***Summary of Issues***"]
    csv << @fwparse.audit_rec.first.keys
      @fwparse.audit_rec.each do |audit|
        csv << audit.values
    end

    #populate rule issues
    rules_array = [@permitall, @over_permissive, @plaintext, @adminsrv, @sensitive, @nologging, @legacy]
    names_array = [
      '***PERMIT ANY TO ANY TO ANY***',
      '***OVERLY PERMISSIVE***',
      '***PLAINTEXT SERVICES***',
      '***ADMINISTRATIVE SERVICES***',
      '***SENSITIVE SERVICES***',
      '***RULES CONFIGURED W/O LOGGING***',
      '***LEGACY SERVICES RULES***',
    ]
      CSV.open(@csvfile, 'w+') do |csv|
        counter = 0
          rules_array.each do |rule|
            if !rule.empty?
              csv << ["\n\n"] << [names_array[counter]]
              csv << rule.first.keys
              rule.select { |rules| csv << rules.values } 
            end
          counter += 1
        end

      #Populate vulnerabilities
        csv << ["\n\n"] << ["***VULNERABILITIES***"]
        csv << ['CVE', 'Severity', 'CVSS', 'References']
        @fwparse.vuln_array.each do |vuln|
          csv << [vuln[:Vulnerability], vuln[:Rating], vuln[:'CVSSv2 Score'], vuln[:allrefs]]
        end
      #Populate Network Services Table
        csv << ["\n\n"] << ["***NETWORK SERVICES***"]
        csv << @fwparse.netw_srvc.first.keys
        @fwparse.netw_srvc.each do |service|
          csv << service.values
        end
      #Populate user table
        csv << ["\n\n"] << ["***LOCAL USERS***"]
        csv << @fwparse.user_array.first.keys
        @fwparse.user_array.each do |user|
          csv << user.values
        end
      end



  end

    # if @fwparse.vuln_array
    #   @vulnstring = CSV.generate do |csv|
    #     csv << ['CVE', 'Severity', 'CVSS', 'Advisorys/Refs']
    #       @fwparse.vuln_array.each { |row| csv << [row[:cve], row[:severity], row[:cvss], row[:allrefs]] }
    #     end
    #   end

end






fwparse = Parsexml.new
fwparse.device_type
fwparse.users
fwparse.net_services
fwparse.auditrec
fwparse.vulns
fwparse.parse_rules
fwparse.rules

output = Output.new(fwparse)
output.build_arrays
output.create_file
output.output_data
# output.write_data

