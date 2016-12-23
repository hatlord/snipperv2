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

            ref.xpath('./table/tablebody/tablerow').each do |issue|
              if @vuln[:title].to_s == "Vulnerability audit summary findings"
                headings.each do |head|
                  val = headings.index(head).to_i + 1
                  @vuln[head.to_sym] = issue.xpath("./tablecell[#{val}]/item").map(&:text).join("\r")
                end
              @vuln_array << @vuln.dup
            end
          end
        end
      end
    end 
  end

  def rules
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

  def testprint
    # @rule_array.each { |r| puts r }
    # @netw_srvc.each { |n| puts n}
    puts @vuln_array
  end

end






fwparse = Parsexml.new
fwparse.device_type
fwparse.users
fwparse.net_services
fwparse.auditrec
fwparse.vulns
fwparse.rules
fwparse.testprint
