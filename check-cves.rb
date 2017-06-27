#!/usr/bin/ruby

require 'HTTParty'
require 'Nokogiri'
require 'Pry'
require 'mysql'
require 'net/smtp'

# Configure mysql var
mysql_host = 'localhost'
mysql_db = ''
mysql_user = ''
mysql_pass = ''
report_email = '' # Set Email here
site_url = 'https://www.cvedetails.com/'

# Set product links here.
products_array = [
  'http://www.cvedetails.com/vulnerability-list/vendor_id-3278/product_id-5768/Openvpn-Openvpn.html',
  'http://www.cvedetails.com/vulnerability-list/vendor_id-217/product_id-383/Openssl-Openssl.html'
]

# DO NOT CHANGE ANYTHING BELOW HERE

cve_summary_array = []
cve_id_array = []
cve_data = {}

# initalize our database connectioon
con = Mysql.new mysql_host, mysql_user, mysql_pass, mysql_db

products_array.each do | prod_page |
  product_page = HTTParty.get(prod_page)

  inital_parse = Nokogiri::HTML(product_page)

  #Check for pages so we can handle pagination
  pages = inital_parse.css('.paging a').map { | link | link['href'] }

  pages.each do | page |
    get_page = HTTParty.get(site_url + page)
    parse_page = Nokogiri::HTML(get_page)
    parse_page.css('.searchresults').css('.srrowns a').map do |link|
          link_str = link['href']
          # Only match the links we're interested in
          if link_str =~ /CVE-/
            # Get only the CVE id
            id = link_str.split('/')[2]
            cve_id_array.push(id)
          end
    end

    parse_page.css('.searchresults').css('.cvesummarylong').map do |s|
        cve_summary = s.text
        cve_summary_array.push(cve_summary)
      end

    if cve_id_array.count == cve_summary_array.count
      cve_id_array.each_with_index do |id, index|

        #TO DO Once we have the cve id we need to check our database or state file for our last found cve. If we found
        rs = con.query "select * from cves where name='#{id}'"
        if rs.num_rows == 0
          cve_data[id] = {}
          cve_data[id]['link'] = site_url + "cve/" + id
          cve_data[id]['summary'] =  cve_summary_array[index]
          #TO DO determine proper use of date field
          pst = con.prepare "insert into cves(name, summary) values(?,?)"
          pst.execute id, cve_data[id]['summary']
        end
        # if our query returns results for the cve in question we skip
      end

    end

  end
end

if cve_data.count > 0
  # Build email template
  d = DateTime.now
  formated_cve_list = ''
  cve_data.each do | k, v |
    formated_cve_list = formated_cve_list + "\n" + "#{k} - #{cve_data[k]['link']}"
  end

message = "
From: CVE Discovery Script <root@localhost>
To: #{report_email}
Subject: CVE Report - #{d.strftime("%d/%m/%Y %H:%M")}

The following CVE's where found for the first time:
#{formated_cve_list}

Please advise"

  Net::SMTP.start('localhost') do |smtp|
    smtp.send_message message, 'root@localhost.com', report_email
  end
end
