check for new cves
==================

This is a simple script to crawl product pages on www.cvedetails.com and check for new CVE's. This script will keep track of it's found CVE's in a database and will email only new results. This script is meant to be ran on a cronjob. 

## How To install
1. Unzip the document.
2. Setup the MySQL database. There's a schema included in the zip file. You'll need to create a MySQL user for the script to use. 
3. run `bundler install`
4. Configure the script:
    - set the mysql credentials
    - set the reporting email
    - if there are more products to check add their URL to the 'products_array' 
5. execute the script `ruby check-cves.rb`

