#!/opt/chef/embedded/bin/ruby
require 'rubygems'
require 'base64'
require 'time'
require 'digest/sha1'
require 'openssl'
require 'net/https'
require 'json'

class ChefAPI

  attr_accessor :http

  attr_accessor :path

  attr_accessor :client_name

  attr_accessor :key_file

  def initialize(opts={})
    server            = opts[:server]
    port              = opts.fetch(:port, 443)
    use_ssl           = opts.fetch(:use_ssl, true)
    ssl_insecure      = opts[:ssl_insecure] ? OpenSSL::SSL::VERIFY_NONE : OpenSSL::SSL::VERIFY_PEER
    @client_name      = opts[:client_name]
    @key_file         = opts[:key_file]

    @http             = Net::HTTP.new(server, port)
    @http.use_ssl     = use_ssl
    @http.verify_mode = ssl_insecure
  end

  def get_request(req_path)
    @path = req_path

    begin
      request  = Net::HTTP::Get.new(path, headers)
      response = http.request(request)
      return response.body;
    rescue OpenSSL::SSL::SSLError => e
      raise "SSL error: #{e.message}."
    end
  end

  def post_request(path,data)

        begin
         request = Net::HTTP::Post.new(path, headers)
         request.set_form_data(data)
         res = Net::HTTP.start(uri.hostname, uri.port) do |http|
                http.request(request)
         end
         return request.body;
        rescue OpenSSL::SSL::SSLError => e
         raise "SSL error: #{e.message}."
        end
  end

  def put_request(path,data)

        begin
                request = Net::HTTP::Put.new(path, headers)
                data.keys.each do |key|
                        request[key] = data[key]
                end
                http.request(request)
                return request.body;
        rescue  OpenSSL::SSL::SSLError => e
                raise "SSL error: #{e.message}."
        end

  end

  private

  def encode(string)
    ::Base64.encode64(Digest::SHA1.digest(string)).chomp
  end

  def headers
    body      = ""
    timestamp = Time.now.utc.iso8601
    key       = OpenSSL::PKey::RSA.new(File.read(key_file))
    canonical = "Method:GET\nHashed Path:#{encode(path)}\nX-Ops-Content-Hash:#{encode(body)}\nX-Ops-Timestamp:#{timestamp}\nX-Ops-UserId:#{client_name}"

    header_hash = {
      'Accept'             => 'application/json',
      'X-Ops-Sign'         => 'version=1.0',
      'X-Ops-Userid'       => client_name,
      'X-Ops-Timestamp'    => timestamp,
      'X-Chef-Version'     => '0.10.4',
      'X-Ops-Content-Hash' => encode(body)
    }

    signature = Base64.encode64(key.private_encrypt(canonical))
    signature_lines = signature.split(/\n/)
    signature_lines.each_index do |idx|
      key = "X-Ops-Authorization-#{idx + 1}"
      header_hash[key] = signature_lines[idx]
    end

    header_hash
 end

end


api=ChefAPI.new({:server => "#{ARGV[0]}", :port => "443", :use_ssl => true, :ssl_insecure => "OpenSSL::SSL::VERIFY_NONE", :client_name => 'akhilesh0',  :key_file => ARGV[1]  })
nodes=JSON.parse(api.get_request("/organizations/akhilesh0/nodes")).keys;
puts "<project>"
nodes.each do |node|
    node_details=JSON.parse(api.get_request("/organizations/akhilesh0/nodes/#{node}"));
    environment=""
    tags=node_details['normal']['tags'][0]
    ip_address = node_details['automatic']['ipaddress']
    begin
puts  "#<node name=\"#{node}\" description=\"Rundeck server node\" tags = \"#{tags}\" hostname=\"#{node_details['automatic']['ipaddress']}\" osArch=\"#{node_details['automatic']['kernel']['machine']}\" osFamily=\"#{node_details['automatic']['platform']} #{node_details['automatic']['platform_version']}\" osName=\"#{node_details['automatic']['os']}\" osVersion=\"#{node_details['automatic']['os_version']}\" username=\"root\"/> ";

   rescue
        next;
   end

end
puts "</project>"
