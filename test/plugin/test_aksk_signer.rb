require "helper"
require "fluent/plugin/aksk/signer.rb"
require 'net/http'
require 'resolv-replace'
require 'uri'

class SdnsApiSignerTest < Test::Unit::TestCase

  def test_sdns_api_signer
    sig = Fluent::Plugin::SdnsApiSinger::Signer.new
    sig.key = "Fad3mbhh9NwadtEd7t0ekFp5HwrNJiDc" # test key
    sig.secret = "5MLR15LYGn8IeTHQwPs7tZyJslGqNZmYI6g8eHETGrWZYZ6J7U9Ak8CrRlSyCEMT"

    r = Fluent::Plugin::SdnsApiSinger::HttpRequest.new("GET", "https://xxx.net/apis/grpc/v2/ListThreatDetail")
    r.headers = {"content-type" => "application/json"}

    r.body = ''
    sig.sign(r)
    puts r.headers["X-Sdk-Date"]
    puts r.headers["Authorization"]

    uri = URI.parse("#{r.scheme}://#{r.host}#{r.uri}")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true if uri.scheme == 'https'
    request = Net::HTTP::Get.new(uri)
    request.initialize_http_header(r.headers)
    response = http.request(request)
    assert response.code == "200"
  end
end
