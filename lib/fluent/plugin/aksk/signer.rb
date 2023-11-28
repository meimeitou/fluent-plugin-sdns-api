#
# Copyright 2023- yinqiwei
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'uri'
require 'net/http'
require 'openssl'
require 'base64'
require 'date'
require 'cgi'

module Fluent
  module Plugin
    module SdnsApiSinger
      Algorithm = "SDK-HMAC-SHA256"
      BasicDateFormat = "%Y%m%dT%H%M%SZ"
      HeaderXDate = "X-Sdk-Date"
      HeaderHost = "host"
      HeaderAuthorization = "Authorization"
      HeaderContentSha256 = "x-sdk-content-sha256"
      
      class HttpRequest
        attr_accessor :method, :scheme, :host, :uri, :query, :headers, :body

        def initialize(method = "", url = "", headers = nil, body = "")
          @method = method
          uri_parse=URI.parse(url)

          spl = url.split("://", 2)
          @scheme = 'http'
          if spl.length > 1
            @scheme = spl[0]
            url = spl[1]
          end
          @query = {}
          if uri_parse.query
            @query = CGI.parse(uri_parse.query)
          end
          @host = uri_parse.host
          @uri = uri_parse.path
          @headers = headers.nil? ? {} : headers.dup
          @body = body.encode('utf-8')
        end
      end

      class Signer
        attr_accessor :key, :secret

        def initialize
          @key = ""
          @secret = ""
        end

        def hmacsha256(key_byte, message)
          OpenSSL::HMAC.digest('sha256', key_byte, message)
        end

        def hex_encode_sha256_hash(data)
          Digest::SHA256.hexdigest(data)
        end

        def string_to_sign(canonical_request, t)
          bytes = hex_encode_sha256_hash(canonical_request)
          "#{Algorithm}\n#{t.strftime(BasicDateFormat)}\n#{bytes}"
        end

        def url_encode(s)
          CGI.escape(s).gsub('+', '%20')
        end

        def canonical_request(r, signed_headers)
          canonical_headers = canonical_headers(r, signed_headers)
          hexencode = find_header(r, HeaderContentSha256)
          if hexencode.nil?
            hexencode = hex_encode_sha256_hash(r.body)
          end
          "#{r.method.upcase}\n#{canonical_uri(r)}\n#{canonical_query_string(r)}\n#{canonical_headers}\n#{signed_headers.join(';')}\n#{hexencode}"
        end

        def canonical_uri(r)
          patterns = CGI.unescape(r.uri).split('/')
          uri = patterns.map { |v| url_encode(v) }
          url_path = uri.join('/')
          url_path += '/' unless url_path[-1] == '/'
          url_path
        end

        def canonical_query_string(r)
          keys = r.query.keys.sort
          keys.map do |key|
            k = url_encode(key)
            value = r.query[key]
            if value.is_a?(Array)
              value.sort.map { |v| "#{k}=#{url_encode(v.to_s)}" }
            else
              "#{k}=#{url_encode(value.to_s)}"
            end
          end.join('&')
        end

        def canonical_headers(r, signed_headers)
          a = []
          headers = {}
          r.headers.each do |key, value|
            key_encoded = key.downcase
            value_encoded = value.strip
            headers[key_encoded] = value_encoded
            r.headers[key] = value_encoded.encode('utf-8').force_encoding('iso-8859-1')
          end
          signed_headers.each { |key| a << "#{key}:#{headers[key]}" }
          "#{a.join("\n")}\n"
        end

        def canonical_headers(r, signed_headers)
          headers = r.headers.transform_keys(&:downcase)
          signed_headers.map { |key| "#{key}:#{headers[key]}" }.join("\n") + "\n"
        end

        def signed_headers(r)
          r.headers.keys.map(&:downcase).sort
        end

        def sign_string_to_sign(string_to_sign, signing_key)
          hm = hmacsha256(signing_key, string_to_sign)
          hm.unpack1('H*')
        end
  
        def auth_header_value(signature, app_key, signed_headers)
          "#{Algorithm} Access=#{app_key}, SignedHeaders=#{signed_headers.join(';')}, Signature=#{signature}"
        end

        def find_header(r, header)
          r.headers.each do |k, v|
            return v if k.downcase == header.downcase
          end
          nil
        end

        def verify(r, authorization)
          r.body = r.body.encode('UTF-8') if r.body.is_a?(String)
          header_time = find_header(r, HeaderXDate)
          return false if header_time.nil?

          t = DateTime.strptime(header_time, BasicDateFormat)
          signed_headers = signed_headers(r)
          canonical_request = canonical_request(r, signed_headers)
          string_to_sign = string_to_sign(canonical_request, t)
          authorization == sign_string_to_sign(string_to_sign, @secret)
        end

        def sign(r)
          r.body = r.body.encode('UTF-8') if r.body.is_a?(String)
          header_time = find_header(r, HeaderXDate)
          if header_time.nil?
            t = DateTime.now
            r.headers[HeaderXDate] = t.strftime(BasicDateFormat)
          else
            t = DateTime.strptime(header_time, BasicDateFormat)
          end

          unless r.headers.keys.any? { |key| key.downcase == 'host' }
            r.headers["host"] = r.host
          end
          signed_headers = signed_headers(r)
          canonical_request = canonical_request(r, signed_headers)
          string_to_sign = string_to_sign(canonical_request, t)
          signature = sign_string_to_sign(string_to_sign, @secret)
          auth_value = auth_header_value(signature, @key, signed_headers)
          r.headers[HeaderAuthorization] = auth_value
          r.headers["content-length"] = r.body.length.to_s
          query_string = canonical_query_string(r)
          r.uri += "?#{query_string}" unless query_string.empty?
        end
      end
    end
  end
end
