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

require "fluent/plugin/input"
require "fluent/plugin/aksk/signer"
require 'uri'
require 'cgi'
require 'json'

module Fluent
  module Plugin
    class SdnsApiListThreatDetailInput < Fluent::Plugin::Input
      attr_accessor :query_end_time, :query_start_time

      Fluent::Plugin.register_input("sdns_api", self)
      
      helpers :timer

      desc "Tag string"
      config_param :tag, :string, default: nil

      desc "Interval secends to pull SDNS API. default: 600"
      config_param :scrape_interval, :time, default: 600

      desc "SDNS API endpoint."
      config_param :endpoint, :string, default: ""

      desc "SDNS API params page_size. 20/50/100, default: 100"
      config_param :page_size, :integer, default: 100

      desc "SDNS API params client_ip: 资产ip地址"
      config_param :client_ip, :string, default: "" # 资产ip地址

      desc "SDNS API params security_zone_id: 安全域" # 安全域
      config_param :security_zone_id, :string, default: ""

      desc "SDNS API params domain: 域名" # 域名
      config_param :domain, :string, default: ""

      desc "SDNS API params threat_level: 威胁等级（low/middle/high/critical），默认值：所有" # 威胁等级
      config_param :threat_level, :array, default: [], value_type: :string

      desc "SDNS API key."
      config_param :access_key, :string, default: ""

      desc "SDNS API secret."
      config_param :access_secret, :string, default: ""
      
      def configure(conf)
        super
        if @access_key == ""
          raise Fluent::ConfigError, "access_key is required"
        end
        if @access_secret == ""
          raise Fluent::ConfigError, "access_secret is required"
        end
        if @endpoint == ""
          raise Fluent::ConfigError, "endpoint is required"
        end
        if @scrape_interval < 60
          raise Fluent::ConfigError, "scrape_interval must be greater than 60"
        end
        @query_start_time = (Time.now.to_i - @scrape_interval).to_i
        $log.info("sdns api query start time: #{@query_start_time}")
      end
      
      def start
        super
        # Startup code goes here!
        $log.info("sdns api start")
        # run inmediately
        refresh_watchers()
        timer_execute(:execute_sdns_api, @scrape_interval, &method(:refresh_watchers))
      end

      def get_full_url(start_time, end_time, cur_page)
        uri_parse = URI.parse(@endpoint)
        query = CGI.parse(uri_parse.query ? uri_parse.query : "")
        query["time_start"] = start_time
        query["time_end"] = end_time
        query["cur_page"] = cur_page
        query["page_size"] = @page_size
        query["domain"] = @domain if @domain != ""
        query["client_ip"] = @client_ip if @client_ip != ""
        query["security_zone_id"] = @security_zone_id if @security_zone_id != ""
        query["threat_level"] = @threat_level if @threat_level.length > 0

        uri_parse.query = URI.encode_www_form(query)
        uri_parse.to_s
      end

      def refresh_watchers
        begin
          cur_page = 1
          start_time = @query_start_time
          end_time = Time.now.to_i

          @query_start_time = end_time # set next query start time
          $log.debug("sdns api query time duration: #{start_time} - #{end_time}")
          full_url = get_full_url(start_time, end_time, cur_page)
          $log.debug("sdns api query: #{full_url}")
          res = get_sdns_api_data(full_url)
          if res.nil?
            return
          end
          $log.debug("sdns api query result: #{res['data']['total']}")
          send_msg(res['data']['items'])
          for cur_page in 2..res['data']['total_pages'] do
            full_url = get_full_url(start_time, end_time, cur_page)
            $log.debug("sdns api query: #{full_url}")
            res = get_sdns_api_data(full_url)
            if res.nil?
              return
            end
            # puts res['data']['cur_page']
            send_msg(res['data']['items'])
          end
        rescue => e
          $log.error(e.message)
        end
      end

      def send_msg(items)
        begin
          for item in items do
            record = {
              "query_timestamp" => item["query_timestamp"],
              "query_time_format" => item["query_time_format"],
              "security_zone_id" => item["security_zone_id"],
              "security_zone_name" => item["security_zone_name"],
              "client_ip" => item["client_ip"],
              "client_port" => item["client_port"],
              "domain" => item["domain"],
              "query_type"  => item["query_type"],
              "action" => item["action"],
              "threat_level" => item["threat_level"],
              "threat_type" => item["threat_type"],
              "event_id" => item["event_id"],
              "event_name" => item["event_name"],
              "event_description" => item["event_description"],
            }
            es = OneEventStream.new(Fluent::EventTime.now, record)
            router.emit_stream(@tag, es)
          end
        rescue => e
          $log.error(e.message)
        end
      end

      def get_sdns_api_data(full_url)
        begin
          sig = SdnsApiSinger::Signer.new
          sig.key = @access_key
          sig.secret = @access_secret

          r = SdnsApiSinger::HttpRequest.new("GET", full_url)
          r.headers = {"content-type" => "application/json"}
          r.body = ''
          sig.sign(r)
          uri = URI.parse("#{r.scheme}://#{r.host}#{r.uri}")
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = true if uri.scheme == 'https'
          request = Net::HTTP::Get.new(uri)
          request.initialize_http_header(r.headers)
          response = http.request(request)
          if response.code != "200"
            $log.error("sdns api query failed: #{response.code} #{response.message}")
            return
          end
          response_body_hash = JSON.parse(response.body)
          if response_body_hash["errno"] != 0
            $log.error("sdns api query failed: #{response_body_hash["errno"]} #{response_body_hash["errmsg"]}")
            return 
          end
          response_body_hash
        rescue => e
          $log.error(e.message)
        end
      end

      def shutdown
        super
      end
    end
  end
end
