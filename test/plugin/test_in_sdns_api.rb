require "helper"
require "fluent/plugin/in_sdns_api.rb"

class SdnsApiListThreatDetailInputTest < Test::Unit::TestCase
  setup do
    Fluent::Test.setup
  end

  # Default configuration for tests
  CONFIG = %[
    client_ip '1.1.1.1'
    access_key 'xxx'
    endpoint 'https://xxx.net/apis/grpc/v2/ListThreatDetail'
    access_secret 'sdf'
  ]

  sub_test_case 'configured with configurations' do
    test 'param1 should reject too short string' do
      assert_raise Fluent::ConfigError do
        create_driver(%[
          param1 a
        ])
      end
    end

    test 'param is set correctly' do
      d = create_driver(CONFIG)
      assert_equal('', d.instance.domain)
      assert_not_nil(d.instance.endpoint)
      assert_not_nil(d.instance.query_start_time)
      # puts d.instance.get_full_url(d.instance.query_start_time, d.instance.query_end_time, 1)
    end
  end

  sub_test_case 'api watcher' do
    test 'get api data' do
      d = create_driver(%[
        access_key 'L2guCE9mRsuvUhNxUDKfgjKR083RqIFB'
        access_secret 'Vy4HrnHHZdewCkeQ9pHeiN6repMUgzjeoP2mqzMCVY2Hbne0k4jlKzZ10unYIKo5'
        endpoint 'https://xxx.net/apis/grpc/v2/ListThreatDetail'
        page_size 20
        scrape_interval 600
      ])
      assert_equal(600, d.instance.scrape_interval)
      start_time = d.instance.query_start_time
      end_time = Time.now.to_i
      full_url = d.instance.get_full_url(start_time, end_time , 1)
      res = d.instance.get_sdns_api_data(full_url)
      assert_not_nil(res)
    end
  end

  sub_test_case 'plugin will emit some events' do
    test 'test expects plugin emits events 4 times' do
      d = create_driver(%[
        access_key 'L2guCE9mRsuvUhNxUDKfgjKR083RqIFB'
        access_secret 'Vy4HrnHHZdewCkeQ9pHeiN6repMUgzjeoP2mqzMCVY2Hbne0k4jlKzZ10unYIKo5'
        endpoint 'https://xxx.net/apis/grpc/v2/ListThreatDetail'
        page_size 100
        scrape_interval 600
      ])

      # or 10 seconds lapse.
      # d.run(expect_emits: 4, timeout: 10)
      d.instance.refresh_watchers()

      # An array of `[tag, time, record]`
      puts d.events
      assert_not_nil(d.events)
    end
  end

  private

  def create_driver(conf)
    Fluent::Test::Driver::Input.new(Fluent::Plugin::SdnsApiListThreatDetailInput).configure(conf)
  end
end
