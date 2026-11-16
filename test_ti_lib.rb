# frozen_string_literal: true
# Unit tests for logstash/ruby/ti_lib.rb using a tiny stand-in for LogStash::Event.
# Run:  ruby tests/test_ti_lib.rb     (needs only a stock Ruby >= 2.7)
require 'minitest/autorun'
require_relative '../logstash/ruby/ti_lib'

class FakeEvent
  def initialize(h = {})
    @data = {}
    h.each { |k, v| set(k, v) }
  end

  def to_h = @data

  def get(ref)
    path(ref).reduce(@data) { |m, k| m.is_a?(Hash) ? m[k] : nil }
  end

  def set(ref, value)
    keys = path(ref)
    last = keys.pop
    h = keys.reduce(@data) do |m, k|
      m[k] = {} unless m[k].is_a?(Hash)
      m[k]
    end
    h[last] = value
  end

  def path(ref) = ref.sub(/\A\[/, '').sub(/\]\z/, '').split('][')
end

class TILibTest < Minitest::Test
  def setup
    TI::CACHE.clear
    TI::FILE_CACHE.clear
    TI::BUDGET.clear
    %w[ABUSEIPDB_API_KEY OTX_API_KEY VT_API_KEY VT_PER_MINUTE VT_DAILY_LIMIT ABUSEIPDB_DAILY_LIMIT].each { |k| ENV.delete(k) }
  end

  def ev(ip, extra = {})
    FakeEvent.new({ '[source][ip]' => ip, '[event][action]' => 'cowrie.login.failed' }.merge(extra))
  end

  # ---- classification
  def test_public_ip_detection
    assert TI.public_ip?('8.8.8.8')
    assert TI.public_ip?('2606:4700:4700::1111')
    assert TI.public_ip?('::ffff:8.8.8.8')
    %w[10.1.2.3 172.20.0.5 192.168.65.1 127.0.0.1 169.254.1.1 100.64.0.9 203.0.113.7 fe80::1 ::1 not-an-ip].each do |ip|
      refute TI.public_ip?(ip), ip
    end
  end

  def test_classify_modes
    e = ev('8.8.8.8'); TI.classify(e)
    assert_equal 'live', e.get('[@metadata][ti_mode]')
    e = ev('172.20.0.1'); TI.classify(e)
    assert_equal 'skip', e.get('[@metadata][ti_mode]')
    assert_equal 'not_applicable', e.get('[ti][verdict]')
    e = ev('8.8.8.8', '[@metadata][simulated]' => 'true'); TI.classify(e)
    assert_equal 'demo', e.get('[@metadata][ti_mode]')
  end

  # ---- budget
  def test_budget_requires_key_and_limits
    e = ev('8.8.8.8'); TI.classify(e)
    TI.budget(e, 'abuse')
    assert_equal 'false', e.get('[@metadata][abuse_ok]')

    ENV['ABUSEIPDB_API_KEY'] = 'k'
    ENV['ABUSEIPDB_DAILY_LIMIT'] = '2'
    3.times.map { e2 = ev('8.8.8.8'); TI.budget(e2, 'abuse'); e2.get('[@metadata][abuse_ok]') }.tap do |r|
      assert_equal %w[true true false], r
    end
  end

  def test_vt_per_minute_limit_and_gate
    ENV['VT_API_KEY'] = 'k'
    ENV['VT_PER_MINUTE'] = '2'
    res = 3.times.map { e = ev('8.8.8.8'); TI.budget(e, 'vt'); e.get('[@metadata][vt_ok]') }
    assert_equal %w[true true false], res
    # gate: AbuseIPDB already cleared the IP (score 3 < 25) -> no VT spend
    TI::BUDGET.clear
    e = ev('8.8.8.8', '[@metadata][abuse_raw]' => { 'data' => { 'abuseConfidenceScore' => 3 } })
    TI.budget(e, 'vt')
    assert_equal 'false', e.get('[@metadata][vt_ok]')
    e = ev('8.8.8.8', '[@metadata][abuse_raw]' => { 'data' => { 'abuseConfidenceScore' => 80 } })
    TI.budget(e, 'vt')
    assert_equal 'true', e.get('[@metadata][vt_ok]')
  end

  # ---- merge / verdict
  ABUSE = { 'data' => { 'abuseConfidenceScore' => 92, 'totalReports' => 410, 'numDistinctUsers' => 55,
                        'usageType' => 'Data Center/Web Hosting/Transit', 'isp' => 'Evil Hosting', 'isTor' => false,
                        'isWhitelisted' => false, 'lastReportedAt' => '2026-11-12T10:00:00+00:00' } }.freeze
  OTX = { 'reputation' => 0,
          'pulse_info' => { 'count' => 3, 'pulses' => [
            { 'name' => 'Mirai C2 sweep', 'tags' => %w[mirai botnet], 'malware_families' => [{ 'display_name' => 'Mirai' }] },
            { 'name' => 'SSH brute', 'tags' => %w[ssh-bruteforce botnet], 'malware_families' => ['Gafgyt'] }
          ] } }.freeze
  VT = { 'data' => { 'attributes' => { 'reputation' => -12, 'as_owner' => 'Evil Hosting', 'country' => 'XX',
                                        'last_analysis_stats' => { 'malicious' => 7, 'suspicious' => 1, 'harmless' => 60, 'undetected' => 20 } } } }.freeze

  def test_merge_all_providers
    e = ev('8.8.8.8', '[@metadata][abuse_raw]' => ABUSE, '[@metadata][otx_raw]' => OTX, '[@metadata][vt_raw]' => VT)
    TI.classify(e)
    TI.merge(e)
    assert_equal 92, e.get('[ti][abuseipdb][confidence_score]')
    assert_equal %w[mirai botnet ssh-bruteforce], e.get('[ti][otx][tags]')
    assert_equal %w[Mirai Gafgyt], e.get('[ti][otx][malware_families]')
    assert_equal 7, e.get('[ti][virustotal][malicious]')
    assert_equal 'malicious', e.get('[ti][verdict]')
    assert_equal 92, e.get('[ti][score]')
    assert_equal %w[abuseipdb otx virustotal], e.get('[ti][providers]')
    # cached: second event for the same IP is answered locally
    e2 = ev('8.8.8.8'); TI.classify(e2); TI.cache_get(e2)
    assert_equal 'true', e2.get('[@metadata][ti_cache_hit]')
    assert_equal 'malicious', e2.get('[ti][verdict]')
  end

  # The http filter may hand us the response body as a raw JSON String instead of a Hash.
  def test_merge_accepts_raw_json_string_bodies
    require 'json'
    e = ev('8.8.8.8', '[@metadata][abuse_raw]' => JSON.generate(ABUSE),
                      '[@metadata][otx_raw]' => JSON.generate(OTX), '[@metadata][vt_raw]' => JSON.generate(VT))
    TI.classify(e)
    TI.merge(e)
    assert_equal 92, e.get('[ti][abuseipdb][confidence_score]')
    assert_equal 7, e.get('[ti][virustotal][malicious]')
    assert_equal %w[abuseipdb otx virustotal], e.get('[ti][providers]')
    assert_equal 'malicious', e.get('[ti][verdict]')
  end

  def test_vt_gate_reads_string_abuse_body
    ENV['VT_API_KEY'] = 'k'
    low = ev('8.8.8.8', '[@metadata][abuse_raw]' => '{"data":{"abuseConfidenceScore":3}}')
    TI.budget(low, 'vt')
    assert_equal 'false', low.get('[@metadata][vt_ok]'), 'clean IP must not spend a VirusTotal call'
    high = ev('1.1.1.1', '[@metadata][abuse_raw]' => '{"data":{"abuseConfidenceScore":80}}')
    TI.budget(high, 'vt')
    assert_equal 'true', high.get('[@metadata][vt_ok]')
  end

  def test_non_json_string_body_is_treated_as_no_data
    e = ev('8.8.8.8', '[@metadata][abuse_raw]' => '<html>502 Bad Gateway</html>')
    TI.classify(e)
    TI.merge(e)
    assert_equal 'unknown', e.get('[ti][verdict]')
  end

  def test_failed_lookup_is_negative_cached_as_unknown
    e = ev('8.8.4.4'); TI.classify(e); TI.merge(e)
    assert_equal 'unknown', e.get('[ti][verdict]')
    assert_equal [], e.get('[ti][providers]')
    assert_operator TI::CACHE['8.8.4.4'][:exp] - Time.now.to_f, :<=, 600
  end

  def test_benign_cdn_is_not_flagged
    abuse = { 'data' => { 'abuseConfidenceScore' => 90, 'usageType' => 'Content Delivery Network' } }
    e = ev('8.8.8.8', '[@metadata][abuse_raw]' => abuse); TI.merge(e)
    assert_equal 'benign', e.get('[ti][verdict]')
    e.set('[event][action]', 'cowrie.session.file_download'); TI.risk(e)
    assert_operator e.get('[event][risk_score]'), :<=, 20
  end

  def test_whitelisted_is_benign
    abuse = { 'data' => { 'abuseConfidenceScore' => 60, 'isWhitelisted' => true } }
    e = ev('8.8.8.8', '[@metadata][abuse_raw]' => abuse); TI.merge(e)
    assert_equal 'benign', e.get('[ti][verdict]')
  end

  def test_garbage_json_does_not_crash
    e = ev('8.8.8.8', '[@metadata][abuse_raw]' => { 'errors' => [{ 'detail' => 'rate limited' }] },
                      '[@metadata][otx_raw]' => 'oops', '[@metadata][vt_raw]' => { 'error' => { 'code' => 'QuotaExceededError' } })
    TI.merge(e)
    assert_equal 'unknown', e.get('[ti][verdict]')
  end

  # ---- demo
  def test_demo_is_deterministic_and_flagged
    a = ev('8.8.8.8'); TI.classify(a); TI.demo(a)
    b = ev('8.8.8.8'); TI.classify(b); TI.demo(b)
    assert_equal a.get('[ti][score]'), b.get('[ti][score]')
    assert_equal ['demo-synthetic'], a.get('[ti][providers]')
    assert_equal true, a.get('[ti][simulated]')
    scores = (1..200).map { |i| x = ev("77.1.#{i}.9"); TI.classify(x); TI.demo(x); x.get('[ti][verdict]') }.uniq
    assert_includes scores, 'malicious'
    assert_includes scores, 'clean'
  end

  # ---- file hashes
  def test_file_merge_and_cache
    sha = 'a' * 64
    raw = { 'data' => { 'attributes' => { 'type_description' => 'ELF', 'size' => 1234, 'names' => %w[bins.sh],
                                          'popular_threat_classification' => { 'suggested_threat_label' => 'trojan.mirai/gafgyt' },
                                          'last_analysis_stats' => { 'malicious' => 41, 'suspicious' => 0, 'undetected' => 25 } } } }
    e = ev('8.8.8.8', '[cowrie][shasum]' => sha, '[@metadata][vtfile_raw]' => raw)
    TI.file_merge(e)
    assert_equal 41, e.get('[ti][file][malicious]')
    assert_equal 'malicious', e.get('[ti][file][verdict]')
    e2 = ev('8.8.8.8', '[cowrie][shasum]' => sha); TI.file_cache_get(e2)
    assert_equal 'true', e2.get('[@metadata][file_cache_hit]')
    assert_equal 'trojan.mirai/gafgyt', e2.get('[ti][file][threat_label]')
  end

  def test_file_lookup_skips_bad_hash
    e = ev('8.8.8.8', '[cowrie][shasum]' => 'nothex'); TI.file_cache_get(e)
    assert_equal 'true', e.get('[@metadata][file_cache_hit]') # "hit" => no HTTP call attempted
  end

  # ---- risk formula
  def test_risk_formula_and_levels
    e = ev('8.8.8.8', '[event][action]' => 'cowrie.session.file_download', '[ti][score]' => 100, '[ti][verdict]' => 'malicious')
    TI.risk(e)
    assert_equal 94, e.get('[event][risk_score]') # 0.6*90 + 0.4*100
    assert_equal 'critical', e.get('[event][risk_level]')
    e = ev('8.8.8.8', '[event][action]' => 'cowrie.login.failed')
    TI.risk(e)
    assert_equal 15, e.get('[event][risk_score]') # 0.6*25 + 0
    assert_equal 'low', e.get('[event][risk_level]')
    e = ev('8.8.8.8', '[event][action]' => 'cowrie.login.success', '[ti][score]' => 90, '[ti][verdict]' => 'malicious')
    TI.risk(e)
    assert_equal 72, e.get('[event][risk_score]')
    assert_equal 'high', e.get('[event][risk_level]')
  end
end
