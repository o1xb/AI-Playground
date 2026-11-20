# OCSF mapper for Logstash's ruby filter. Same semantics as loggrouper/ocsf/mapping.py (apply_mapping);
# the conformance check compares the two on real samples.
#
#   ruby { path => "/etc/logstash/ocsf_mapper.rb" script_params => { "spec" => "<base64 JSON>" } }
require "json"
require "base64"
require "time"

NUM_RX = /\A[-+]?\d+(\.\d+)?([eE][-+]?\d+)?\z/
INT_RX = /\A[-+]?\d+\z/

def register(params)
  @spec = JSON.parse(Base64.decode64(params["spec"]))
end

IDX_RX = /\A(.+)\[(\d+)\]\z/

# dotted path; a segment may carry an array index: evidences[0].src_endpoint.ip
def lg_get(h, path)
  cur = h
  path.split(".").each do |k|
    m = IDX_RX.match(k)
    k = m[1] if m
    return nil unless cur.is_a?(Hash) && cur.key?(k)
    cur = cur[k]
    if m
      i = m[2].to_i
      return nil unless cur.is_a?(Array) && i < cur.length
      cur = cur[i]
    end
  end
  cur
end

def lg_set(h, path, v)
  ks = path.split(".")
  cur = h
  ks.each_with_index do |k, n|
    last = n == ks.length - 1
    m = IDX_RX.match(k)
    if m
      k = m[1]
      i = m[2].to_i
      cur[k] = [] unless cur[k].is_a?(Array)
      cur[k] << {} while cur[k].length <= i
      if last
        cur[k][i] = v
      else
        cur[k][i] = {} unless cur[k][i].is_a?(Hash)
        cur = cur[k][i]
      end
    elsif last
      cur[k] = v
    else
      cur[k] = {} unless cur[k].is_a?(Hash)
      cur = cur[k]
    end
  end
end

def lg_key(v)
  return (v ? "true" : "false") if v == true || v == false
  return JSON.generate(v) if v.is_a?(Hash) || v.is_a?(Array)
  if v.is_a?(Float)
    s = v.to_s
    return s
  end
  v.to_s
end

def lg_ts_ms(v)
  return nil if v.nil? || v == true || v == false
  if v.respond_to?(:time) && !v.is_a?(String)
    t = v.time
    return t.to_i * 1000 + t.usec / 1000
  end
  s = v.to_s.strip
  if s =~ INT_RX
    x = Integer(s, 10)
    return x * 1000 if x < 10**11
    return x if x < 10**14
    return x / 1000 if x < 10**17
    return x / 1000000
  end
  if s =~ NUM_RX
    x = Float(s)
    return x < 1e11 ? (x * 1000).to_i : x.to_i
  end
  # only ISO-8601-like strings, exactly what Python's datetime.fromisoformat accepts in the executor
  return nil unless s =~ /\A\d{4}-\d\d-\d\d([T ]\d\d:\d\d(:\d\d(\.\d+)?)?)?(Z|[+-]\d\d:?\d\d)?\z/
  begin
    t = Time.iso8601(s.sub(" ", "T") + (s =~ /(Z|[+-]\d\d:?\d\d)\z/ || s.length == 10 ? "" : "Z"))
  rescue ArgumentError
    return nil
  end
  t.to_i * 1000 + t.usec / 1000
end

def lg_cast(v, typ)
  return [true, v] if typ.nil?
  case typ
  when "integer"
    s = lg_key(v)
    return [false, nil] if v == true || v == false || s !~ NUM_RX
    return [true, s =~ INT_RX ? Integer(s, 10) : Float(s).to_i]
  when "float"
    s = lg_key(v)
    return [false, nil] if v == true || v == false || s !~ NUM_RX
    return [true, Float(s)]
  when "string" then return [true, lg_key(v)]
  when "boolean"
    s = lg_key(v).downcase
    return [true, true] if %w[true t yes y 1].include?(s)
    return [true, false] if %w[false f no n 0].include?(s)
    return [false, nil]
  when "lower" then return [true, lg_key(v).downcase]
  when "upper" then return [true, lg_key(v).upcase]
  when "timestamp_ms"
    x = lg_ts_ms(v)
    return [!x.nil?, x]
  end
  [false, nil]
end

def lg_remove(h, parts)
  if parts.length == 1
    h.delete(parts[0])
    return
  end
  sub = h[parts[0]]
  if sub.is_a?(Hash)
    lg_remove(sub, parts[1..-1])
    h.delete(parts[0]) if sub.empty?
  end
end

def lg_plain(x)
  # deep copy with Logstash Timestamp objects rendered as ISO-8601 strings (the Python executor's form)
  if x.is_a?(Hash)
    h = {}
    x.each { |k, v| h[k] = lg_plain(v) }
    h
  elsif x.is_a?(Array)
    x.map { |v| lg_plain(v) }
  elsif !x.is_a?(String) && x.respond_to?(:time)
    x.to_s
  else
    x
  end
end

def lg_empty?(x)
  x.nil? || x == "" || x == [] || x == {}
end

def filter(event)
  # @timestamp counts only when the parser set it from the log (date step succeeded), as in the Python executor
  ts = event.get("[@metadata][lg_ts]") ? event.get("[@timestamp]") : nil
  ev = { "vendor" => lg_plain(event.get("[vendor]")), "message" => event.get("[message]"), "@timestamp" => ts }
  out = {}
  used = []
  @spec["fields"].each do |f|
    v = nil
    if f.key?("value")
      v = f["value"]
    else
      srcs = f["from"].is_a?(Array) ? f["from"] : [f["from"]]
      skip = f.key?("skip_values") ? f["skip_values"] : @spec["default_skip"]
      srcs.each do |s|
        x = s == "@timestamp" ? ev["@timestamp"] : lg_get(ev, s)
        unless lg_empty?(x) || skip.include?(lg_key(x))
          v = x
          used << s
          break
        end
      end
    end
    if v.nil?
      next unless f.key?("default")
      v = f["default"]
    elsif f.key?("map")
      m = f["map"]
      k = lg_key(v)
      lower = {}
      m.keys.each { |a| lower[a.downcase] = a }
      if m.key?(k)
        v = m[k]
      elsif lower.key?(k.downcase)
        v = m[lower[k.downcase]]
      elsif f.key?("default")
        v = f["default"]
      else
        next
      end
    end
    ok, v = lg_cast(v, f["type"])
    next unless ok
    lg_set(out, f["to"], v)
  end
  c = @spec["_class"]
  out["class_uid"] = c["uid"]
  out["category_uid"] = c["category_uid"]
  out["activity_id"] = 0 unless out.key?("activity_id")
  out["severity_id"] = 0 unless out.key?("severity_id")
  out["type_uid"] = out["activity_id"].is_a?(Integer) ? c["uid"] * 100 + out["activity_id"] : nil
  if !out.key?("time") && !ev["@timestamp"].nil?
    t = lg_ts_ms(ev["@timestamp"])
    out["time"] = t unless t.nil?
  end
  lg_set(out, "metadata.version", @spec["_version"])
  out["class_name"] = c["caption"]
  out["category_name"] = c["category_caption"]
  act_caps = {}
  @spec["_siblings"].each do |id_path, name_path, caps|
    act_caps = caps if id_path == "activity_id"
    idv = lg_get(out, id_path)
    if !idv.nil? && lg_get(out, name_path).nil? && caps.key?(idv.to_s)
      lg_set(out, name_path, caps[idv.to_s])
    end
  end
  act = act_caps[out["activity_id"].to_s]
  out["type_name"] = "#{c['caption']}: #{act}" if act
  if @spec["raw_data"] && ev["message"].is_a?(String) && !out.key?("raw_data")
    out["raw_data"] = ev["message"]
  end
  if @spec["unmapped"] && ev["vendor"].is_a?(Hash)
    rest = lg_plain(ev["vendor"])
    used.each { |s| lg_remove(rest, s.split(".")[1..-1]) if s.start_with?("vendor.") }
    out["unmapped"] = rest unless rest.empty?
  end
  event.remove("[vendor]")
  event.remove("[message]")
  out.each { |k, v| event.set("[#{k}]", v) }
  [event]
end
