const rules = [{"method":"POST","url":"^https://(?:get\\.shouji\\.sogou\\.com|sec\\.sginput\\.qq\\.com|worldwide\\.sogou\\.com)(?::443)?/q(?:\\?|$)","flags":"i","mime":"^\\s*application/(?:octet-stream|proto)\\s*(?:;.*)?$","mime_flags":"i"},{"method":"POST","url":"^https?://swc\\.pinyin\\.sogou\\.com(?::(?:80|443))?/swc(?:\\.php|/0)(?:\\?|$)","flags":"i"}];
const headers = $request.headers || {};
const keys = Object.keys(headers);
const blocked = rules.some(function(rule) {
  if ($request.method !== rule.method || !new RegExp(rule.url, rule.flags).test($request.url)) return false;
  if (!rule.mime) return true;
  if (keys.some(function(key) { return key.toLowerCase() === "s-cookie"; })) return false;
  const key = keys.find(function(key) { return key.toLowerCase() === "content-type"; });
  return key !== undefined && new RegExp(rule.mime, rule.mime_flags).test(headers[key]);
});
$done(blocked ? {response:{status:503,headers:{"Content-Length":"0"},body:""}} : {});
