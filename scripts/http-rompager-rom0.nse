description = [[
This exploits /rom-0 information disclosure present in RomPager Embedded Web Server 
Affected devices include ZTE, TP-Link, ZynOS, Huawei and many others.
]]

---
-- @usage nmap -p80 --script http-rompager-rom0 <target>
-- @usage nmap -sV http-rompager-rom0 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-rompager-rom0: 
-- |   VULNERABLE:
-- |   /rom-0 information disclosure present in ZTE, TP-Link, ZynOS, Huawei
-- |     State: VULNERABLE (Exploitable)
-- |       Information disclosure present in RomPager Embedded Web Server.
-- |       Affected devices include ZTE, TP-Link, ZynOS, Huawei and many others.
-- |       ZTE, TP-Link, ZynOS, Huawei and possibly others are vulnerable to remote credential and information disclosure.
-- |       Attackers can query the URIs "/rom-0" to extract sensitive information.
-- |           
-- |     Disclosure date: 2014-01-11
-- |    
-- |     References:
-- |       https://dariusfreamon.wordpress.com/tag/rompager/
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=2014-4019
-- |       http://www.osvdb.org/show/osvdb/102668
-- |_      http://rootatnasro.wordpress.com/2014/01/11/how-i-saved-your-a-from-the-zynos-rom-0-attack-full-disclosure/
---

author = "Vlatko Kosturjak <kost@linux.hr>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"exploit","vuln"}

local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"
local vulns = require "vulns"
local stdnse = require "stdnse"

portrule = shortport.http

action = function(host, port)
  local vuln = {
    title = '/rom-0 information disclosure present in ZTE, TP-Link, ZynOS, Huawei',
    state = vulns.STATE.NOT_VULN,
    description = [[
Information disclosure present in RomPager Embedded Web Server.
Affected devices include ZTE, TP-Link, ZynOS, Huawei and many others.
ZTE, TP-Link, ZynOS, Huawei and possibly others are vulnerable to remote credential and information disclosure.
Attackers can query the URIs "/rom-0" to extract sensitive information.
    ]],
    references = {
      'https://dariusfreamon.wordpress.com/tag/rompager/',
      'http://rootatnasro.wordpress.com/2014/01/11/how-i-saved-your-a-from-the-zynos-rom-0-attack-full-disclosure/',
      'https://cve.mitre.org/cgi-bin/cvename.cgi?name=2014-4019',
      'http://www.osvdb.org/show/osvdb/102668'
    },
    dates = {
      disclosure = {year = '2014', month = '01', day = '11'},
    },
  }

  -- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
  local _, http_status, _ = http.identify_404(host,port)
  if ( http_status == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", host.ip, port.number)
    return false
  end

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local open_session = http.get(host.ip, port, "/rom-0")
  if open_session and open_session.status == 200 then
    if open_session.body:match("dbgarea") or open_session.body:match("spt.dat") or open_session.body:match("autoexec.net") then
      vuln.state = vulns.STATE.VULN
      return vuln_report:make_output(vuln)
    else
      vuln.state = vulns.STATE.LIKELY_VULN
      vuln.extra_info = "Correct HTTP (200) answer but uncorrect signature. Check manually!"
      return vuln_report:make_output(vuln)
    end
  end
end
