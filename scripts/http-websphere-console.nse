description = [[
This script identifies IBM Websphere consoles.
]]

---
-- @usage
-- nmap -sV --script http-websphere-console <target>
--
-- @output
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- | http-websphere-console: 
-- |   consoles: 
-- |_    WebSphere at /console/portal/0/Welcome
---

author = "Vlatko Kosturjak <kost@linux.hr>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","default"}

local http = require "http"
local shortport = require "shortport"
local string = require "string"
local stdnse = require "stdnse"

portrule = shortport.port_or_service({80, 443, 8080, 9044}, {"http", "https", "tcp", "open"})

action = function(host, port)
  local consoleurls = { "/ibm/console/logon.jsp?action=OK", "/console/", "/console/portal/0/Welcome" } 
  local output = stdnse.output_table()
  output.consoles = {}

  for i,url in ipairs(consoleurls) do
    stdnse.debug2("[websphere] Getting URL: "..url)
    local response = http.get(host, port, url, { no_cache = true, redirect_ok = 3 })

    if ( response.status == 200 ) then
      if (response.body:match("[Ww][Ee][Bb][Ss][Pp][Hh][Ee][Rr][Ee]") ) then
        table.insert(output.consoles,"WebSphere at "..url)
      elseif (response.body:match("WSC Console Federation") ) then
        table.insert(output.consoles,"WSC at "..url)
      else
        table.insert(output.consoles,"Unknown at "..url)
      end
    end
  end

  -- empty table, no consoles were found
  if next(output.consoles) == nil then
    return
  end 
  -- return all consoles found
  return output
end
