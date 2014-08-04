local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

local l77feh = stdnse.silent_require "lantronix77feh"

description = [[
Attempts to get basic info and server status from a Lantronix devices.

For more information about 77FEh, see:

https://github.com/kost/lantronix-witchcraft
]]

---
-- @usage
-- nmap -p 30718 <ip> --script=lantronix-77feh-info
--
-- @output
-- PORT      STATE         SERVICE
-- 30718/udp open|filtered Lantronix77FEh
-- | lantronix-77feh-info: 
-- |   Version: 5.8.8.1
-- |   Device Type: X2D
-- |   MAC address: 0123456789ab
-- |_  Password: test (74657374)
--

-- version 0.1
-- Created 16/06/2014 - v0.1 - created by Vlatko Kosturjak <kost@linux.hr>

author = "Vlatko Kosturjak"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service(30718, "Lantronix77FEh", {"udp","tcp"})

function action(host,port)

  local socket = nmap.new_socket()

  -- set a reasonable timeout value
  socket:set_timeout(20000)
  -- do some exception  / cleanup
  local catch = function()
    socket:close()
  end

  local try = nmap.new_try(catch)

  try( socket:connect(host, port, port.protocol) )

  local results = {}

  local status, val = l77feh.get_version(socket)
  if (not(status)) then 
    stdnse.print_debug(3, "Error getting version: "..val)
  else
    table.insert(results, ("Version: %s"):format(val))
    port.version.name ='Lantronix77FEh'
    port.version.product=val
    port.version.name_confidence = 10
    nmap.set_port_version(host,port)
  end

  local status, val = l77feh.get_info(socket)
  if (not(status)) then 
    stdnse.print_debug(3, "Error getting info: "..val)
  else
    table.insert(results, ("Device Type: %s"):format(val["devtype"])) 
    table.insert(results, ("MAC address: %s"):format(stdnse.tohex(val["devmac"]))) 
  end

  local status, val = l77feh.get_password(socket)
  if (not(status)) then 
    stdnse.print_debug(3, "Error getting password: "..val)
  else
    local outputpass 
    if val == string.char(0x00,0x00,0x00,0x00) then
      outputpass = "(Disabled)"
    else
      outputpass = val.." ("..stdnse.tohex(val)..")"
    end
    table.insert(results, ("Password: %s"):format(outputpass)) 
  end

  return stdnse.format_output(true, results)
end
