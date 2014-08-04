---
-- Library methods for handling Lantronix 77FEh communication as client
--
-- @author Vlatko Kosturjak
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
--
-- Version 0.1
--

local bin = require "bin"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("lantronix77feh", stdnse.seeall)

--[[

  Lantronix 77FEh protocol implementation.

  For more information about 77FEh, see:

  https://github.com/kost/lantronix-witchcraft

]]--

-- Protocol magic strings
L77FEH_RCR = string.char(0x00,0x00,0x00,0xF4)
L77FEH_INF = string.char(0x00,0x00,0x00,0xF6)
L77FEH_SETUP = string.char(0x00,0x00,0x00,0xF8)

--@param socket to connect to
--@param pktcont packet content to send to server
--@param respsize to receive from server
--@return status : true if ok; false if bad
--@return result : received packet, error msg if bad
function send_pkt (socket,pktcont,respsize)
  stdnse.print_debug(9, "77feh sending: "..stdnse.tohex(pktcont))
  local status, err = socket:send(pktcont)
  if ( not(status) ) then
    stdnse.print_debug(3, "cannot send pktcont "..combo)
    return false, "Failed to connect to server"
  end

  local response
  status, response = socket:receive_bytes(respsize)
  stdnse.print_debug(9, "77feh received "..stdnse.tohex(response))
  if ( not(status) ) then
    stdnse.print_debug(3, "Receive packet for size of "..respsize)
    return false, err
  end

  return true, response
end

function send_rcr (socket) 
  local status, resp = send_pkt (socket, L77FEH_RCR, 32)
  local resppkt = string.sub(resp,1,4)
  if not (resppkt == string.char(0x00,0x00,0x00,0xF5)) then
    resp = "Response header not valid"
    stdnse.print_debug(3, resp)
    status = false
  end
  return status, resp
end

function send_inf (socket) 
  local status, resp = send_pkt (socket, L77FEH_INF, 30)
  local resppkt = string.sub(resp,1,4)
  if not (resppkt == string.char(0x00,0x00,0x00,0xF7)) then
    resp = "Response header not valid"
    stdnse.print_debug(3, resp)
    status = false
  end
  return status, resp
end

function send_setup (socket) 
  local status, resp = send_pkt (socket, L77FEH_SETUP, 124)
  local resppkt = string.sub(resp,1,4)
  if not (resppkt == string.char(0x00,0x00,0x00,0xF9)) then
    resp = "Response header not valid"
    stdnse.print_debug(3, resp)
    status = false
  end
  return status, resp
end

function get_version (socket)
  local status, val = send_rcr(socket)
  if (not(status)) then 
    return false, "Error getting version: "..val
  else
    local pos,ver = bin.unpack("z",val,17)
    return true, ver
  end
end

function get_info (socket)
  local status, val = send_inf(socket)
  if (not(status)) then 
    return false, "Error getting info: "..val
  else
    local resp = {}
    local pos,devtype = bin.unpack("A3",val,9)
    resp["devtype"] = devtype
    local pos,devmac = bin.unpack("A6",val,25)
    resp["devmac"] = devmac
    return true, resp
  end
end

function get_password (socket)
  local status, val = send_setup(socket)
  if (not(status)) then 
    return false, "Error getting password: "..val
  else
    local pos,simplepass = bin.unpack("A4",val,13)
    return true, simplepass
  end
end 

return _ENV;
