local brute = require "brute"
local creds = require "creds"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local url = require "url"

description = [[
Performs brute force password auditing against IBM WebSphere Console.

It uses the unpwdb and brute libraries to perform password guessing. Any successful guesses are stored using the
credentials library.

Websphere's default uri and form names:
* Default uri:<code>/ibm/console/logon.jsp?action=OK</code>
* Default uservar: <code>username</code>
* Default passvar: <code>passwd</code>
]]

---
-- @usage
-- nmap -sV --script http-websphere-console-brute
--   --script-args 'userdb=users.txt,passdb=passwds.txt,http-websphere-console-brute.hostname=domain.com,
--                  http-websphere-console-brute.threads=3,brute.firstonly=true' <target>
-- nmap -sV --script http-websphere-console-brute <target>
--
-- @output
-- PORT     STATE SERVICE  REASON  VERSION
-- 9080/tcp open  ssl/http syn-ack IBM WebSphere Application Server 8.0
-- | http-server-header: 
-- | Server:
-- |_  WebSphere Application Server/8.0
-- | http-websphere-console-brute: 
-- |   Accounts: No valid accounts found
-- |_  Statistics: Performed 9868 guesses in 450 seconds, average tps: 22
--
-- @args http-websphere-console-brute.uri Path to authentication script. Default: /ibm/console/logon.jsp?action=OK
-- @args http-websphere-console-brute.hostname Virtual Hostname Header
-- @args http-websphere-console-brute.uservar sets the http-variable name that holds the
--                                 username used to authenticate. Default: username
-- @args http-websphere-console-brute.passvar sets the http-variable name that holds the
--                                 password used to authenticate. Default: passwd
-- @args http-websphere-console-brute.threads sets the number of threads. Default: 3
--
-- Other useful arguments when using this script are:
-- * http.useragent = String - User Agent used in HTTP requests
-- * brute.firstonly = Boolean - Stop attack when the first credentials are found
-- * brute.mode = user/creds/pass - Username password iterator
-- * passdb = String - Path to password list
-- * userdb = String - Path to user list
--
--
-- Based on Paulino Calderon's websphere-console brute forcer
--

author = "Vlatko Kosturjak <kost@linux.hr>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


-- portrule = shortport.http
portrule = shortport.port_or_service({80, 443, 8080, 9044}, {"http", "https"})

local DEFAULT_WEBSPHERE_LOGIN_URI = "/ibm/console/j_security_check"
local DEFAULT_WEBSPHERE_CONSOLE_URI = "/ibm/console/logon.jsp?action=OK"
local DEFAULT_WEBSPHERE_USERVAR = "j_username"
local DEFAULT_WEBSPHERE_PASSVAR = "j_password"
local DEFAULT_THREAD_NUM = 3

---
--This class implements the Brute library (http://nmap.org/nsedoc/lib/brute.html)
---
Driver = {
  new = function(self, host, port, options)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = stdnse.get_script_args('http-websphere-console-brute.hostname') or host
    o.port = port
    o.uri = stdnse.get_script_args('http-websphere-console-brute.uri') or DEFAULT_WEBSPHERE_LOGIN_URI
    o.options = options
    return o
  end,

  connect = function( self )
    return true
  end,

  login = function( self, username, password )
    -- stdnse.debug2("HTTP POST %s:%d%s for %s:%s\n", stdnse.get_hostname(self.host), self.port.number, self.uri, username, password)
    stdnse.debug2("HTTP POST %s:%s for %s:%s\n", stdnse.get_hostname(self.host),  self.uri, username, password)
    local opts = { redirect_ok = false, no_cache = true, no_cache_body = true }
    local response = http.post( self.host, self.port, self.uri, opts, nil,
      { [self.options.uservar] = username, [self.options.passvar] = password,
      action = "Log in" } )

    local status = tonumber(response.status) or 0
    local rpath = response.header.location

    if rpath and rpath:match('logonError.jsp') then
      stdnse.debug2("%s:%s => REDIRECT loginError\n", username, password)
      return false, brute.Error:new( "Incorrect password" )
    end

    if status > 300 and status < 400 and rpath then
      stdnse.debug2("%s:%s => %d = REDIRECT to %s\n", username, password, status, rpath)
      local path = url.absolute(self.uri, rpath)
      response = http.get(self.host, self.port, path, opts)
      stdnse.debug2("%s:%s => REDIRECT BODY => %s\n", username, password, response.body)
    end

    if response.body == nil or response.body:match('Unable to login.') or response.body:match('Login failed.') 
      or response.body:match('Invalid User ID or password') then
        stdnse.debug2("%s:%s => FAIL\n", username, password)
        return false, brute.Error:new( "Incorrect password" )
    end
    stdnse.debug1("%s:%s:%d => Account found => %s\n", username, password, status, response.body)
    return true, creds.Account:new( username, password, creds.State.VALID)
  end,

  disconnect = function( self )
    return true
  end,

  check = function( self )
    local response = http.get( self.host, self.port, self.uri )
    -- stdnse.debug1("HTTP GET %s:%d%s", stdnse.get_hostname(self.host),self.port.number, self.uri)
    stdnse.debug1("HTTP GET %s:%s", stdnse.get_hostname(self.host),self.uri)
    -- Check if password field is there
    if ( response.status == 200 and response.body:match('[Tt][Yy][Pp][Ee]=[\'"]password[\'"]')) then
      stdnse.debug1("Initial check passed. Launching brute force attack")
      return true
    else
      stdnse.debug1("Initial check failed. Password field wasn't found")
    end
    return false
  end

}
---
--MAIN
---
action = function( host, port )
  local status, result, engine
  local uservar = stdnse.get_script_args('http-websphere-console-brute.uservar') or DEFAULT_WEBSPHERE_USERVAR
  local passvar = stdnse.get_script_args('http-websphere-console-brute.passvar') or DEFAULT_WEBSPHERE_PASSVAR
  local thread_num = stdnse.get_script_args("http-websphere-console-brute.threads") or DEFAULT_THREAD_NUM

  engine = brute.Engine:new( Driver, host, port, { uservar = uservar, passvar = passvar } )
  engine:setMaxThreads(thread_num)
  engine.options.script_name = SCRIPT_NAME
  status, result = engine:start()

  return result
end
