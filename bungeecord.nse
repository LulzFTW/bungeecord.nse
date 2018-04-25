local nmap = require "nmap"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects vulnerable BungeeCord backend servers.
]]

author = "lulz fukc the what"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "safe", "vuln"}

---
-- @output
-- PORT      STATE SERVICE
-- 25565/tcp open  minecraft
-- | bungeecord: 
-- |   status: BungeeCord backend detected
-- |   motd: A Minecraft Server
-- |   version: Spigot 1.10.2
-- |   players: 0/100
-- |_  address: 127.0.0.1:25565


portrule = shortport.port_or_service(25565, "minecraft")

action = function(host, port)
  local socket = nmap.new_socket()

  local status, result = pcall(function()
    local connection
    socket:set_timeout(2500)
    assert(socket:connect(host, port))
    connection = Connection:new(socket)
    handshake(connection, 47, 1)
    response = read_status(connection)
    socket:close()

    socket:set_timeout(2500)
    assert(socket:connect(host, port))
    connection = Connection:new(socket)
    handshake(connection, response.version.protocol, 2)

    if test_bungee(connection) then
      local result = stdnse.output_table()
      result.status = 'BungeeCord backend detected'
      result.motd = response.description.text or response.description
      result.version = response.version.name
      result.players = response.players.online .. '/' .. response.players.max
      result.address = host.ip .. ':' .. port.number
      return result
    end
  end)
  socket:close()

  if status then return result end
end

local BUNGEE_SIGNATURE = 'If you wish to use IP forwarding, please enable it in your BungeeCord config as well!'

function handshake(connection, version, state)
  local packet = PacketBuffer:new()
  packet:writevarint(0)
  packet:writevarint(version)
  packet:writestring('')
  packet:writeshort(0)
  packet:writevarint(state)
  connection:writebuffer(packet)
end

function read_status(connection)
  local request = PacketBuffer:new()
  request:writevarint(0)
  connection:writebuffer(request)

  local response = connection:readbuffer()
  if response:readvarint() ~= 0 then
    error('Received invalid status response packet.')
  end

  local raw = response:readstring()
  local _, val = assert(json.parse(raw))
  return val
end

function test_bungee(connection)
  local response = connection:readbuffer()
  if response:readvarint() ~= 0 then
    error('Received invalid disconnect packet.')
  end

  return string.match(response:readstring(), BUNGEE_SIGNATURE) ~= nil
end

PacketBuffer = {}

function PacketBuffer:new()
  local b = {_bytes = {}, _pos = 1}
  self.__index = self
  return setmetatable(b, self)
end

function PacketBuffer:read(length)
  local data = self:getbytes(self._pos, self._pos + length - 1)
  self._pos = self._pos + length
  return data
end

function PacketBuffer:write(data)
  for i = 1, #data do
    self._bytes[self._pos] = data:sub(i, i)
    self._pos = self._pos + 1
  end
end

function PacketBuffer:receive(data)
  local pos = #self._bytes
  for i = 1, #data do
    self._bytes[pos + i] = data:sub(i, i)
  end
end

function PacketBuffer:getbytes(index, length)
  return table.concat(self._bytes, "", index, length)
end

function PacketBuffer:remaining()
  return #self._bytes - self._pos + 1
end

function PacketBuffer:readvarint()
  local result, part = 0, 0
  for i = 0, 4 do
    part = string.byte(self:read(1))
    result = result | (part & 0x7F) << 7 * i
    if part & 0x80 == 0 then
      return result
    end
  end
  error('Server sent a varint that was too big!')
end

function PacketBuffer:writevarint(value)
  local remaining = value
  for i = 0, 4 do
    if remaining & ~0x7F == 0 then
      self:write(string.pack('>B', remaining))
      return
    end
    self:write(string.pack('>B', remaining & 0x7F | 0x80))
    remaining = remaining >> 7
  end
  error(string.format('The value %d is too big to send in a varint', value))
end

function PacketBuffer:readstring()
  local length = self:readvarint()
  return self:read(length)
end

function PacketBuffer:writestring(value)
  self:writevarint(#value)
  self:write(value)
end

function PacketBuffer:readshort()
  return string.unpack(">h", self:read(2))
end

function PacketBuffer:writeshort(value)
  self:write(string.pack(">h", value))
end

function PacketBuffer:readint()
  return string.unpack(">i", self:read(4))
end

function PacketBuffer:writeint(value)
  self:write(string.pack(">i", value))
end

function PacketBuffer:readlong()
  return string.unpack(">l", self:read(8))
end

function PacketBuffer:writelong(value)
  self:write(string.pack(">l", value))
end

function PacketBuffer:readbuffer()
  local length = self:readvarint()
  local result = PacketBuffer:new()
  result:receive(self:read(length))
  return result
end

function PacketBuffer:writebuffer(buffer)
  local data = buffer:getbytes()
  self:writevarint(#data)
  self:write(data)
end

Connection = PacketBuffer:new()

function Connection:new(socket)
  local c = PacketBuffer:new()
  c._socket = socket
  self.__index = self
  return setmetatable(c, self)
end

function Connection:read(length)
  local offset = length - self:remaining()
  if offset > 0 then
    local _, data = assert(self._socket:receive_bytes(offset))
    self:receive(data)
  end
  return PacketBuffer.read(self, length)
end

function Connection:write(data)
  assert(self._socket:send(data))
end
