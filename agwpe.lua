-- =============================================================================
-- Copyright (c) 2025 Martin F N Cooper
--
-- Author: Martin F N Cooper
-- License: MIT License
--
-- Version: 1.0.0
-- =============================================================================

--[[
    AGWPE Dissector for Wireshark

    A comprehensive dissector that shows the AGWPE header fields, and also the
    associated data where present.

    Preferences:

    * Server port (default: 8000)
      This is used to determine whether a frame is a request or response, which
      in turn allows correct interpretation of the data kind field. This must
      be set correctly for the dissector to work properly.

    * Strict validation (default: true)
      When true, the reserved fields of a possible header are checked for
      compliance with the AGWPE spec before dissecting and showing the header.
      When false, reserved fields are ignored, which can be useful when working
      with a non-compliant client or server. However, it can also lead to false
      positives and incorrect identification of AGWPE frames.

    * Show reserved fields (default: false)
      When true, every field in a header is shown, including the reserved
      fields, which should always be zeroed out per the AGWPE spec. This can
      be useful when Strict validation is disabled in order to examine the
      details of a non-compliant header.
]]

local PROTOCOL_NAME = "AGWPE"
local PROTOCOL_DESC = "AGWPE Protocol"
local FILTER_PREFIX = "agwpe."
local HEADER_LEN = 36

local DATAKIND_FROM_CLIENT = {
    P = "Application Login",
    X = "Register CallSign",
    x = "Unregister CallSign",
    G = "Ask Port Information",
    m = "Enable Reception of Monitoring Frames",
    R = "AGWPE Version Info",
    g = "Ask Port Capabilities",
    H = "Callsign Heard on a Port",
    y = "Ask Outstanding frames waiting on a Port",
    Y = "Ask Outstanding frames waiting for a connection",
    M = "Send UNPROTO Information",
    C = "Connect, Start an AX.25 Connection",
    D = "Send Connected Data",
    d = "Disconnect, Terminate an AX.25 Connection",
    v = "Connect VIA, Start an AX.25 circuit thru digipeaters",
    V = "Send UNPROTO VIA",
    c = "Non-Standard Connections, Connection with PID",
    K = "Send Data in 'raw' AX.25 format",
    k = "Activate reception of Frames in 'raw' format"
}

local DATAKIND_FROM_SERVER = {
    R = "Version Number",
    X = "Callsign Registration",
    G = "Port Information",
    g = "Capabilities of a Port",
    y = "Frames Outstanding on a Port",
    Y = "Frames Outstanding on a Connection",
    H = "Heard Stations on a Port",
    C = "AX.25 Connection Received",
    D = "Connected AX.25 Data",
    d = "Disconnect Completed",
    I = "Monitored Connected Information",
    S = "Monitored Supervisory Information",
    U = "Monitored Unproto Information",
    T = "Monitoring Own Information",
    K = "Monitored Information in Raw Format"
}

local FIELDS = {
    --
    -- Generated direction field
    --
    frametype = ProtoField.string(FILTER_PREFIX .. "frametype",
        "Frame Type", base.ASCII),
    --
    -- Header fields
    --
    port = ProtoField.uint8(FILTER_PREFIX .. "port",
        "AGWPE Port", base.DEC),
    reserved_1 = ProtoField.bytes(FILTER_PREFIX .. "reserved_1",
        "Reserved 1", base.SPACE),
    datakind = ProtoField.string(FILTER_PREFIX .. "kind",
        "DataKind", base.ASCII),
    reserved_2 = ProtoField.uint8(FILTER_PREFIX .. "reserved_2",
        "Reserved 2", base.HEX),
    pid = ProtoField.uint8(FILTER_PREFIX .. "pid",
        "Protocol ID", base.HEX),
    reserved_3 = ProtoField.uint8(FILTER_PREFIX .. "reserved_3",
        "Reserved 3", base.HEX),
    callfrom = ProtoField.string(FILTER_PREFIX .. "callfrom",
        "Call From", base.ASCII),
    callto = ProtoField.string(FILTER_PREFIX .. "callto",
        "Call To", base.ASCII),
    datalen = ProtoField.uint32(FILTER_PREFIX .. "datalen",
        "Data Length", base.DEC),
    reserved_user = ProtoField.uint32(FILTER_PREFIX .. "reserved_user",
        "Reserved User", base.DEC),
    --
    -- Data fields
    --
    -- Application login
    userid = ProtoField.stringz(FILTER_PREFIX .. "userid",
        "User Id", base.ASCII),
    password = ProtoField.stringz(FILTER_PREFIX .. "password",
        "Password", base.ASCII),
    -- Version information
    version_major = ProtoField.uint16(FILTER_PREFIX .. "version_major",
        "Major Version", base.DEC),
    version_minor = ProtoField.uint16(FILTER_PREFIX .. "version_minor",
        "Minor Version", base.DEC),
    -- Callsign registration
    callsign_registered = ProtoField.uint8(FILTER_PREFIX .. "registered",
        "Registered", base.DEC, {[0] = "False", [1] = "True"}),
    -- Port information
    port_count = ProtoField.uint16(FILTER_PREFIX .. "port_count",
        "Port Count", base.DEC),
    port_name = ProtoField.string(FILTER_PREFIX .. "port_name",
        "Port Name", base.UNICODE),
    -- Port capabilities
    pc_baud_rate = ProtoField.uint8(FILTER_PREFIX .. "baud_rate",
        "Baud Rate", base.DEC,
        {[0] = "1200", [1] = "2400", [2] = "4800", [3] = "9600"}),
    pc_traffic_level = ProtoField.uint8(FILTER_PREFIX .. "traffic_level",
        "Traffic Level", base.HEX),
    pc_tx_delay = ProtoField.uint16(FILTER_PREFIX .. "tx_delay",
        "TX Delay", base.DEC),
    pc_tx_tail = ProtoField.uint16(FILTER_PREFIX .. "tx_tail",
        "TX Tail", base.DEC),
    pc_persist = ProtoField.uint16(FILTER_PREFIX .. "persist",
        "Persist", base.DEC),
    pc_slot_time = ProtoField.uint16(FILTER_PREFIX .. "slot_time",
        "Slot Time", base.DEC),
    pc_max_frame = ProtoField.uint16(FILTER_PREFIX .. "max_frame",
        "Max Frame", base.DEC),
    pc_active_conns = ProtoField.uint16(FILTER_PREFIX .. "active_conns",
        "Active Connections", base.DEC),
    pc_bytes_recd = ProtoField.uint32(FILTER_PREFIX .. "bytes_received",
        "Bytes Received", base.DEC),
    -- Outstanding frames
    frames_on_port = ProtoField.uint32(FILTER_PREFIX .. "frames_on_port",
        "Frames Outstanding on Port", base.DEC),
    frames_on_conn = ProtoField.uint32(FILTER_PREFIX .. "frames_on_conn",
        "Frames Outstanding on Connection", base.DEC),
    -- Heard calls
    heard_text = ProtoField.stringz(FILTER_PREFIX .. "heard_text",
        "Heard Text", base.ASCII),
    heard_first = ProtoField.string(FILTER_PREFIX .. "heard_first",
        "First Heard", base.ASCII),
    heard_last = ProtoField.string(FILTER_PREFIX .. "heard_last",
        "Last Heard", base.ASCII),
    -- Unproto data
    unproto_data = ProtoField.string(FILTER_PREFIX .. "unproto_data",
        "Unproto Data", base.UNICODE),
    -- Connections
    conn_message = ProtoField.stringz(FILTER_PREFIX .. "connection_message",
        "Connection Message", base.ASCII),
    disconn_message = ProtoField.stringz(
        FILTER_PREFIX .. "disconnection_message",
        "Disconnection Message", base.ASCII),
    conn_data = ProtoField.string(FILTER_PREFIX .. "connected_data",
        "Connected Data", base.UNICODE),
    -- Vias
    via_count = ProtoField.uint8(FILTER_PREFIX .. "via_count",
        "Number of Vias", base.DEC),
    via1 = ProtoField.stringz(FILTER_PREFIX .. "var1", "Via 1", base.ASCII),
    via2 = ProtoField.stringz(FILTER_PREFIX .. "var2", "Via 2", base.ASCII),
    via3 = ProtoField.stringz(FILTER_PREFIX .. "var3", "Via 3", base.ASCII),
    via4 = ProtoField.stringz(FILTER_PREFIX .. "var4", "Via 4", base.ASCII),
    via5 = ProtoField.stringz(FILTER_PREFIX .. "var5", "Via 5", base.ASCII),
    via6 = ProtoField.stringz(FILTER_PREFIX .. "var6", "Via 6", base.ASCII),
    via7 = ProtoField.stringz(FILTER_PREFIX .. "var7", "Via 7", base.ASCII),
    -- Monitoring text and data
    text_data = ProtoField.string(FILTER_PREFIX .. "text_data",
        "Text", base.UNICODE),
    binary_data = ProtoField.bytes(FILTER_PREFIX .. "binary_data",
        "Binary", base.SPACE),
    -- Raw data
    tnc_port = ProtoField.uint8(FILTER_PREFIX .. "tnc_port",
        "TNC Port", base.DEC)
}

-- Monitoring frames from the server have two parts, first text and then some
-- binary data. Here we split the buffer content into its constituent parts.
local function split_buffer(buffer)
    local s = buffer:string()
    local ix = s:find('\r')
    if ix == nil then
        return nil, buffer(0)
    end
    local text = s:sub(1, ix)
    local remaining = buffer:len() - ix
    if remaining <= 0 then
        return buffer(0), nil
    end
    local length
    _, _, length = text:find(" Len=(%d+)")
    if length == nil or length > remaining then
        return buffer(0, ix), buffer(ix)
    else
        return buffer(0, ix), buffer(ix, length)
    end
end

-- After splitting the buffer, we add the relevant parts to the tree. Note that
-- either part may be empty.
local function add_split_data(tree, buffer)
    text, binary = split_buffer(buffer)
    if text ~= nil then
        tree:add(FIELDS.text_data, text)
    end
    if binary ~= nil then
        tree:add(FIELDS.binary_data, binary)
    end
end

-- Dealing with the presentation of vias is handled slightly differently only
-- because there may be up to 7 of them, and we don't want to repeat ourselves.
local function add_vias(tree, buffer)
    local count = buffer(0, 1):uint()
    if count > 7 then
        count = 7
    end
    if buffer:len() < (1 + count * 10) then
        count = math.floor((buffer:len() - 1) / 10)
    end
    tree:add(FIELDS.via_count, buffer(0, 1))
    local offset = 1
    for ix = 1, count do
        local via_id = "via" .. ix
        tree:add(FIELDS[via_id], buffer(offset, 10))
        offset = offset + 10
    end
end

-- Parse the port info string into a count and the port names. The elements of
-- the string are separated by semicolons, but the string also ends with one.
local function add_port_info(tree, buffer)
    local text = buffer(0, header.datalen):stringz()
    local iter = string.gmatch(text, "([^;]+)")

    local count = iter()
    tree:add(FIELDS.port_count, tonumber(count))

    local buffer_pos = count:len() + 1
    for port in iter do
        port_len = port:len()
        if port_len > 0 then
            tree:add(FIELDS.port_name, buffer(buffer_pos, port_len))
        end
        buffer_pos = buffer_pos + port_len + 1
    end
end

-- The binary portion of the timestamp in a heard call, if present, uses the
-- Windows SYSTEMTIME structure. Here we break that apart and format is (but
-- ignoring the weekday).
local function format_systemtime(buffer)
    return string.format("%04d-%02d-%02d %02d:%02d:%02d",
        buffer(0, 2):le_uint(), buffer(2, 2):le_uint(),
        buffer(6, 2):le_uint(), buffer(8, 2):le_uint(),
        buffer(10, 2):le_uint(), buffer(12, 2):le_uint())
end

-- Each heard call record consists of either one or three parts. If one, there
-- is only text. If three, there is text along with two time structures, one
-- for first heard and the other for last heard.
--
-- The AGWPE spec says that all parts are always there. However, versions of
-- ldsped earlier than 1.19 have the text part but not timestamps. Further,
-- AGWPE itself inserts null padding before the timestamps, so we have to look
-- for it in the buffer. Direwolf does not currently implement heard calls.
local function add_heard_calls(tree, buffer, header)
    local ST_LEN = 16
    local EXPECTED_LEN = 2 * ST_LEN
    local text_len = buffer:strsize()

    tree:add(FIELDS.heard_text, buffer(0, text_len))

    local remaining = header.datalen - text_len
    if remaining < EXPECTED_LEN then
        return
    end
    local offset
    if remaining == EXPECTED_LEN then
        -- Case 1: data has expected length for 2 SYSTEMTIME instances
        offset = 0
    else
        -- Case 2: padding somewhere
        -- Case 2a: data at end, leading nulls, per AGWPE (but not spec)
        offset = remaining - EXPECTED_LEN
        local year1 = buffer(offset, 2):uint()
        local year2 = buffer(offset + ST_LEN, 2):uint()
        if not(year1 > 2000 and year1 < 2200
                and year2 > 2000 and year2 < 2200) then
            -- Case 2b: data at beginning, random padding at end
            offset = 0
            year1 = buffer(offset, 2):uint()
            year2 = buffer(offset + ST_LEN, 2):uint()
            if not(year1 > 2000 and year1 < 2200
                    and year2 > 2000 and year2 < 2200) then
                -- Out of luck - no valid timestamp data
                offset = nil
            end
        end
    end
    if offset ~= nil then
      tree:add(FIELDS.heard_first,
        format_systemtime(buffer(text_len + offset, ST_LEN)))
      tree:add(FIELDS.heard_last,
        format_systemtime(buffer(text_len + offset + ST_LEN, ST_LEN)))
    end
end

local REQUEST_FNS = {
    P = function(tree, buffer, header, pinfo)
            tree:add(FIELDS.userid, buffer(0, 255))
            tree:add(FIELDS.password, buffer(255, 255))
        end,
    M = function(tree, buffer, header, pinfo)
            if header.pid == 0xF0 then
                tree:add(FIELDS.unproto_data, buffer(0, header.datalen))
            end
        end,
    D = function(tree, buffer, header, pinfo)
            if header.pid == 0xF0 then
                tree:add(FIELDS.conn_data, buffer(0, header.datalen))
            end
        end,
    v = function(tree, buffer, header, pinfo)
            add_vias(tree, buffer)
        end,
    V = function(tree, buffer, header, pinfo)
            add_vias(tree, buffer)
        end,
    K = function(tree, buffer, header, pinfo)
            tree:add(FIELDS.tnc_port, buffer(0, 1))
			Dissector.get("ax25"):call( buffer(1):tvb(), pinfo, tree)
        end
}

local RESPONSE_FNS = {
    R = function(tree, buffer, header, pinfo)
            tree:add_le(FIELDS.version_major, buffer(0, 2))
            tree:add_le(FIELDS.version_major, buffer(4, 2))
        end,
    X = function(tree, buffer, header, pinfo)
            tree:add(FIELDS.callsign_registered, buffer(0, 1))
        end,
    G = function(tree, buffer, header, pinfo)
            add_port_info(tree, buffer)
        end,
    g = function(tree, buffer, header, pinfo)
            tree:add(FIELDS.pc_baud_rate, buffer(0, 1))
            tree:add(FIELDS.pc_traffic_level, buffer(1, 1))
            tree:add(FIELDS.pc_tx_delay, buffer(2, 1))
            tree:add(FIELDS.pc_tx_tail, buffer(3, 1))
            tree:add(FIELDS.pc_persist, buffer(4, 1))
            tree:add(FIELDS.pc_slot_time, buffer(5, 1))
            tree:add(FIELDS.pc_max_frame, buffer(6, 1))
            tree:add(FIELDS.pc_active_conns, buffer(7, 1))
            tree:add_le(FIELDS.pc_bytes_recd, buffer(8, 4))
        end,
    y = function(tree, buffer, header, pinfo)
            tree:add_le(FIELDS.frames_on_port, buffer(0, 4))
        end,
    Y = function(tree, buffer, header, pinfo)
            tree:add_le(FIELDS.frames_on_conn, buffer(0, 4))
        end,
    H = function(tree, buffer, header, pinfo)
            add_heard_calls(tree, buffer, header)
        end,
    C = function(tree, buffer, header, pinfo)
            tree:add(FIELDS.conn_message, buffer(0, header.datalen))
        end,
    D = function(tree, buffer, header, pinfo)
            if header.pid == 0xF0 then
                tree:add(FIELDS.conn_data, buffer(0, header.datalen))
            end
        end,
    d = function(tree, buffer, header, pinfo)
            tree:add(FIELDS.disconn_message, buffer(0, header.datalen))
        end,
    I = function(tree, buffer, header, pinfo)
            add_split_data(tree, buffer, pinfo)
        end,
    S = function(tree, buffer, header, pinfo)
            add_split_data(tree, buffer)
        end,
    U = function(tree, buffer, header, pinfo)
            add_split_data(tree, buffer)
        end,
    T = function(tree, buffer, header, pinfo)
            add_split_data(tree, buffer)
        end,
    K = function(tree, buffer, header, pinfo)
            tree:add(FIELDS.tnc_port, buffer(0, 1))
			Dissector.get("ax25"):call( buffer(1):tvb(), pinfo, tree)
        end
}

local FRAME_TYPE = {
    request = "Request from Client",
    response = "Response from Server"
}

local preferences = {
    server_port = 8000,
    strict_validation = true,
    show_reserved = false
}

-- Parse the 36-byte AGWPE frame header, including reserved bytes
local function parse_header(buffer)
    return {
        port = buffer(0, 1):uint(),
        reserved_1 = buffer(1, 3):uint(),
        datakind = string.char(buffer(4, 1):uint()),
        reserved_2 = buffer(5, 1):uint(),
        pid = buffer(6, 1):uint(),
        reserved_3 = buffer(7, 1):uint(),
        callfrom = buffer(8, 10):string(),
        callto = buffer(18, 10):string(),
        datalen = buffer(28, 4):le_uint(),
        reserved_user = buffer(32, 4):uint()
    }
end

-- Examine the header data to determine whether or not this looks like a real
-- AGWPE frame header. This is really the only way that we can tell if the
-- data looks valid. Since the spec says that reserved bytes should be zero,
-- we check those, but allow for an opt-out by the user, in case they are using
-- a non-compliant implementation.
local function is_valid_header(header)
    return string.match(header.datakind, "%a") ~= nil
        and (not preferences.strict_validation
            or (header.reserved_1 == 0
                and header.reserved_2 == 0
                and header.reserved_3 == 0
                and header.reserved_user == 0))
end

--
-- Protocol
--

local protocol = Proto(PROTOCOL_NAME, PROTOCOL_DESC)

protocol.fields = FIELDS

--
-- Dissector
--

-- This function does the real work of dissecting an AGWPE PDU. However, it is
-- not the dissector function that we hand to Wireshark, because there may be
-- more than one AGWPE frame within a single TCP segment. Wireshark will make
-- sure that what we are handed contains what we need.
function dissect_one(buffer, pinfo, tree)
    if buffer:len() < HEADER_LEN then
        return 0
    end

    local header = parse_header(buffer)
    if not is_valid_header(header) then
        return 0
    end

    pinfo.cols.protocol = PROTOCOL_NAME

    local is_request = pinfo.dst_port == preferences.server_port
    local datakind_desc = is_request
        and DATAKIND_FROM_CLIENT[header.datakind]
        or DATAKIND_FROM_SERVER[header.datakind]
    if datakind_desc == nil then
        datakind_desc = "Unknown"
    end

    local subtree = tree:add(protocol, buffer(), "AGWPE Protocol Data"
        .. ", Type: " .. (is_request and "Request" or "Response")
        .. ", DataKind: " .. header.datakind)

    subtree:add(FIELDS.frametype, is_request
        and FRAME_TYPE.request
        or FRAME_TYPE.response):set_generated()
    subtree:add(FIELDS.port, buffer(0, 1))
    if preferences.show_reserved then
        subtree:add(FIELDS.reserved_1, buffer(1, 3))
    end
    subtree:add(FIELDS.datakind, buffer(4, 1))
        :append_text(" (" .. datakind_desc .. ")")
    if preferences.show_reserved then
        subtree:add(FIELDS.reserved_2, buffer(5, 1))
    end
    subtree:add(FIELDS.pid, buffer(6, 1))
    if preferences.show_reserved then
        subtree:add(FIELDS.reserved_3, buffer(7, 1))
    end
    subtree:add(FIELDS.callfrom, buffer(8, 10))
    subtree:add(FIELDS.callto, buffer(18, 10))
    subtree:add_le(FIELDS.datalen, buffer(28, 4))
    if preferences.show_reserved then
        subtree:add(FIELDS.reserved_user, buffer(32, 4))
    end

    -- If there's no data, we're done
    if header.datalen == 0 then
        return HEADER_LEN
    end

    local fn
    if is_request then
        fn = REQUEST_FNS[header.datakind]
    else
        fn = RESPONSE_FNS[header.datakind]
    end
    if fn ~= nil then
        local data_tree = subtree:add("Data")
        fn(data_tree, buffer:range(HEADER_LEN), header, pinfo)
    end

    return HEADER_LEN + header.datalen
end

-- We need to be able to tell Wireshark how much data is in our entire frame.
-- That is just the size of the frame header plus however much data that header
-- tells us will follow.
function get_total_length(tvb, pinfo, offset)
    header = parse_header(tvb(offset, HEADER_LEN):tvb())
    return HEADER_LEN + header.datalen
end

-- This is the dissector that we hand to Wireshark. When invoked, it will call
-- back into Wireshark, which will later result in one or more calls to our
-- length function and to our real dissector function, depending upon how many
-- AGWPE frames are in the TCP segment.
function protocol.dissector(buffer, pinfo, tree)
    dissect_tcp_pdus(buffer, tree, HEADER_LEN, get_total_length, dissect_one)
end

--
-- Preferences
--

protocol.prefs.server_port = Pref.uint(
    "Server port", preferences.server_port,
    "The TCP port on which the AGWPE server is listening")
protocol.prefs.strict_validation = Pref.bool(
    "Strict validation", preferences.strict_validation,
    "Should the dissector strictly validate headers before showing fields?")
protocol.prefs.show_reserved = Pref.bool(
    "Show reserved fields", preferences.show_reserved,
    "Should the content of reserved fields be displayed?")

function protocol.prefs_changed()
    preferences.strict_validation = protocol.prefs.strict_validation
    preferences.show_reserved = protocol.prefs.show_reserved
    -- If the port has been changed, then we need to change our entry in the
    -- dissector table so that it takes effect. Otherwise it will not take
    -- effect until Wireshark is restarted.
    if preferences.server_port ~= protocol.prefs.server_port then
        local dtable = DissectorTable.get("tcp.port")
        if preferences.server_port ~= 0 then
            dtable:remove(preferences.server_port, protocol)
        end
        preferences.server_port = protocol.prefs.server_port
        if preferences.server_port ~= 0 then
            dtable:add(preferences.server_port, protocol)
        end
    end
end

--
-- Mainline
--

DissectorTable.get("tcp.port"):add(preferences.server_port, protocol)
