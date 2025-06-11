local p_myprotocol = Proto("MyProtocol", "My Custom Protocol")

local f_flag = ProtoField.uint8("myprotocol.flag", "Flag", base.HEX)
local f_flag_name = ProtoField.string("myprotocol.flag_name", "Flag Name")
local f_seq_num = ProtoField.uint16("myprotocol.seq_num", "Sequence Number", base.DEC)
local f_ack_num = ProtoField.uint16("myprotocol.ack_num", "Acknowledgment Number", base.DEC)
local f_window = ProtoField.uint16("myprotocol.window", "Window Size", base.DEC)
local f_fragment_size = ProtoField.uint16("myprotocol.fragment_size", "Fragment Size", base.DEC)
local f_check_sum = ProtoField.uint32("myprotocol.check_sum", "Checksum", base.HEX)

p_myprotocol.fields = { f_flag, f_flag_name, f_seq_num, f_ack_num, f_window, f_fragment_size, f_check_sum }

local flag_names = {
    [0x1] = "SYN",
    [0x2] = "ACK",
    [0x3] = "SYN_ACK",
    [0x4] = "FIN",
    [0x5] = "NACK",
    [0x6] = "DATA",
    [0x7] = "KEEPALIVE"
}

function p_myprotocol.dissector(buffer, pinfo, tree)
    if buffer:len() < 13 then
        return
    end

    local subtree = tree:add(p_myprotocol, buffer())

    local flag_value = buffer(0, 1):uint()
    local flag_name = flag_names[flag_value] or "UNKNOWN"

    subtree:add(f_flag, buffer(0, 1))
    subtree:add(f_flag_name, flag_name)
    subtree:add(f_seq_num, buffer(1, 2))
    subtree:add(f_ack_num, buffer(3, 2))
    subtree:add(f_window, buffer(5, 2))
    subtree:add(f_fragment_size, buffer(7, 2))
    subtree:add(f_check_sum, buffer(9, 4))

    local payload = buffer(13)
    if payload:len() > 0 then
        subtree:add(buffer(13), "Payload: " .. payload:bytes():tohex())
    end
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(50000, p_myprotocol)