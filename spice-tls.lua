-- wireshark -X lua_script:spice-tls.lua -o tls.keylog_file:/tmp/keylogfile.txt -d tls.port==4433,spice-tls
-- qemu-system-x86_64 -spice x509-key-file=key,x509-cert-file=cert,x509-cacert-file=cert,tls-port=4433,disable-ticketing=on
-- SSLKEYLOGFILE=/tmp/keylogfile.txt LD_PRELOAD=sslkeylogfile-preload/LD_PRELOAD_sslkeylogfile.so remote-viewer spice://localhost?tls-port=4433
local proto = Proto("spice-tls", "SPICE over TLS")
local spice = Dissector.get("spice")
function proto.dissector(buf, pinfo, tree) return spice:call(buf, pinfo, tree) end
DissectorTable.get("tls.port"):add_for_decode_as(proto)

-- Before <https://gitlab.com/wireshark/wireshark/-/commit/fb9d01556dbc28a507778f66cbaca234a55e6305>,
-- there was no way for Lua to get the "spice" dissector.
-- Workaround: start Wireshark with:
-- wireshark -d tcp.port==1,spice
function proto.init()
    if spice == nil then
        spice = DissectorTable.get("tcp.port"):get_dissector(1)
    end
end
