## KCP Plugin for Wireshark

In Mac, copy kcp_dissector.lua and kcp2.lua to /Applications/Wireshark.app/Contents/PlugIns/wireshark

### 1. Parse standard KCP
kcp_dissector.lua    

register dissector to UDP port 8081
### 2. Parse KCP-FEC 
kcp2.lua   

register dissector to UDP port 8082

