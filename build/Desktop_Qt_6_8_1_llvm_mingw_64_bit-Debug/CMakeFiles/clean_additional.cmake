# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles\\Packet_sniffer_pro_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\Packet_sniffer_pro_autogen.dir\\ParseCache.txt"
  "Packet_sniffer_pro_autogen"
  )
endif()
