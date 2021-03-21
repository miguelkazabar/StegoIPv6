project (StegoIPv6)
cmake_minimum_required(VERSION 3.0)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

ADD_EXECUTABLE(StegoIPv6 stegoipv6.cpp)
target_link_libraries(StegoIPv6 -lcrafter -lcryptopp)