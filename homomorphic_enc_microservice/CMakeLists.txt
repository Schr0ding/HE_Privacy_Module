cmake_minimum_required(VERSION 3.22.1)
project(MicroServC VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(MicroServC src/main.cpp)

find_package(SEAL REQUIRED)
target_link_libraries(MicroServC SEAL::seal)

include_directories(/usr/local/include)
link_directories(/usr/local/lib)
target_link_libraries(MicroServC pistache ssl crypto)
