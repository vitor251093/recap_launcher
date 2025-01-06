cmake_minimum_required(VERSION 3.15)
project(DarksporeLauncher)

set(CMAKE_CXX_STANDARD 17)

add_executable(DarksporeLauncher launcher.cpp)

# Link against Windows API libraries if needed
target_link_libraries(DarksporeLauncher kernel32)
