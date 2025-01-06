cmake_minimum_required(VERSION 3.20.4)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

project(DarksporeLauncher)

add_executable(DarksporeLauncher launcher.cpp)

# Link against Windows API libraries if needed
target_link_libraries(DarksporeLauncher kernel32)
