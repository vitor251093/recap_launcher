cmake_minimum_required(VERSION 3.20.4)

set(CMAKE_CXX_STANDARD 17)

project(recap_launcher)

add_executable(recap_launcher launcher.cpp)

target_link_libraries(recap_launcher PRIVATE Version kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 advapi32)