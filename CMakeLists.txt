cmake_minimum_required(VERSION 3.20.4)

set(CMAKE_CXX_STANDARD 17)

project(DarksporeLauncher)

add_executable(DarksporeLauncher launcher.cpp)

target_link_libraries(DarksporeLauncher PRIVATE Version kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 advapi32)