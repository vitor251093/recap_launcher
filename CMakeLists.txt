cmake_minimum_required(VERSION 3.15)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# Prevent in-source builds
set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
# Create compilation database
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE BOOL "" FORCE)

project(recap_launcher VERSION 0.1 LANGUAGES CXX)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Force 32-bit builds
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "As the target process is a 32-bit executable, detours must be built as a 32-bit library as well.")
endif()

# CPM package manager setup
include(cmake/get_cpm.cmake)
include(cmake/get_findvcvars.cmake)
find_package(Vcvars REQUIRED)

# Detours
CPMAddPackage(
    NAME detours
    GIT_REPOSITORY https://github.com/microsoft/detours.git
    VERSION 4.0.1
    DOWNLOAD_ONLY YES)
if(detours_ADDED)
    add_library(detours STATIC IMPORTED)
    file(GLOB_RECURSE DETOURS_SOURCES "${detours_SOURCE_DIR}/src/*.*")
    set(DETOURS_BUILD_COMMAND ${Vcvars_LAUNCHER} nmake DETOURS_TARGET_PROCESSOR=X86)
    set(DETOURS_BUILD_OUTPUT ${detours_SOURCE_DIR}/lib.X86/detours.lib)
    set_target_properties(detours PROPERTIES IMPORTED_LOCATION ${DETOURS_BUILD_OUTPUT})
    add_custom_command(
        OUTPUT ${DETOURS_BUILD_OUTPUT}
        COMMAND ${DETOURS_BUILD_COMMAND}
        DEPENDS ${DETOURS_SOURCES}
        WORKING_DIRECTORY ${detours_SOURCE_DIR}/src
        VERBATIM)
    add_custom_target(detours-build DEPENDS ${DETOURS_BUILD_OUTPUT})
    add_dependencies(detours detours-build)
    file(MAKE_DIRECTORY ${detours_SOURCE_DIR}/include)
    target_include_directories(detours SYSTEM INTERFACE $<BUILD_INTERFACE:${detours_SOURCE_DIR}/include>)
endif()

CPMAddPackage(
    NAME sig
    GIT_REPOSITORY https://github.com/HoShiMin/Sig.git
    GIT_TAG 369071b5a23eb6584c797abfdeb57056bb761111)
if(sig_ADDED)
    add_library(sig INTERFACE)
    target_include_directories(sig SYSTEM INTERFACE $<BUILD_INTERFACE:${sig_SOURCE_DIR}/include>)
endif()

CPMAddPackage(
    NAME tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG v3.4.0)

add_library(RecapHooks SHARED)
set(RECAP_HOOKS_SOURCES Source/RecapHooks/Module.def
                        Source/RecapHooks/Main.cpp)
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${RECAP_HOOKS_SOURCES})
target_sources(RecapHooks PRIVATE ${RECAP_HOOKS_SOURCES})
target_link_libraries(RecapHooks PRIVATE detours ws2_32 sig tomlplusplus::tomlplusplus)
set_target_properties(RecapHooks PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(RecapLauncher)
set(RECAP_LAUNCHER_SOURCES Source/RecapLauncher/Main.cpp)
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${RECAP_LAUNCHER_SOURCES})
target_sources(RecapLauncher PRIVATE ${RECAP_LAUNCHER_SOURCES})
target_link_libraries(RecapLauncher PRIVATE detours)
set_target_properties(RecapLauncher PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    LINK_FLAGS "/SUBSYSTEM:CONSOLE")

include(GNUInstallDirs)
install(TARGETS RecapHooks RecapLauncher RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES Config/RecapHooks.toml DESTINATION ${CMAKE_INSTALL_BINDIR})
