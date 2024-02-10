cmake_minimum_required(VERSION 3.15)

if (("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "" AND NOT CMAKE_SIZEOF_VOID_P EQUAL 4) OR NOT "${CMAKE_GENERATOR_PLATFORM}" STREQUAL "Win32")
  message(FATAL_ERROR "CMake must be configured for the 32-bit architecture.")
endif()

project(limbos_gate C ASM_NASM)
add_executable(limbos_gate main.c limbosgate.asm)
