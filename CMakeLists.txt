cmake_minimum_required(VERSION 3.15)

if (NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "CMake must be configured for the 32-bit architecture.")
endif()

project(limbos_gate C ASM_NASM)
add_executable(limbos_gate main.c limbosgate.asm)
