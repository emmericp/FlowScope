CMAKE_MINIMUM_REQUIRED(VERSION 2.8.10)

IF(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 5.0)
	MESSAGE(FATAL_ERROR "FlowScope requires gcc 5 or newer.")
ENDIF()

SET(CMAKE_CXX_FLAGS "-fno-stack-protector -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -g -O3 -std=gnu++11 -march=native")
SET(CMAKE_C_FLAGS "-fno-stack-protector -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -g -O3 -std=gnu11 -march=native")

SET(PRJ flowscope)

FILE(GLOB SOURCES src/*.c src/*.cpp)

SET(PHOBOS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/phobos)

INCLUDE_DIRECTORIES(
	${CMAKE_CURRENT_SOURCE_DIR}/src
	${PHOBOS_DIR}/deps/dpdk/x86_64-native-linuxapp-gcc/include
	${PHOBOS_DIR}/deps/luajit/src
	${PHOBOS_DIR}/lib
	${PHOBOS_DIR}/src
)

ADD_LIBRARY(${PRJ} SHARED ${SOURCES})

