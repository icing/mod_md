# Copyright 2020 Contributors to mod_md project
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

PROJECT(mod_md C)
CMAKE_MINIMUM_REQUIRED(VERSION 3.14)

INCLUDE(CheckSymbolExists)

IF(WIN32)
    SET(CMAKE_C_FLAGS "/O2 /MD /W3 /Zi")
    # TODO: Questionable...people might want to override -DCMAKE_C_FLAGS_DEBUG="..."
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS}")
    SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}")
ELSE()

ENDIF()

SET(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules ${CMAKE_MODULE_PATH})

SET(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/modules)

FIND_PACKAGE(OpenSSL REQUIRED)
FIND_PACKAGE(CURL REQUIRED)
FIND_PACKAGE(JANSSON REQUIRED)
FIND_PACKAGE(APACHE REQUIRED)
FIND_PACKAGE(APR REQUIRED)

INCLUDE_DIRECTORIES(${APR_INCLUDE_DIR})
INCLUDE_DIRECTORIES(${APRUTIL_INCLUDE_DIR})
INCLUDE_DIRECTORIES(${APACHE_INCLUDE_DIR})
INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
INCLUDE_DIRECTORIES(${CURL_INCLUDE_DIR})
INCLUDE_DIRECTORIES(${JANSSON_INCLUDE_DIR})

AUX_SOURCE_DIRECTORY(${CMAKE_SOURCE_DIR}/src SRC_LIST)
ADD_LIBRARY(mod_md MODULE ${SRC_LIST})
SET_TARGET_PROPERTIES(mod_md PROPERTIES PREFIX "")
SET_TARGET_PROPERTIES(mod_md PROPERTIES SUFFIX ".so")

TARGET_LINK_LIBRARIES(mod_md ${APR_LIBRARIES} ${APRUTIL_LIBRARIES} ${APACHE_LIBRARY} ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES} ${JANSSON_LIBRARIES})

MESSAGE(STATUS "")
MESSAGE(STATUS "")
MESSAGE(STATUS "mod_md configuration summary:")
MESSAGE(STATUS "")
MESSAGE(STATUS "  Build type ...................... : ${CMAKE_BUILD_TYPE}")
MESSAGE(STATUS "  Install prefix .................. : ${CMAKE_INSTALL_PREFIX}")
MESSAGE(STATUS "  C compiler ...................... : ${CMAKE_C_COMPILER}")
MESSAGE(STATUS "  APR include directory ........... : ${APR_INCLUDE_DIR}")
MESSAGE(STATUS "  APR libraries ................... : ${APR_LIBRARIES}")
MESSAGE(STATUS "  APR Util include directory ...... : ${APRUTIL_INCLUDE_DIR}")
MESSAGE(STATUS "  APR Util libraries .............. : ${APRUTIL_LIBRARIES}")
MESSAGE(STATUS "  OpenSSL include directory ....... : ${OPENSSL_INCLUDE_DIR}")
MESSAGE(STATUS "  OpenSSL libraries ............... : ${OPENSSL_LIBRARIES}")
MESSAGE(STATUS "  Curl include directory........... : ${CURL_INCLUDE_DIR}")
MESSAGE(STATUS "  Curl libraries................... : ${CURL_LIBRARIES}")
MESSAGE(STATUS "  Jansson include directory.........: ${JANSSON_INCLUDE_DIR}")
MESSAGE(STATUS "  Jansson libraries ............... : ${JANSSON_LIBRARIES}")
MESSAGE(STATUS "")
