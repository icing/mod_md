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

# One must set a hint: APACHE_ROOT_DIR
# Module defines
#  APACHE_FOUND         - System has APACHE
#  APACHE_INCLUDE_DIR   - The APACHE include directory
#  APACHE_LIBRARIES     - Library
# Defined:
#  APACHE_LIBRARY       - httpd lib

IF(NOT APACHE_ROOT_DIR)
    message(FATAL_ERROR "APACHE_ROOT_DIR is not set. We don't know where to look for APACHE, quitting.")
ENDIF()
FIND_PATH(APACHE_INCLUDE_DIR httpd.h
    "${APACHE_ROOT_DIR}/include"
)
SET(APACHE_NAMES ${APACHE_NAMES} httpd libhttpd)
FIND_LIBRARY(APACHE_LIBRARY NAMES ${APACHE_NAMES} PATHS "${APACHE_ROOT_DIR}/lib" "${APACHE_ROOT_DIR}/lib64")
IF (APACHE_LIBRARY AND APACHE_INCLUDE_DIR)
    SET(APACHE_LIBRARIES ${APACHE_LIBRARY})
    SET(APACHE_FOUND "YES")
ELSE (APACHE_LIBRARY AND APACHE_INCLUDE_DIR)
    SET(APACHE_FOUND "NO")
ENDIF (APACHE_LIBRARY AND APACHE_INCLUDE_DIR)

IF (APACHE_FOUND)
    IF (NOT APACHE_FIND_QUIETLY)
        MESSAGE(STATUS "Found APACHE: ${APACHE_LIBRARIES}")
    ENDIF (NOT APACHE_FIND_QUIETLY)
ELSE (APACHE_FOUND)
    IF (APACHE_FIND_REQUIRED)
        MESSAGE(FATAL_ERROR "Could not find APACHE library")
    ENDIF (APACHE_FIND_REQUIRED)
ENDIF (APACHE_FOUND)

MARK_AS_ADVANCED(
        APACHE_LIBRARY
        APACHE_INCLUDE_DIR
)