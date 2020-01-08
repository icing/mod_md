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

# One must set a hint: JANSSON_ROOT_DIR
# Once done this will define
#  JANSSON_FOUND
#  JANSSON_INCLUDE_DIRS
#  JANSSON_LIBRARIES

IF(NOT JANSSON_ROOT_DIR)
    message(FATAL_ERROR "JANSSON_ROOT_DIR is not set. We don't know where to look for JANSSON, quitting.")
ENDIF()


FIND_PATH(JANSSON_INCLUDE_DIR jansson.h
    "${JANSSON_ROOT_DIR}/include"
)

SET(JANSSON_NAMES ${JANSSON_NAMES} jansson libjansson)
FIND_LIBRARY(JANSSON_LIBRARY NAMES ${JANSSON_NAMES} PATHS "${JANSSON_ROOT_DIR}/lib" "${JANSSON_ROOT_DIR}/lib64")

IF (JANSSON_LIBRARY AND JANSSON_INCLUDE_DIR)
    SET(JANSSON_LIBRARIES ${JANSSON_LIBRARY})
    SET(JANSSON_FOUND "YES")
ELSE (JANSSON_LIBRARY AND JANSSON_INCLUDE_DIR)
    SET(JANSSON_FOUND "NO")
ENDIF (JANSSON_LIBRARY AND JANSSON_INCLUDE_DIR)

IF (JANSSON_FOUND)
    IF (NOT JANSSON_FIND_QUIETLY)
        MESSAGE(STATUS "Found JANSSON: ${JANSSON_LIBRARIES}")
    ENDIF (NOT JANSSON_FIND_QUIETLY)
ELSE (JANSSON_FOUND)
    IF (JANSSON_FIND_REQUIRED)
        MESSAGE(FATAL_ERROR "Could not find JANSSON library")
    ENDIF (JANSSON_FIND_REQUIRED)
ENDIF (JANSSON_FOUND)

MARK_AS_ADVANCED(
        JANSSON_LIBRARY
        JANSSON_INCLUDE_DIR
)
