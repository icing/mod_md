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

# One must set a hint: APR_ROOT_DIR, APRUTIL_ROOT_DIR
# Find the APR includes and libraries
# Module defines
#   APR_INCLUDE_DIR and APRUTIL_INCLUDE_DIR, apr.h, etc.
#   APR_LIBRARIES and APRUTIL_LIBRARIES, libs needed to use APR.
#   APR_FOUND and APRUTIL_FOUND, whether APR usable.
# Defined:
#   APR_LIBRARY and APRUTIL_LIBRARY, where to find the APR library.

IF(NOT APR_ROOT_DIR)
    message(FATAL_ERROR "APR_ROOT_DIR is not set. We don't know where to look for APR, quitting.")
ENDIF()

IF(NOT APRUTIL_ROOT_DIR)
    message(FATAL_ERROR "APR_ROOT_DIR is not set. We don't know where to look for APR, quitting.")
ENDIF()

FIND_PATH(APR_INCLUDE_DIR apr.h
    "${APR_ROOT_DIR}/include"
)
SET(APR_NAMES ${APR_NAMES} libapr-1 apr-1)
FIND_LIBRARY(APR_LIBRARY NAMES ${APR_NAMES} PATHS "${APR_ROOT_DIR}/lib" "${APR_ROOT_DIR}/lib64")
IF (APR_LIBRARY AND APR_INCLUDE_DIR)
    SET(APR_LIBRARIES ${APR_LIBRARY})
    SET(APR_FOUND "YES")
ELSE (APR_LIBRARY AND APR_INCLUDE_DIR)
    SET(APR_FOUND "NO")
ENDIF (APR_LIBRARY AND APR_INCLUDE_DIR)

IF (APR_FOUND)
    IF (NOT APR_FIND_QUIETLY)
        MESSAGE(STATUS "Found APR: ${APR_LIBRARIES}")
    ENDIF (NOT APR_FIND_QUIETLY)
ELSE (APR_FOUND)
    IF (APR_FIND_REQUIRED)
        MESSAGE(FATAL_ERROR "Could not find APR library")
    ENDIF (APR_FIND_REQUIRED)
ENDIF (APR_FOUND)

MARK_AS_ADVANCED(
        APR_LIBRARY
        APR_INCLUDE_DIR
)

# APR Util
FIND_PATH(APRUTIL_INCLUDE_DIR apu.h
    "${APRUTIL_ROOT_DIR}/include"
)

SET(APRUTIL_NAMES ${APRUTIL_NAMES} libaprutil-1 aprutil-1)
FIND_LIBRARY(APRUTIL_LIBRARY
        NAMES ${APRUTIL_NAMES}
        PATHS "${APRUTIL_ROOT_DIR}/lib" "${APRUTIL_ROOT_DIR}/lib64"
)

IF (APRUTIL_LIBRARY AND APRUTIL_INCLUDE_DIR)
    SET(APRUTIL_LIBRARIES ${APRUTIL_LIBRARY})
    SET(APRUTIL_FOUND "YES")
ELSE (APRUTIL_LIBRARY AND APRUTIL_INCLUDE_DIR)
    SET(APRUTIL_FOUND "NO")
ENDIF (APRUTIL_LIBRARY AND APRUTIL_INCLUDE_DIR)

IF (APRUTIL_FOUND)
    IF (NOT APRUTIL_FIND_QUIETLY)
        MESSAGE(STATUS "Found APRUTIL: ${APRUTIL_LIBRARIES}")
    ENDIF (NOT APRUTIL_FIND_QUIETLY)
ELSE (APRUTIL_FOUND)
    IF (APRUTIL_FIND_REQUIRED)
        MESSAGE(FATAL_ERROR "Could not find APRUTIL library")
    ENDIF (APRUTIL_FIND_REQUIRED)
ENDIF (APRUTIL_FOUND)

MARK_AS_ADVANCED(
        APRUTIL_LIBRARY
        APRUTIL_INCLUDE_DIR
)
