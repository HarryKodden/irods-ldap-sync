cmake_minimum_required(VERSION 3.5.0 FATAL_ERROR)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake/modules)

if (NOT IRODS_EXTERNALS_PACKAGE_ROOT)
  set(IRODS_EXTERNALS_PACKAGE_ROOT "/opt/irods-externals" CACHE STRING "Choose the location of iRODS external packages." FORCE)
  message(STATUS "Setting unspecified IRODS_EXTERNALS_PACKAGE_ROOT to '${IRODS_EXTERNALS_PACKAGE_ROOT}'")
endif()

macro(IRODS_MACRO_CHECK_DEPENDENCY_SET_FULLPATH DEPENDENCY_NAME DEPENDENCY_SUBDIRECTORY)
  if (IS_DIRECTORY ${IRODS_EXTERNALS_FULLPATH_${DEPENDENCY_NAME}})
    message(STATUS "Using user-specified value for IRODS_EXTERNALS_FULLPATH_${DEPENDENCY_NAME}: ${IRODS_EXTERNALS_FULLPATH_${DEPENDENCY_NAME}}")
  else()
    if (NOT IS_DIRECTORY ${IRODS_EXTERNALS_PACKAGE_ROOT}/${DEPENDENCY_SUBDIRECTORY})
      message(FATAL_ERROR "${DEPENDENCY_NAME} not found at ${IRODS_EXTERNALS_PACKAGE_ROOT}/${DEPENDENCY_SUBDIRECTORY}")
    endif()
    set(IRODS_EXTERNALS_FULLPATH_${DEPENDENCY_NAME} ${IRODS_EXTERNALS_PACKAGE_ROOT}/${DEPENDENCY_SUBDIRECTORY})
  endif()
endmacro()

macro(IRODS_MACRO_CHECK_DEPENDENCY_SET_FULLPATH_ADD_TO_IRODS_PACKAGE_DEPENDENCIES_LIST DEPENDENCY_NAME DEPENDENCY_SUBDIRECTORY)
  IRODS_MACRO_CHECK_DEPENDENCY_SET_FULLPATH(${DEPENDENCY_NAME} ${DEPENDENCY_SUBDIRECTORY})
  list(APPEND IRODS_PACKAGE_DEPENDENCIES_LIST irods-externals-${DEPENDENCY_SUBDIRECTORY})
endmacro()

IRODS_MACRO_CHECK_DEPENDENCY_SET_FULLPATH_ADD_TO_IRODS_PACKAGE_DEPENDENCIES_LIST(CLANG_RUNTIME clang-runtime6.0-0)
IRODS_MACRO_CHECK_DEPENDENCY_SET_FULLPATH_ADD_TO_IRODS_PACKAGE_DEPENDENCIES_LIST(BOOST boost1.67.0-0)
add_compile_options(-std=c++17)

set(CMAKE_C_COMPILER  /usr/bin/clang-6.0)
set(CMAKE_CXX_COMPILER  /usr/bin/clang++-6.0)

set(CMAKE_EXE_LINKER_FLAGS_INIT "${CMAKE_EXE_LINKER_FLAGS} -stdlib=libc++")

# set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -stdlib=libc++ -Wl,-z,defs")
# set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -stdlib=libc++ -Wl,-z,defs")

add_compile_options(-nostdinc++)
add_compile_options(-Wall)
add_compile_options(-Wextra)
add_compile_options(-Werror)
add_compile_options(-Wno-unused-parameter)
add_compile_options(-Wno-unused-function)
add_compile_options(-fPIC)

include_directories(
  /usr/include/clang/6.0/include/
  /opt/irods/lib/core/include/
  /opt/irods/server/core/include/
  /opt/irods/server/icat/include
  /opt/irods/server/api/include/
  /opt/irods/server/re/include/
  /opt/irods/lib/api/include/
  /usr/include/c++/7
  /usr/include/x86_64-linux-gnu/c++/7/
  )

find_package(OpenSSL REQUIRED)
find_package(PAM REQUIRED)

if (NOT PAM_LIBRARY)
  find_library(PAM_LIBRARY pam)
  if (PAM_LIBRARY)
    message(STATUS "Found pam: ${PAM_LIBRARY}")
  else()
    message(FATAL_ERROR "pam library not found")
  endif()
endif()

add_subdirectory (whereami)

set(IRODS_AUTH_PLUGIN_pam_interactive_SOURCES
  ${CMAKE_SOURCE_DIR}/src/libpam_interactive.cpp
  ${CMAKE_SOURCE_DIR}/src/conversation.cpp
  ${CMAKE_SOURCE_DIR}/src/message.cpp
  ${CMAKE_SOURCE_DIR}/src/pam_handshake/handshake_session.cpp
  ${CMAKE_SOURCE_DIR}/src/pam_handshake/pam_conversation.cpp
  )


set(
  IRODS_AUTH_PLUGIN_TYPES
  client
  server
  )

set(
  IRODS_PLUGIN_COMPILE_DEFINITIONS_client
  )

set(
  IRODS_PLUGIN_COMPILE_DEFINITIONS_server
  RODS_SERVER
  ENABLE_RE
  )

foreach(TYPE ${IRODS_AUTH_PLUGIN_TYPES})
  set(
    IRODS_CURRENT_PLUGIN_TARGET
    pam_interactive_${TYPE}
    )
  add_library(
    ${IRODS_CURRENT_PLUGIN_TARGET}
    MODULE
    ${IRODS_AUTH_PLUGIN_pam_interactive_SOURCES}
    )

  target_include_directories(
    ${IRODS_CURRENT_PLUGIN_TARGET}
    PRIVATE
    ${IRODS_EXTERNALS_FULLPATH_BOOST}/include
    ${IRODS_EXTERNALS_PACKAGE_ROOT}/json3.7.3-0/include
    ${OPENSSL_INCLUDE_DIR}
    )

  target_compile_definitions(
    ${IRODS_CURRENT_PLUGIN_TARGET}
    PRIVATE
    ${IRODS_PLUGIN_COMPILE_DEFINITIONS_${TYPE}}
    ${IRODS_COMPILE_DEFINITIONS}
    BOOST_SYSTEM_NO_DEPRECATED
    )
  target_compile_options(
    ${IRODS_CURRENT_PLUGIN_TARGET}
    PRIVATE
    -Wno-write-strings)
  set_property(
    TARGET
    ${IRODS_CURRENT_PLUGIN_TARGET}
    PROPERTY
    CXX_STANDARD
    ${IRODS_CXX_STANDARD})
  install(
      TARGETS
      ${IRODS_CURRENT_PLUGIN_TARGET}
      LIBRARY
      DESTINATION ${IRODS_PLUGINS_DIRECTORY}/auth
      COMPONENT ${IRODS_PACKAGE_COMPONENT_RUNTIME_NAME}
      )
endforeach()

target_link_libraries(
  pam_interactive_server
  PRIVATE
  ${PAM_LIBRARY}
  WhereAmI
  )

target_link_libraries(
  pam_interactive_client
  PRIVATE
  WhereAmI
  )

# auth check executable
add_executable(
  pam_handshake_auth_check
  src/pam_handshake/auth_check_main.cpp
  src/pam_handshake/pam_conversation.cpp
)

set_property(
  TARGET
  pam_handshake_auth_check
  PROPERTY
  CXX_STANDARD
  ${IRODS_CXX_STANDARD}
)

target_link_libraries(
  pam_handshake_auth_check
  PRIVATE
  ${IRODS_EXTERNALS_FULLPATH_CLANG_RUNTIME}/lib/libc++.so.1
  ${IRODS_EXTERNALS_FULLPATH_CLANG_RUNTIME}/lib/libc++abi.so.1
  /usr/lib/libirods_common.so
  ${PAM_LIBRARY}
)


# unit test
add_executable(
  run_test
  ${CMAKE_SOURCE_DIR}/test/run_test.cpp
  ${CMAKE_SOURCE_DIR}/test/test_util.cpp
  ${CMAKE_SOURCE_DIR}/test/test_pam.cpp
  ${CMAKE_SOURCE_DIR}/test/test_message.cpp
  ${CMAKE_SOURCE_DIR}/src/message.cpp
  ${CMAKE_SOURCE_DIR}/src/conversation.cpp
  ${CMAKE_SOURCE_DIR}/src/pam_handshake/pam_conversation.cpp
  )

target_include_directories(
  run_test
  PRIVATE
  ${IRODS_EXTERNALS_PACKAGE_ROOT}/catch22.3.0-0/include/
  ${IRODS_EXTERNALS_PACKAGE_ROOT}/json3.7.3-0/include
  ${IRODS_EXTERNALS_PACKAGE_ROOT}/boost1.67.0-0/include
  src
  )

set_property(
  TARGET
  run_test
  PROPERTY
  CXX_STANDARD
  ${IRODS_CXX_STANDARD}
  )

target_link_libraries(run_test
  ${IRODS_EXTERNALS_FULLPATH_CLANG_RUNTIME}/lib/libc++.so.1
  ${IRODS_EXTERNALS_FULLPATH_CLANG_RUNTIME}/lib/libc++abi.so.1
  /usr/lib/libirods_common.so
  ${PAM_LIBRARY}
  WhereAmI
)