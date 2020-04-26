option(CONFIG_STDIO "Build corec file API with stdio support" ON)
option(CONFIG_MULTITHREAD "Enable multithread support in corec" OFF)
option(CONFIG_DEBUGCHECKS "Add extra checks in corec objects/helpers in debug builds" ON)
option(CONFIG_DEBUG_LEAKS "Debug leaks in corec objects in debug builds" OFF)
option(CONFIG_SAFE_C "Notify unsafe C legacy calls" OFF)

# Base core API
add_library("corec" INTERFACE)
set(corec_base_PUBLIC_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/corec.h
  ${CMAKE_CURRENT_SOURCE_DIR}/err.h
  ${CMAKE_CURRENT_SOURCE_DIR}/helper.h
  ${CMAKE_CURRENT_SOURCE_DIR}/memalloc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/portab.h
  ${CMAKE_CURRENT_SOURCE_DIR}/confhelper.h
  ${CMAKE_CURRENT_SOURCE_DIR}/banned.h
)
target_sources("corec" INTERFACE ${corec_base_PUBLIC_HEADERS})
target_include_directories("corec" INTERFACE ".." "${COREC_CONFIG_DIR}")
if(${CMAKE_VERSION}` VERSION_GREATER_EQUAL "3.15.0")
  set_target_properties("corec" PROPERTIES 
    PUBLIC_HEADER "${corec_base_PUBLIC_HEADERS}"
  )
endif()

# Node API
set(corec_node_SOURCES
  node/node.c
  node/nodetree.c
)
set(corec_node_PUBLIC_HEADERS
  node/node.h
  node/nodebase.h
  node/nodetree.h
  node/nodetools.h
)
add_library("corec_node" ${corec_node_SOURCES} ${corec_node_PUBLIC_HEADERS}
  # documentation installed with the sources
  node/corec.html
)
set_target_properties("corec_node" PROPERTIES 
  PUBLIC_HEADER "${corec_node_PUBLIC_HEADERS}"
)
target_include_directories("corec_node" PUBLIC ".")
target_link_libraries("corec_node" PUBLIC "corec_array" "corec_str" "corec_file")
if(CONFIG_MULTITHREAD)
  target_link_libraries("corec_node" PUBLIC "corec_multithread")
endif(CONFIG_MULTITHREAD)


# Array API
set(corec_array_SOURCES
  array/array.c
)
set(corec_array_PUBLIC_HEADERS
  array/array.h
)
add_library("corec_array" ${corec_array_SOURCES})
set_target_properties("corec_array" PROPERTIES 
  PUBLIC_HEADER "${corec_array_PUBLIC_HEADERS}"
)
target_link_libraries("corec_array" PUBLIC "corec")

# String API
add_library("corec_str" INTERFACE)
set(corec_str_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/str/str.c
)
set(corec_str_WIN32_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/str/str_win32.c
)
set(corec_str_OSX_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/str/str_osx.c
)
set(corec_str_LINUX_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/str/str_linux.c
)
set(corec_str_PUBLIC_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/str/str.h
)
target_sources("corec_str" INTERFACE  ${corec_str_SOURCES} ${corec_str_PUBLIC_HEADERS})
if (WIN32)
  target_sources("corec_str" INTERFACE ${corec_str_WIN32_SOURCES})
elseif(APPLE)
    target_sources("corec_str" INTERFACE ${corec_str_OSX_SOURCES})
elseif(UNIX)
    target_sources("corec_str" INTERFACE ${corec_str_LINUX_SOURCES})
endif(WIN32)
if(${CMAKE_VERSION}` VERSION_GREATER_EQUAL "3.15.0")
  set_target_properties("corec_str" PROPERTIES 
    PUBLIC_HEADER "${corec_str_PUBLIC_HEADERS}"
  )
endif()

set(corec_multithread_WIN32_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/multithread/multithread_win32.c
)
set(corec_multithread_UNIX_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/multithread/multithread_pthread.c
)
set(corec_multithread_PUBLIC_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/multithread/multithread.h
)
add_library("corec_multithread" INTERFACE)
if (WIN32)
  target_sources("corec_multithread" INTERFACE ${corec_multithread_WIN32_SOURCES})
elseif(UNIX)
  target_sources("corec_multithread" INTERFACE ${corec_multithread_UNIX_SOURCES})
  target_link_libraries("corec_multithread" INTERFACE pthread)
endif(WIN32)
if(${CMAKE_VERSION}` VERSION_GREATER_EQUAL "3.15.0")
  set_target_properties("corec_multithread" PROPERTIES
    PUBLIC_HEADER "${corec_multithread_PUBLIC_HEADERS}"
  )
endif()
target_link_libraries("corec_multithread" INTERFACE "corec_node")

add_subdirectory("helpers")
