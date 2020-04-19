# zlib library API

option(CONFIG_ZLIB "Enable zlib (de)compression" ON)

if (CONFIG_ZLIB)
    add_library("zlib")
    set(ZLIB_GROUP_HEADERS
        ${CMAKE_CURRENT_SOURCE_DIR}/crc32.h
        ${CMAKE_CURRENT_SOURCE_DIR}/inffast.h
        ${CMAKE_CURRENT_SOURCE_DIR}/inffixed.h
        ${CMAKE_CURRENT_SOURCE_DIR}/inflate.h
        ${CMAKE_CURRENT_SOURCE_DIR}/inftrees.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zconf.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zlib.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zutil.h
        ${CMAKE_CURRENT_SOURCE_DIR}/deflate.h
        ${CMAKE_CURRENT_SOURCE_DIR}/trees.h
    )
    set(ZLIB_GROUP_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/adler32.c
        ${CMAKE_CURRENT_SOURCE_DIR}/crc32.c
        ${CMAKE_CURRENT_SOURCE_DIR}/inffast.c
        ${CMAKE_CURRENT_SOURCE_DIR}/inflate.c
        ${CMAKE_CURRENT_SOURCE_DIR}/inftrees.c
        ${CMAKE_CURRENT_SOURCE_DIR}/uncompr.c
        ${CMAKE_CURRENT_SOURCE_DIR}/zutil.c
        ${CMAKE_CURRENT_SOURCE_DIR}/compress.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deflate.c
        ${CMAKE_CURRENT_SOURCE_DIR}/trees.c
    )
    target_compile_definitions("zlib" PRIVATE FASTEST NO_ERRNO_H)
    target_sources("zlib" PRIVATE ${ZLIB_GROUP_SOURCES} ${ZLIB_GROUP_HEADERS})
    target_include_directories("zlib" PUBLIC ".")
    set_target_properties("zlib" PROPERTIES 
        PUBLIC_HEADERS "${COREC_BASE_HEADERS}"
    )
endif(CONFIG_ZLIB)