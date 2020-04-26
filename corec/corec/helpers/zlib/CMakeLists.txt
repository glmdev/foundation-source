# zlib library API

option(CONFIG_ZLIB "Enable zlib (de)compression" ON)

if (CONFIG_ZLIB)
    add_library("zlib")
    set(ZLIB_GROUP_HEADERS
        crc32.h
        inffast.h
        inffixed.h
        inflate.h
        inftrees.h
        zconf.h
        zlib.h
        zutil.h
        deflate.h
        trees.h
    )
    set(ZLIB_GROUP_SOURCES
        adler32.c
        crc32.c
        inffast.c
        inflate.c
        inftrees.c
        uncompr.c
        zutil.c
        compress.c
        deflate.c
        trees.c
    )

    if(0)
    if(MSVC)
        if (${CMAKE_HOST_SYSTEM_PROCESSOR} MATCHES AMD64)
            target_compile_definitions("zlib" PRIVATE ASMINF)
            set(ZLIB_ASM_SOURCES
                contrib/masmx64/gvmat64.asm
                contrib/masmx64/inffas8664.c
                contrib/masmx64/inffasx64.asm
            )
        elseif (${CMAKE_HOST_SYSTEM_PROCESSOR} MATCHES X86)
            target_compile_definitions("zlib" PRIVATE ASMINF)
            set(ZLIB_ASM_SOURCES
                contrib/masmx64/masmx86/inffas32.asm
                contrib/masmx64/masmx86/match686.asm
            )
        endif()
      endif(MSVC)

    if(GCC AND NOT APPLE)
        if (${CMAKE_HOST_SYSTEM_PROCESSOR} MATCHES x86_64)
            target_compile_definitions("zlib" PRIVATE ASMV)
            set(ZLIB_ASM_SOURCES
            contrib/masmx64/masmx86/inffas32.asm
            contrib/masmx64/masmx86/match686.asm
        )
        elseif (${CMAKE_HOST_SYSTEM_PROCESSOR} MATCHES i686)
            target_compile_definitions("zlib" PRIVATE ASMV)
            target_compile_definitions("zlib" PRIVATE ASMINF)
            set(ZLIB_ASM_SOURCES
                contrib/masmx64/masmx86/inffas32.asm
                contrib/masmx64/masmx86/match686.asm
            )
        endif()
    endif()
    endif()
    
    target_compile_definitions("zlib" PRIVATE FASTEST NO_ERRNO_H)
    # if(WIN32 && DYNAMIC BUILD)
    #     target_compile_definitions("zlib" ZLIB_DLL)
    # endif(WIN32)
    target_sources("zlib" PRIVATE ${ZLIB_GROUP_SOURCES} ${ZLIB_ASM_SOURCES} ${ZLIB_GROUP_HEADERS})
    target_include_directories("zlib" PUBLIC ".")
    set_target_properties("zlib" PROPERTIES 
        PUBLIC_HEADER "${ZLIB_GROUP_HEADERS}"
    )
endif(CONFIG_ZLIB)
