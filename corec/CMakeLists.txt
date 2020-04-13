add_library("corec"
  corec/node/node.c
  corec/node/nodetree.c
  corec/array/array.c
  corec/str/str.c

  corec/helpers/file/bufstream.c
  corec/helpers/file/memstream.c
  corec/helpers/file/streams.c
  corec/helpers/file/tools.c

  # only if CONFIG_STDIO is set
  corec/helpers/file/stream_stdio.c
)
if (WIN32)
  target_sources("corec" 
    corec/str/str_win32.c
    corec/helpers/file/date_win32.c
    corec/helpers/file/file_win32.c
    corec/helpers/charconvert/charconvert_win32.c
  )
endif(WIN32)
if (UNIX)
  target_sources("corec" PRIVATE
    corec/helpers/date/date_libc.c
    corec/helpers/file/file_libc.c
  )
  if (APPLE)
    target_sources("corec" PRIVATE 
      corec/str/str_osx.c
      corec/helpers/charconvert/charconvert_osx.c
    )
  else()
    target_sources("corec" PRIVATE 
      corec/str/str_linux.c
      corec/helpers/charconvert/charconvert_linux.c
    )
  endif()
endif(UNIX)

target_include_directories("corec" PUBLIC ".")

add_library("corec_parser"
  corec/helpers/parser/buffer.c
  corec/helpers/parser/dataheap.c
  corec/helpers/parser/hotkey.c
  corec/helpers/parser/nodelookup.c
  corec/helpers/parser/parser2.c
  corec/helpers/parser/strtab.c
  corec/helpers/parser/strtypes.c
  corec/helpers/parser/urlpart.c
)
target_link_libraries("corec_parser" PRIVATE "corec")
target_include_directories("corec_parser" PUBLIC ".")

add_library("ccsystem")
if (WIN32)
  target_sources("ccsystem" PRIVATE corec/helpers/system/ccsystem_win32.c)
endif(WIN32)
if (UNIX)
  target_sources("ccsystem" PRIVATE corec/helpers/system/ccsystem_posix.c)
endif(UNIX)
target_include_directories("ccsystem" PUBLIC ".")

add_library("md5" corec/helpers/md5/md5.c)
target_include_directories("md5" PUBLIC ".")