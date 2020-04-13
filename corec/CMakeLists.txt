add_library("corec"
  corec/node/node.c
)

target_include_directories("corec" PRIVATE ".")
