add_library("matroska2"
  matroskamain.c
  matroskablock.c
  matroska_sem.c
)
target_include_directories("matroska2" PUBLIC ".")
target_link_libraries("matroska2" PRIVATE "ebml2")