set(DMG_DEPENDENCY_ROOT "${CMAKE_CURRENT_LIST_DIR}/../third_party")
add_library(dmg_miniz STATIC "${DMG_DEPENDENCY_ROOT}/miniz/miniz.c")
target_include_directories(dmg_miniz PUBLIC "${DMG_DEPENDENCY_ROOT}/miniz")
# MINIZ_NO_DEFLATE_APIS also defines MINIZ_NO_ARCHIVE_WRITING_APIS upstream.
target_compile_definitions(dmg_miniz PUBLIC MINIZ_NO_STDIO MINIZ_NO_TIME
  MINIZ_NO_DEFLATE_APIS
  MINIZ_NO_ZLIB_COMPATIBLE_NAMES MINIZ_NO_MALLOC)
set_target_properties(dmg_miniz PROPERTIES POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)

option(DMG_WITH_SQLITE "Build the optional desktop SQLite adapter dependency" OFF)
if(DMG_WITH_SQLITE)
  if(ANDROID)
    message(FATAL_ERROR "DMG_WITH_SQLITE is a desktop-only capability")
  endif()
  add_library(dmg_sqlite STATIC "${DMG_DEPENDENCY_ROOT}/sqlite/sqlite3.c")
  target_include_directories(dmg_sqlite PUBLIC "${DMG_DEPENDENCY_ROOT}/sqlite")
  target_compile_definitions(dmg_sqlite PRIVATE SQLITE_OMIT_LOAD_EXTENSION SQLITE_THREADSAFE=1)
  set_target_properties(dmg_sqlite PROPERTIES POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
endif()
