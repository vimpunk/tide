cmake_minimum_required(VERSION 3.9.2)
project(tide)

set(CMAKE_CXX_STANDARD 17)

if(CMAKE_BUILD_TYPE STREQUAL Debug)
    message("Configuring Debug build...")
    add_definitions(-DTIDE_ENABLE_LOGGING)
    add_definitions(-DTIDE_LOG_PATH=${LOG_PATH})
    add_definitions(-DTIDE_LOG_PRIORITY=${LOG_PRIORITY})
    option(STREAM_DEBUGGING "log in real time to stdout" OFF)
    if(STREAM_DEBUGGING)
        add_definitions(-DTIDE_ENABLE_STREAM_DEBUGGING)
    endif()
    option(LOG_PEERS_SEPARATELY "give each peer its own log file" OFF)
    if(LOG_PEERS_SEPARATELY)
        add_definitions(-DTIDE_LOG_PEERS_SEPARATELY)
    endif()
    option(MERGE_TORRENT_LOGS "merge all torrent logs into engine's log file" OFF)
    if(MERGE_TORRENT_LOGS)
        add_definitions(-DTIDE_MERGE_TORRENT_LOGS)
    endif()
endif()

# Only name the source files' names, and create the full paths separately.
set(source_names 
    bdecode.cpp
    bencode.cpp
    disk_io.cpp
    disk_io_error.cpp
    engine.cpp
    file.cpp
    log.cpp
    message_parser.cpp
    metainfo.cpp
    path_sanitizer.cpp
    peer_session.cpp
    peer_session_error.cpp
    piece_download.cpp
    piece_picker.cpp
    random.cpp
    rate_limiter.cpp
    send_buffer.cpp
    sha1_hasher.cpp
    system.cpp
    thread_pool.cpp
    time.cpp
    torrent.cpp
    torrent_frontend.cpp
    torrent_handle.cpp
    torrent_storage.cpp
    tracker.cpp
    )

foreach(s ${source_names})
    list(APPEND tide_src ${CMAKE_CURRENT_SOURCE_DIR}/src/${s})
endforeach()

add_library(tide SHARED ${tide_src})

# Make headers available just by their names for internal use.
target_include_directories(tide PRIVATE
    # The actual location of the headers.
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/tide>
    # The format of the headers as included in the source files.
    $<INSTALL_INTERFACE:include/tide>
    )

#target_include_directories(tide PRIVATE
    ## The actual location of the headers.
    #$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/lib>
    ## The format of the headers as included in the source files.
    #$<INSTALL_INTERFACE:include>
    #)

# The public installation of the headers.
# TODO is this necessary?
target_include_directories(tide PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    )

# Include external libs.
#
# TODO turn these into a find_package command
target_include_directories(tide PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/lib/mio/include)
target_include_directories(tide PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/lib/endian/include)
target_include_directories(tide PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/lib/beast-asio-standalone/include)

# Find appropriate threading library.
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
if(Threads_FOUND)
    target_link_libraries(tide Threads::Threads)
else()
    message("Threads could not be found")
    return()
endif()

# TODO turn linking crypto this into a find_package command
target_link_libraries(tide crypto)

# Install library source.
install(TARGETS tide LIBRARY DESTINATION lib)

# Install tide header files.
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/tide DESTINATION include)
# Install the tide convenience header as well.
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/tide.hpp DESTINATION include)
# Install mio header files.
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib/mio/include/mio DESTINATION include)
# Install beast-asio-standalone header files.
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib/beast-asio-standalone/include/beast DESTINATION include)
