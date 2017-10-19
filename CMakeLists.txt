cmake_minimum_required(VERSION 3.9.2)
project(tide)

add_definitions(-std=c++14)

# Only name the source files, and create the full paths separately.
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
    # The actual location of the headers used in the source files.
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/tide>
    # The format of the headers used in the source files.
    $<INSTALL_INTERFACE:include/tide>
    )

# The public installation of the headers.
# TODO is this necessary?
target_include_directories(tide PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    )

# Include mio (memory mapping) library.
# TODO turn this into a find_package command
target_include_directories(tide PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/lib/mio/include)

# Find appropriate threading library.
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
if(Threads_FOUND)
    target_link_libraries(tide Threads::Threads)
else()
    message("Threads could not be found")
    return()
endif()

# Find required Boost components.
find_package(Boost REQUIRED COMPONENTS filesystem system)
if(Boost_FOUND)
    target_link_libraries(tide Boost::filesystem Boost::system)
else()
    message("Boost could not be found")
    return()
endif()

# TODO turn linking crypto this into a find_package command
target_link_libraries(tide crypto)

# Install library source.
install(TARGETS tide LIBRARY DESTINATION lib)

# Install header files.
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/tide DESTINATION include)

# Install the convenience header as well.
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/tide.hpp DESTINATION include)
