cmake_minimum_required(VERSION 3.12)
project(http2-client)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(
  Boost
  COMPONENTS url program_options
  REQUIRED)
find_package(OpenSSL REQUIRED)

find_path(NGHTTP2_INCLUDE_DIRS "nghttp2/nghttp2.h")
find_library(NGHTTP2_LIBRARIES NAMES nghttp2)

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/src/*.cpp)

add_executable(${PROJECT_NAME} ${SOURCES})
target_include_directories(
  ${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/include ${Boost_INCLUDE_DIRS}
                          ${OPENSSL_INCLUDE_DIR} ${NGHTTP2_INCLUDE_DIRS})
target_link_libraries(
  ${PROJECT_NAME} PRIVATE ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES}
                          ${NGHTTP2_LIBRARIES})
