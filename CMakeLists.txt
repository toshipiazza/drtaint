cmake_minimum_required (VERSION 3.0)
project (drtaint)

set(DynamoRIO_DIR         /home/piazzt/SD/Build/dynamorio/exports/cmake)
set(DrMemoryFramework_DIR /home/piazzt/install/exports32/drmf)

set(CMAKE_CXX_STANDARD 11)
add_library(drtaint SHARED
  sample_app.c
  drtaint.cpp
  drtaint_shadow.c
  drtaint_helper.cpp)
find_package(DynamoRIO REQUIRED)
find_package(DrMemoryFramework REQUIRED)
configure_DynamoRIO_client(drtaint)
use_DynamoRIO_extension(drtaint "drreg")
use_DynamoRIO_extension(drtaint "drmgr")
use_DynamoRIO_extension(drtaint "umbra")
use_DynamoRIO_extension(drtaint "drutil")
