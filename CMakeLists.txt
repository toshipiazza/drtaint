cmake_minimum_required (VERSION 3.0)
project (drtaint)

set(DynamoRIO_DIR         /home/piazzt/SD/Build/dynamorio/exports/cmake)
set(DrMemoryFramework_DIR /home/piazzt/install/exports32/drmf)

set(CMAKE_CXX_STANDARD 11)
add_library(draslrharden SHARED
  app/draslrharden.cpp
  drtaint.cpp
  drtaint_shadow.c
  drtaint_helper.cpp)
add_library(drtaint SHARED
  app/drtaint_only.cpp
  drtaint.cpp
  drtaint_shadow.c
  drtaint_helper.cpp)
find_package(DynamoRIO REQUIRED)
find_package(DrMemoryFramework REQUIRED)

configure_DynamoRIO_client(draslrharden)
use_DynamoRIO_extension(draslrharden "drreg")
use_DynamoRIO_extension(draslrharden "drmgr")
use_DynamoRIO_extension(draslrharden "drutil")
use_DynamoRIO_extension(draslrharden "drx")
use_DynamoRIO_extension(draslrharden "droption")
use_DynamoRIO_extension(draslrharden "umbra")
use_DynamoRIO_extension(draslrharden "drsyscall")

configure_DynamoRIO_client(drtaint)
use_DynamoRIO_extension(drtaint "drreg")
use_DynamoRIO_extension(drtaint "drmgr")
use_DynamoRIO_extension(drtaint "drutil")
use_DynamoRIO_extension(drtaint "drx")
use_DynamoRIO_extension(drtaint "umbra")
use_DynamoRIO_extension(drtaint "drsyscall")
