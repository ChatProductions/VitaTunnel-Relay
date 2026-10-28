cmake_minimum_required(VERSION 3.10)
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "Vita toolchain")
  else()
    message(FATAL_ERROR "Set VITASDK, or specify CMAKE_TOOLCHAIN_FILE")
  endif()
endif()
project(VitaTunnel C)
include("$ENV{VITASDK}/share/vita.cmake")
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wl,-q -Wl,-z,noexecstack")
set(VITA_MAKE_FSELF_FLAGS "${VITA_MAKE_FSELF_FLAGS} -a 0x2808000000000000")

# Installer code is pinned from upstream and fetched by tools/prepare_vendor.sh.
foreach(f vpk_installer.c vpk_zip.c sha1.c head_bin.h)
  if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/installer/src/${f}")
    message(FATAL_ERROR "Missing vendor/installer/src/${f}. Run tools/prepare_vendor.sh")
  endif()
endforeach()
add_executable(vitatunnel src/main.c src/protocol.c src/report.c
  vendor/installer/src/vpk_installer.c vendor/installer/src/vpk_zip.c
  vendor/installer/src/sha1.c)
target_include_directories(vitatunnel PRIVATE src vendor/installer/src)
target_link_libraries(vitatunnel PRIVATE
  zip zstd lzma bz2 curl ssl crypto z
  vita2d freetype png jpeg
  SceNet_stub SceNetCtl_stub SceSsl_stub SceHttp_stub
  ScePromoterUtil_stub SceSysmodule_stub SceAppMgr_stub SceAppUtil_stub
  SceDisplay_stub SceGxm_stub SceCtrl_stub ScePower_stub ScePgf_stub
  SceCommonDialog_stub m pthread)
vita_create_self(eboot.bin vitatunnel UNSAFE)
vita_create_vpk(VitaTunnel.vpk VITATUNN1 eboot.bin
  VERSION 01.00 NAME "VitaTunnel"
  FILE assets/cacert.pem cacert.pem
  FILE assets/icon0.png sce_sys/icon0.png
  FILE assets/bg.png sce_sys/livearea/contents/bg.png
  FILE assets/startup.png sce_sys/livearea/contents/startup.png
  FILE assets/template.xml sce_sys/livearea/contents/template.xml)
