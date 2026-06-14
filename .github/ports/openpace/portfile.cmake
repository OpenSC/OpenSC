vcpkg_check_linkage(ONLY_STATIC_LIBRARY)

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO frankmorgner/openpace
    REF ${VERSION}
    SHA512 9236de244e4c306223c7051f3c2cd0df155ca473d69d55b22f97e4050ed9c30a037511851e3afcb75745f3e95c5b79d2d96e3e2f8e23e692a07f3e0530cf5b40
    HEAD_REF master
)

file(COPY "${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt" DESTINATION "${SOURCE_PATH}/src")

vcpkg_cmake_configure(SOURCE_PATH "${SOURCE_PATH}/src")
vcpkg_cmake_install()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/COPYING")
