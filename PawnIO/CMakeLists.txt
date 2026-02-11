wdk_add_driver(PawnIO
        src/callbacks.cpp
        src/driver.cpp
        src/natives_impl_windows.cpp
        src/signature.cpp
        src/vm.cpp
        $<$<STREQUAL:"${WDK_PLATFORM}","arm64">:src/msrmrs.cpp>
        $<$<STREQUAL:"${WDK_PLATFORM}","x64">:src/x64.asm>

        src/resource.rc
)

target_include_directories(PawnIO PUBLIC include)

target_link_libraries(PawnIO PawnPP WDK::KSECDD)

target_precompile_headers(PawnIO PRIVATE src/stdafx.h)

target_compile_options(PawnIO PRIVATE
        /utf-8
        /guard:ehcont
        /INTEGRITYCHECK
        /d1nodatetime
        /Brepro
        /Zi
)

target_link_options(PawnIO PRIVATE
        /DEBUG
        /OPT:REF
        /OPT:ICF=10
        /ENTRY:DriverEntry
        /EMITPOGOPHASEINFO
        /INTEGRITYCHECK
        /FILEALIGN:0x1000
        $<$<STREQUAL:"${WDK_PLATFORM}","x64">:/CETCOMPAT>
        $<$<NOT:$<STREQUAL:"${CMAKE_BUILD_TYPE}","Debug">>:/BREPRO>
        $<$<NOT:$<STREQUAL:"${CMAKE_BUILD_TYPE}","Debug">>:/NOVCFEATURE>
        $<$<NOT:$<STREQUAL:"${CMAKE_BUILD_TYPE}","Debug">>:/NOCOFFGRPINFO>
        $<$<NOT:$<STREQUAL:"${CMAKE_BUILD_TYPE}","Debug">>:/PDBALTPATH:%_PDB%>
)

set_target_properties(PawnIO PROPERTIES OUTPUT_NAME "${PAWNIO_NAME}_unsigned")

if ("${SIGN_SCRIPT}" STREQUAL "")
    add_custom_command(
            OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.sys"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:PawnIO>"
            "${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.sys"
            DEPENDS "$<TARGET_FILE:PawnIO>"
            VERBATIM
    )
else ()
    add_custom_command(
            OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.sys"
            COMMAND "${SIGN_SCRIPT}"
            "$<TARGET_FILE:PawnIO>"
            "${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.sys"
            DEPENDS "$<TARGET_FILE:PawnIO>"
            VERBATIM
    )
endif ()

if (WDK_PLATFORM STREQUAL "x64")
    set(INF_ARCH "ntamd64")
elseif (WDK_PLATFORM STREQUAL "arm64")
    set(INF_ARCH "ntarm64")
endif ()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/PawnIO.inf.in ${CMAKE_CURRENT_BINARY_DIR}/PawnIO.inf.in @ONLY)
file(GENERATE OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.inf INPUT ${CMAKE_CURRENT_BINARY_DIR}/PawnIO.inf.in)

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.cat
        COMMAND "${INF2CAT}"
        "/driver:${CMAKE_CURRENT_BINARY_DIR}"
        "/os:10_RS5_${WDK_PLATFORM},ServerRS5_${WDK_PLATFORM},10_GE_${WDK_PLATFORM},Server2025_${WDK_PLATFORM}"
        "/verbose"
        "/pageHashes"
        DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.sys" "${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.inf"
)

file(GENERATE OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cab.ddf CONTENT "
.OPTION EXPLICIT
.Set CabinetFileCountThreshold=0
.Set FolderFileCountThreshold=0
.Set FolderSizeThreshold=0
.Set MaxCabinetSize=0
.Set MaxDiskFileCount=0
.Set MaxDiskSize=0
.Set CompressionType=MSZIP
.Set Cabinet=on
.Set Compress=on
${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.sys
${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.inf
${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.cat
")

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.cab
        COMMAND "${MAKECAB}" /V0 /D "DiskDirectory1=${CMAKE_CURRENT_BINARY_DIR}" /D "CabinetNameTemplate=${PAWNIO_NAME}.cab" /F "${CMAKE_CURRENT_BINARY_DIR}/cab.ddf"
        DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.sys" "${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.inf" "${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.cat"
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        COMMENT "Creating CAB package..."
        VERBATIM
)

add_custom_target(PawnIO_CAB ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.cab)
