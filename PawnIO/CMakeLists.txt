if (MSVC)
    # CMake enables /RTC1 in Debug by default, but its user-mode support
    # routines are unavailable to kernel drivers.
    string(REGEX REPLACE "(^| )[/-]RTC1( |$)" " " CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
endif ()

set(PAWNIO_ARCH_SOURCES)
if (WDK_PLATFORM STREQUAL "x64")
    add_library(PawnIOAsm OBJECT src/x64.asm)
    target_compile_options(PawnIOAsm PRIVATE /Zi)
    list(APPEND PAWNIO_ARCH_SOURCES $<TARGET_OBJECTS:PawnIOAsm>)
elseif (WDK_PLATFORM STREQUAL "arm64")
    list(APPEND PAWNIO_ARCH_SOURCES src/msrmrs.cpp)
endif ()

wdk_add_driver(PawnIO
        src/callbacks.cpp
        src/driver.cpp
        src/natives_impl_windows.cpp
        src/signature.cpp
        src/vm.cpp
        ${PAWNIO_ARCH_SOURCES}

        src/resource.rc
)

set_target_properties(PawnIO PROPERTIES ENABLE_EXPORTS ON)

add_library(PawnIOInclude INTERFACE)
target_include_directories(PawnIOInclude INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(PawnIO PawnIOInclude PawnPP PawnIOBuildInfo WDK::KSECDD)

target_precompile_headers(PawnIO PRIVATE src/stdafx.h)

target_compile_options(PawnIO PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/utf-8>
        $<$<COMPILE_LANGUAGE:CXX>:/guard:ehcont>
        $<$<COMPILE_LANGUAGE:CXX>:/d1nodatetime>
        $<$<COMPILE_LANGUAGE:CXX>:/Brepro>
        $<$<COMPILE_LANGUAGE:CXX>:/Zi>
        $<$<COMPILE_LANGUAGE:CXX>:/W4>
        $<$<COMPILE_LANGUAGE:CXX>:/WX>
)

target_link_options(PawnIO PRIVATE
        /guard:ehcont
        /DEBUG
        /OPT:REF
        /OPT:ICF=10
        /EMITPOGOPHASEINFO
        /INTEGRITYCHECK
        /FILEALIGN:0x1000
        $<$<STREQUAL:"${WDK_PLATFORM}","x64">:/CETCOMPAT>
        $<$<NOT:$<CONFIG:Debug>>:/BREPRO>
        $<$<NOT:$<CONFIG:Debug>>:/NOVCFEATURE>
        $<$<NOT:$<CONFIG:Debug>>:/NOCOFFGRPINFO>
        $<$<NOT:$<CONFIG:Debug>>:/PDBALTPATH:%_PDB%>
)

if (PAWNIO_UNRESTRICTED)
    target_compile_definitions(PawnIO PRIVATE PAWNIO_UNRESTRICTED)
endif ()

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

set(DRIVER_DIR "${CMAKE_CURRENT_BINARY_DIR}/driver")
file(MAKE_DIRECTORY "${DRIVER_DIR}")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/PawnIO.inf.in ${CMAKE_CURRENT_BINARY_DIR}/PawnIO.inf.in @ONLY)
file(GENERATE OUTPUT ${DRIVER_DIR}/${PAWNIO_NAME}.inf INPUT ${CMAKE_CURRENT_BINARY_DIR}/PawnIO.inf.in)

add_custom_command(
        OUTPUT ${DRIVER_DIR}/${PAWNIO_NAME}.sys
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.sys"
        "${DRIVER_DIR}/${PAWNIO_NAME}.sys"
        DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.sys"
        VERBATIM
)

add_custom_command(
        OUTPUT ${DRIVER_DIR}/${PAWNIO_NAME}.cat
        COMMAND "${INF2CAT}"
        "/driver:${DRIVER_DIR}"
        "/os:10_RS5_${WDK_PLATFORM},ServerRS5_${WDK_PLATFORM},10_GE_${WDK_PLATFORM},Server2025_${WDK_PLATFORM}"
        "/verbose"
        "/pageHashes"
        DEPENDS "${DRIVER_DIR}/${PAWNIO_NAME}.sys" "${DRIVER_DIR}/${PAWNIO_NAME}.inf"
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
${DRIVER_DIR}/${PAWNIO_NAME}.sys driver/${PAWNIO_NAME}.sys
${DRIVER_DIR}/${PAWNIO_NAME}.inf driver/${PAWNIO_NAME}.inf
${DRIVER_DIR}/${PAWNIO_NAME}.cat driver/${PAWNIO_NAME}.cat
")

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.cab
        COMMAND "${MAKECAB}" /V0 /D "DiskDirectory1=${CMAKE_CURRENT_BINARY_DIR}" /D "CabinetNameTemplate=${PAWNIO_NAME}.cab" /F "${CMAKE_CURRENT_BINARY_DIR}/cab.ddf"
        DEPENDS "${DRIVER_DIR}/${PAWNIO_NAME}.sys" "${DRIVER_DIR}/${PAWNIO_NAME}.inf" "${DRIVER_DIR}/${PAWNIO_NAME}.cat"
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        COMMENT "Creating CAB package..."
        VERBATIM
)

add_custom_target(PawnIO_CAB ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${PAWNIO_NAME}.cab)
