set(STATIC_LIBRARY aescuda)
set(SHARED_LIBRARY aescuda_shared)

add_library(${STATIC_LIBRARY} STATIC aes.cu)
add_library(${PROJECT_NAME}::Lib ALIAS ${STATIC_LIBRARY})
add_library(${SHARED_LIBRARY} SHARED aes.cu)

add_executable(encrypt-seq enc.cu config.cc)
add_executable(encrypt-par enc.cu config.cc)

set_property(TARGET encrypt-seq APPEND PROPERTY COMPILE_DEFINITIONS RT_PARALLEL=0)
set_property(TARGET encrypt-par APPEND PROPERTY COMPILE_DEFINITIONS RT_PARALLEL=1)

set_target_properties(
    ${STATIC_LIBRARY} ${SHARED_LIBRARY} encrypt-seq encrypt-par
    PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
    )

target_link_libraries(encrypt-seq PRIVATE ${PROJECT_NAME}::Lib)
target_link_libraries(encrypt-par PRIVATE ${PROJECT_NAME}::Lib)
