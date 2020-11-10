add_executable(test_aes test_aes.cc)
add_executable(test_aes_cuda test_aes_cuda.cu)

target_link_libraries(test_aes PRIVATE ${PROJECT_NAME}::Lib GTest::GTest GTest::Main)
target_link_libraries(test_aes_cuda PRIVATE ${PROJECT_NAME}::Lib GTest::GTest GTest::Main)

set_property(TARGET test_aes PROPERTY CUDA_SEPARABLE_COMPILATION ON)
set_property(TARGET test_aes_cuda PROPERTY CUDA_SEPARABLE_COMPILATION ON)

add_test(AesTests test_aes)
add_test(AesCudaTests test_aes_cuda)
