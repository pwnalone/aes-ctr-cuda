# GPU-Accelerated AES-128/192/256-CTR Encryption

### Prerequisites

- CUDA-capable GPU
- Compiler with C++14 support
- NVIDIA CUDA Toolkit
- (optional) CMake 3.10 or higher (for easy compilation)
- (optional) Googletest (for running unit tests)

### Compile

If you have CMake 3.10 or higher installed on your system, compilation is very simple.

```bash
./build.sh
```

Otherwise, you will need to build the code manually.

```bash
# Build the libaescuda.a  static library.
nvcc -dc -o src/aes.cu.o src/aes.cu -Isrc
ar r libaescuda.a src/aes.cu.o
ranlib libaescuda.a

# Build the libaescuda.so shared library.
nvcc -dc -o src/aes.cu.o src/aes.cu -Isrc --compiler-options '-fPIC'
nvcc     -o libaescuda.so src/aes.cu.o    --compiler-options '-fPIC' --shared

# Build the tests.
nvcc -dc -o test/test_aes.cc.o      test/test_aes.cc       -Isrc
nvcc -dc -o test/test_fsc.cc.o      test/test_fsc.cc       -Isrc
nvcc -dc -o test/test_ctr.cc.o      test/test_ctr.cc       -Isrc
nvcc -dc -o test/test_aes_cuda.cu.o test/test_aes_cuda.cu  -Isrc
nvcc -dc -o test/test_fsc_cuda.cu.o test/test_fsc_cuda.cu  -Isrc
nvcc -dc -o test/test_ctr_cuda.cu.o test/test_ctr_cuda.cu  -Isrc
nvcc     -o test/test_aes      test/test_aes.cc.o      -L. -laescuda -lgtest -lgtest_main  # CPU-bound tests
nvcc     -o test/test_fsc      test/test_fsc.cc.o      -L.           -lgtest -lgtest_main
nvcc     -o test/test_ctr      test/test_ctr.cc.o      -L. -laescuda -lgtest -lgtest_main
nvcc     -o test/test_aes_cuda test/test_aes_cuda.cu.o -L. -laescuda -lgtest -lgtest_main  # GPU-bound tests
nvcc     -o test/test_fsc_cuda test/test_fsc_cuda.cc.o -L.           -lgtest -lgtest_main
nvcc     -o test/test_ctr_cuda test/test_ctr_cuda.cu.o -L. -laescuda -lgtest -lgtest_main
```

### Test

Run all the unit tests at once using CMake.

```bash
cmake --build build --target test
```

Or run them individually. This will provide more detailed output.

```bash
build/test/test_aes
build/test/test_aes_cuda
build/test/test_fsc
build/test/test_fsc_cuda
build/test/test_ctr
build/test/test_ctr_cuda
```
