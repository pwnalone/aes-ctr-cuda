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
nvcc -dc -o test/test_aes_cuda.cu.o test/test_aes_cuda.cu  -Isrc
nvcc     -o test/test_aes      test/test_aes.cc.o      -L. -laescuda -lgtest -lgtest_main  # CPU-bound tests
nvcc     -o test/test_aes_cuda test/test_aes_cuda.cu.o -L. -laescuda -lgtest -lgtest_main  # GPU-bound tests
```

### Test

Run the CPU-bound unit tests. These tests ensure that the implementations of AES key expansion and
single-block encryption are correct.

```bash
build/test/test_aes
```

Run the GPU-bound unit tests. These tests ensure that AES encryption works as expected on the GPU.
AES key expansion is not tested, since it is a CPU-only operation.

```bash
build/test/test_aes_cuda
```
