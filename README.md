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

# Build the `encrypt-*` executables (assuming one of the above 'aescuda' libraries has already been
# built). Note: If linking to the shared library, the library's location must be present in the
# LD_LIBRARY_PATH variable to run the program.
# e.g. `LD_LIBRARY_PATH="$PWD:${LD_LIBRARY_PATH}" ./encrypt-seq`
nvcc -dc -o src/enc-seq.cu.o src/enc.cu -Isrc -DRT_PARALLEL=0
nvcc -dc -o src/enc-par.cu.o src/enc.cu -Isrc -DRT_PARALLEL=1
nvcc     -o encrypt-seq src/enc-seq.cu.o src/config.cc -L. -laescuda -DRT_PARALLEL=0
nvcc     -o encrypt-par src/enc-par.cu.o src/config.cc -L. -laescuda -DRT_PARALLEL=1

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

### Run

To display the help menu, try running `encrypt-seq` or `encrypt-par` without any arguments.

```bash
$ ./encrypt-seq
Usage: encrypt-seq [options] [FILE]

  Encrypt/decrypt a given file on the CPU using AES with the CTR mode of operation.

Options:
  -h, --help         Display this help menu and exit.
  -V, --version      Display the version and exit.
  -e, --encrypt      Encrypt the file.
  -d, --decrypt      Decrypt the file.
  -k KEY, --key KEY  Specify the key to encrypt/decrypt the file.
  --128              Encrypt/decrypt the file using a 128-bit AES cipher.
  --192              Encrypt/decrypt the file using a 192-bit AES cipher.
  --256              Encrypt/decrypt the file using a 256-bit AES cipher [default].
```

Encrypt a given file, using the default cipher (AES-256-CTR) and a randomly-generated key.

```bash
$ # Create an 8 MiB size file of 0x00-bytes.
$ dd if=/dev/zero of=./8M-zero.bin bs=1M count=8 status=none
$ # Encrypt the file.
$ ./encrypt-par -e ./8M-zero.bin
[*] Key: ce8f2eee06d9a2c3394ccf904c0ca48e50c79ce21cac0804b78aed6f9ac6dba1
[*] memcpy() [host -> device] elapsed time: 1859 microseconds
[*] AES encrypt() CUDA kernel elapsed time: 8906 microseconds
[*] memcpy() [device -> host] elapsed time: 1775 microseconds
```

You can confirm that that file was encrypted by generating a hexdump of the first few bytes.

**Note:** _Even if you use the same key, your hexdump will be different, since a randomly-generated
nonce is used internally to ensure that the same sequence of bytes does not produce the same
ciphertext more than once._

```bash
$ xxd ./8M-zero.bin | head
00000000: 8f79 60db 0b6f 7429 361e 6e48 f414 2a4b  .y`..ot)6.nH..*K
00000010: 32f1 c3b8 784e 8fc8 a0b6 2e08 505a 8e4c  2...xN......PZ.L
00000020: a315 c5a7 15a4 7caa dab1 6c5b 5752 360d  ......|...l[WR6.
00000030: 19f1 fc80 549c 47a3 021a de70 39f7 f814  ....T.G....p9...
00000040: ce05 32d0 f6a9 800d 7745 6da8 27dc 2dba  ..2.....wEm.'.-.
00000050: 1179 b613 1eda f314 a892 a5aa 94fd 8c44  .y.............D
00000060: 5f52 36de 6aac f553 78a5 e796 eb29 0e12  _R6.j..Sx....)..
00000070: 867d 6266 e085 ab2d e36a 4457 bc11 8401  .}bf...-.jDW....
00000080: e017 8c50 2946 5873 6550 cb99 bd4a 6528  ...P)FXseP...Je(
00000090: 9277 eb80 1b6f 680b 63b3 29f0 41a9 2d2f  .w...oh.c.).A.-/
```

Next, decrypt the file, passing in the randomly-generated key from the encryption operation.

**Note:** _You must specify the same key that was used to encrypt the file, otherwise the file's
contents will be lost._

```bash
$ ./encrypt -d ./8M-zero.bin -k ce8f2eee06d9a2c3394ccf904c0ca48e50c79ce21cac0804b78aed6f9ac6dba1
[*] memcpy() [host -> device] elapsed time: 1856 microseconds
[*] AES encrypt() CUDA kernel elapsed time: 8932 microseconds
[*] memcpy() [device -> host] elapsed time: 1771 microseconds
```

Finally, confirm that the file's contents were decrypted properly.

```bash
$ xxd ./8M-zero.bin | head
00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000090: 0000 0000 0000 0000 0000 0000 0000 0000  ................
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
