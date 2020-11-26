//
// Copyright (c) 2020 Zakaria Essadaoui, Joshua Inscoe, Alexandra Livadas, Angel Ortiz-Regules
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
// associated documentation files (the "Software"), to deal in the Software without restriction,
// including without limitation the rights to use, copy, modify, merge, publish, distribute,
// sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or
// substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
// NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//


#define AES_DEBUG_
#include "aes.hh"

#include <cstdint>

#include <cuda_runtime.h>
#include <device_launch_parameters.h>

#include <gtest/gtest.h>


using crypto::Aes128;
using crypto::Aes192;
using crypto::Aes256;


namespace { // anonymous

__global__ void aes128encrypt(unsigned char* blk, Aes128 const* cipher) { cipher->encrypt(blk); }
__global__ void aes192encrypt(unsigned char* blk, Aes192 const* cipher) { cipher->encrypt(blk); }
__global__ void aes256encrypt(unsigned char* blk, Aes256 const* cipher) { cipher->encrypt(blk); }

} // anonymous namespace


TEST(AesEncryptCudaTest, Aes128) {
    // Example 128-bit cipher key taken from NIST FIPS-197 Appendix C.1.
    constexpr unsigned char const key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    cudaError_t error;
    Aes128* cipher = nullptr;
    unsigned char* blk = nullptr;

    error = cudaMallocManaged(&cipher, sizeof(Aes128));
    if (error) {
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }
    cipher = new(cipher) Aes128(key);
    error = cudaMallocManaged(&blk, sizeof(char) * 16);
    if (error) {
        cudaFree(cipher);
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }

    // Example plaintext taken from NIST FIPS-197 Appendix C.1.
    blk[ 0] = 0x00; blk[ 1] = 0x11; blk[ 2] = 0x22; blk[ 3] = 0x33;
    blk[ 4] = 0x44; blk[ 5] = 0x55; blk[ 6] = 0x66; blk[ 7] = 0x77;
    blk[ 8] = 0x88; blk[ 9] = 0x99; blk[10] = 0xaa; blk[11] = 0xbb;
    blk[12] = 0xcc; blk[13] = 0xdd; blk[14] = 0xee; blk[15] = 0xff;

    aes128encrypt<<<1, 1>>>(blk, cipher);

    cudaDeviceSynchronize();

    EXPECT_EQ(blk[ 0], 0x69);
    EXPECT_EQ(blk[ 1], 0xc4);
    EXPECT_EQ(blk[ 2], 0xe0);
    EXPECT_EQ(blk[ 3], 0xd8);
    EXPECT_EQ(blk[ 4], 0x6a);
    EXPECT_EQ(blk[ 5], 0x7b);
    EXPECT_EQ(blk[ 6], 0x04);
    EXPECT_EQ(blk[ 7], 0x30);
    EXPECT_EQ(blk[ 8], 0xd8);
    EXPECT_EQ(blk[ 9], 0xcd);
    EXPECT_EQ(blk[10], 0xb7);
    EXPECT_EQ(blk[11], 0x80);
    EXPECT_EQ(blk[12], 0x70);
    EXPECT_EQ(blk[13], 0xb4);
    EXPECT_EQ(blk[14], 0xc5);
    EXPECT_EQ(blk[15], 0x5a);

    cipher->~Aes128();
    cudaFree(cipher);
    cudaFree(blk);
}

TEST(AesEncryptCudaTest, Aes192) {
    // Example 192-bit cipher key taken from NIST FIPS-197 Appendix C.2.
    constexpr unsigned char const key[24] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };

    cudaError_t error;
    Aes192* cipher = nullptr;
    unsigned char* blk = nullptr;

    error = cudaMallocManaged(&cipher, sizeof(Aes192));
    if (error) {
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }
    cipher = new(cipher) Aes192(key);
    error = cudaMallocManaged(&blk, sizeof(char) * 16);
    if (error) {
        cudaFree(cipher);
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }

    // Example plaintext taken from NIST FIPS-197 Appendix C.2.
    blk[ 0] = 0x00; blk[ 1] = 0x11; blk[ 2] = 0x22; blk[ 3] = 0x33;
    blk[ 4] = 0x44; blk[ 5] = 0x55; blk[ 6] = 0x66; blk[ 7] = 0x77;
    blk[ 8] = 0x88; blk[ 9] = 0x99; blk[10] = 0xaa; blk[11] = 0xbb;
    blk[12] = 0xcc; blk[13] = 0xdd; blk[14] = 0xee; blk[15] = 0xff;

    aes192encrypt<<<1, 1>>>(blk, cipher);

    cudaDeviceSynchronize();

    EXPECT_EQ(blk[ 0], 0xdd);
    EXPECT_EQ(blk[ 1], 0xa9);
    EXPECT_EQ(blk[ 2], 0x7c);
    EXPECT_EQ(blk[ 3], 0xa4);
    EXPECT_EQ(blk[ 4], 0x86);
    EXPECT_EQ(blk[ 5], 0x4c);
    EXPECT_EQ(blk[ 6], 0xdf);
    EXPECT_EQ(blk[ 7], 0xe0);
    EXPECT_EQ(blk[ 8], 0x6e);
    EXPECT_EQ(blk[ 9], 0xaf);
    EXPECT_EQ(blk[10], 0x70);
    EXPECT_EQ(blk[11], 0xa0);
    EXPECT_EQ(blk[12], 0xec);
    EXPECT_EQ(blk[13], 0x0d);
    EXPECT_EQ(blk[14], 0x71);
    EXPECT_EQ(blk[15], 0x91);

    cipher->~Aes192();
    cudaFree(cipher);
    cudaFree(blk);
}

TEST(AesEncryptCudaTest, Aes256) {
    // Example 256-bit cipher key taken from NIST FIPS-197 Appendix C.3.
    constexpr unsigned char const key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    cudaError_t error;
    Aes256* cipher = nullptr;
    unsigned char* blk = nullptr;

    error = cudaMallocManaged(&cipher, sizeof(Aes256));
    if (error) {
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }
    cipher = new(cipher) Aes256(key);
    error = cudaMallocManaged(&blk, sizeof(char) * 16);
    if (error) {
        cudaFree(cipher);
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }

    // Example plaintext taken from NIST FIPS-197 Appendix C.3.
    blk[ 0] = 0x00; blk[ 1] = 0x11; blk[ 2] = 0x22; blk[ 3] = 0x33;
    blk[ 4] = 0x44; blk[ 5] = 0x55; blk[ 6] = 0x66; blk[ 7] = 0x77;
    blk[ 8] = 0x88; blk[ 9] = 0x99; blk[10] = 0xaa; blk[11] = 0xbb;
    blk[12] = 0xcc; blk[13] = 0xdd; blk[14] = 0xee; blk[15] = 0xff;

    aes256encrypt<<<1, 1>>>(blk, cipher);

    cudaDeviceSynchronize();

    EXPECT_EQ(blk[ 0], 0x8e);
    EXPECT_EQ(blk[ 1], 0xa2);
    EXPECT_EQ(blk[ 2], 0xb7);
    EXPECT_EQ(blk[ 3], 0xca);
    EXPECT_EQ(blk[ 4], 0x51);
    EXPECT_EQ(blk[ 5], 0x67);
    EXPECT_EQ(blk[ 6], 0x45);
    EXPECT_EQ(blk[ 7], 0xbf);
    EXPECT_EQ(blk[ 8], 0xea);
    EXPECT_EQ(blk[ 9], 0xfc);
    EXPECT_EQ(blk[10], 0x49);
    EXPECT_EQ(blk[11], 0x90);
    EXPECT_EQ(blk[12], 0x4b);
    EXPECT_EQ(blk[13], 0x49);
    EXPECT_EQ(blk[14], 0x60);
    EXPECT_EQ(blk[15], 0x89);

    cipher->~Aes256();
    cudaFree(cipher);
    cudaFree(blk);
}
