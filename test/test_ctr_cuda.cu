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


#include "aes.hh"
#include "ctr.hh"
#include "util.hh"

#include <algorithm>
#include <array>

#include <cuda_runtime.h>
#include <device_launch_parameters.h>

#include <gtest/gtest.h>


#define ARRAY_SIZE 4096


using crypto::Aes128;
using crypto::Aes192;
using crypto::Aes256;
using crypto::CtrMode;


namespace { // anonymous

constexpr unsigned char const nonce_0[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
constexpr unsigned char const nonce_1[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};
constexpr unsigned char const nonce_2[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
};
constexpr unsigned char const nonce_3[16] = {
    0x9d, 0x8b, 0xe8, 0xec, 0x25, 0x29, 0xbd, 0x5a,
    0x3d, 0xbc, 0x45, 0x2e, 0x8b, 0x2a, 0x46, 0xb8
};
constexpr unsigned char const nonce_4[16] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe
};
constexpr unsigned char const nonce_5[16] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};


template <typename BlockCipherType>
__global__ void encrypt(CtrMode<BlockCipherType> const* cipher, unsigned char* data, size_t size)
{
    constexpr size_t blk_size = CtrMode<BlockCipherType>::blk_size;
    size_t threads = gridDim.x * blockDim.x;
    size_t blks = size / blk_size;
    size_t blks_per_thread = (blks + threads - 1) / threads;
    size_t offset = (blockDim.x * blockIdx.x + threadIdx.x) * blks_per_thread;
    if (offset <= blks) {
        data += offset * blk_size;
        size -= offset * blk_size;
        size = crypto::util::min(blks_per_thread * blk_size, size);
        cipher->encrypt(data, size, offset);
    }
}


template <typename StreamCipherType>
void test_ctr_mode_decryption(StreamCipherType const* cipher)
{
    std::array<unsigned char, 16> const bytes = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    std::array<unsigned char, ARRAY_SIZE> ptext { };
    std::array<unsigned char, ARRAY_SIZE> ctext { };

    unsigned char* data = nullptr;
    cudaError_t error = cudaMallocManaged(&data, sizeof(char) * ARRAY_SIZE);
    if (error) {
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }

    size_t const threads = ARRAY_SIZE / StreamCipherType::blk_size;

    // Test that double-encrypting with the same nonce and key produces the original plaintext.
    for (auto const byte : bytes) {
        std::fill(ptext.begin(), ptext.end(), byte);
        std::fill(data, data + ARRAY_SIZE, byte);
        encrypt<<<1, threads>>>(cipher, data, ARRAY_SIZE);
        cudaDeviceSynchronize();
        std::copy(data, data + ARRAY_SIZE, ctext.begin());
        EXPECT_NE(ptext, ctext);
        encrypt<<<1, threads>>>(cipher, data, ARRAY_SIZE);
        cudaDeviceSynchronize();
        std::copy(data, data + ARRAY_SIZE, ctext.begin());
        EXPECT_EQ(ptext, ctext);
    }

    cudaFree(data);
}

} // anonymous namespace


TEST(CtrModeCudaTest, Aes128) {
    // Example 128-bit cipher key taken from NIST FIPS-197 Appendix A.1.
    constexpr unsigned char const key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    CtrMode<Aes128>* cipher = nullptr;
    cudaError_t error = cudaMallocManaged(&cipher, sizeof(*cipher));
    if (error) {
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }

    // Test decryption (i.e. double-encryption with same nonce and key).
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes128>(key, nonce_0));
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes128>(key, nonce_1));
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes128>(key, nonce_2));
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes128>(key, nonce_3));
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes128>(key, nonce_4));
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes128>(key, nonce_5));

    cipher->~CtrMode<Aes128>();
    cudaFree(cipher);
}

TEST(CtrModeCudaTest, Aes192) {
    // Example 192-bit cipher key taken from NIST FIPS-197 Appendix A.2.
    constexpr unsigned char const key[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    CtrMode<Aes192>* cipher = nullptr;
    cudaError_t error = cudaMallocManaged(&cipher, sizeof(*cipher));
    if (error) {
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }

    // Test decryption (i.e. double-encryption with same nonce and key).
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes192>(key, nonce_0));
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes192>(key, nonce_1));
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes192>(key, nonce_2));
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes192>(key, nonce_3));
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes192>(key, nonce_4));
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes192>(key, nonce_5));

    cipher->~CtrMode<Aes192>();
    cudaFree(cipher);
}

TEST(CtrModeCudaTest, Aes256) {
    // Example 256-bit cipher key taken from NIST FIPS-197 Appendix A.3.
    constexpr unsigned char const key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    CtrMode<Aes256>* cipher = nullptr;
    cudaError_t error = cudaMallocManaged(&cipher, sizeof(*cipher));
    if (error) {
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }

    // Test decryption (i.e. double-encryption with same nonce and key).
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes256>(key, nonce_0));
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes256>(key, nonce_1));
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes256>(key, nonce_2));
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes256>(key, nonce_3));
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes256>(key, nonce_4));
    test_ctr_mode_decryption(new(cipher) CtrMode<Aes256>(key, nonce_5));

    cipher->~CtrMode<Aes256>();
    cudaFree(cipher);
}
