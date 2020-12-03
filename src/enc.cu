//
// Copyright (c) 2018 Zakaria Essadaoui, Joshua Inscoe, Alexandra Livadas, Angel Ortiz-Regules
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


#include <algorithm>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

#if defined(RT_PARALLEL) && RT_PARALLEL != 0
#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#endif

#include "aes.hh"
#include "ctr.hh"

#include "config.hh"
#include "timer.hh"
#include "util.hh"


using crypto::Aes128;
using crypto::Aes192;
using crypto::Aes256;
using crypto::CtrMode;


namespace { // anonymous

constexpr size_t blk_size = Aes128::blk_size;


#if defined(RT_PARALLEL) && RT_PARALLEL != 0

#define SRCLOC() __FILE__ << ":" << __LINE__ << ": "

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

int aes_ctr_encrypt(
    Config const& config, unsigned char const nonce[blk_size], void* data, size_t size
    )
{
    Timer<std::chrono::microseconds> timer { };
    auto timedelta = timer.time();

    cudaError_t deverror { };
    unsigned char* data_d = nullptr;
    CtrMode<Aes128>* aes128ctr_d = nullptr;
    CtrMode<Aes192>* aes192ctr_d = nullptr;
    CtrMode<Aes256>* aes256ctr_d = nullptr;
    CtrMode<Aes128>  aes128ctr_h { &config.key[0], nonce };
    CtrMode<Aes192>  aes192ctr_h { &config.key[0], nonce };
    CtrMode<Aes256>  aes256ctr_h { &config.key[0], nonce };

    // Allocate memory on the GPU and copy the file data over from the CPU.
    deverror = cudaMalloc(&data_d, size);
    if (deverror) {
        std::cerr << SRCLOC() << "[!] error: " << cudaGetErrorString(deverror) << "\n";
        goto _fail;
    }
    timedelta = timer.time();
    deverror = cudaMemcpy(data_d, data, size, cudaMemcpyHostToDevice);
    if (deverror) {
        std::cerr << SRCLOC() << "[!] error: " << cudaGetErrorString(deverror) << "\n";
        goto _fail;
    }
    timedelta = timer.time();

    std::cout << "[*] memcpy() [host -> device] elapsed time: " << timedelta << " microseconds\n";

    // Allocate memory on the GPU for the cipher classes.
    deverror = cudaMalloc(&aes128ctr_d, sizeof(aes128ctr_h));
    if (deverror) {
        std::cerr << SRCLOC() << "[!] error: " << cudaGetErrorString(deverror) << "\n";
        goto _fail;
    }
    deverror = cudaMalloc(&aes192ctr_d, sizeof(aes192ctr_h));
    if (deverror) {
        std::cerr << SRCLOC() << "[!] error: " << cudaGetErrorString(deverror) << "\n";
        goto _fail;
    }
    deverror = cudaMalloc(&aes256ctr_d, sizeof(aes256ctr_h));
    if (deverror) {
        std::cerr << SRCLOC() << "[!] error: " << cudaGetErrorString(deverror) << "\n";
        goto _fail;
    }

    // Copy the cipher classes to the GPU.
    deverror = cudaMemcpy(aes128ctr_d, &aes128ctr_h, sizeof(aes128ctr_h), cudaMemcpyHostToDevice);
    if (deverror) {
        std::cerr << SRCLOC() << "[!] error: " << cudaGetErrorString(deverror) << "\n";
        goto _fail;
    }
    deverror = cudaMemcpy(aes192ctr_d, &aes192ctr_h, sizeof(aes192ctr_h), cudaMemcpyHostToDevice);
    if (deverror) {
        std::cerr << SRCLOC() << "[!] error: " << cudaGetErrorString(deverror) << "\n";
        goto _fail;
    }
    deverror = cudaMemcpy(aes256ctr_d, &aes256ctr_h, sizeof(aes256ctr_h), cudaMemcpyHostToDevice);
    if (deverror) {
        std::cerr << SRCLOC() << "[!] error: " << cudaGetErrorString(deverror) << "\n";
        goto _fail;
    }

    // Perform AES encryption using CTR mode for the proper key size.
    timedelta = timer.time();
    switch (config.key_size) {
    case 128: encrypt<<<1024, 1024>>>(aes128ctr_d, data_d, size); break;
    case 192: encrypt<<<1024, 1024>>>(aes192ctr_d, data_d, size); break;
    case 256: encrypt<<<1024, 1024>>>(aes256ctr_d, data_d, size); break;
    default:
        assert("Unsupported AES key size" && false);
        goto _fail;
    }
    cudaDeviceSynchronize();
    timedelta = timer.time();

    std::cout << "[*] AES encrypt() CUDA kernel elapsed time: " << timedelta << " microseconds\n";

    // Zero-out the cipher classes in GPU memory. The cipher classes maintain copies of the round
    // keys, so it's important for security that these keys don't get left around in memory.
    deverror = cudaMemset(aes128ctr_d, 0x00, sizeof(aes128ctr_h));
    if (deverror) {
        std::cerr << SRCLOC() << "[!] warning: Failed to zero-out GPU memory: "
            << cudaGetErrorString(deverror) << "\n";
    }
    deverror = cudaMemset(aes192ctr_d, 0x00, sizeof(aes192ctr_h));
    if (deverror) {
        std::cerr << SRCLOC() << "[!] warning: Failed to zero-out GPU memory: "
            << cudaGetErrorString(deverror) << "\n";
    }
    deverror = cudaMemset(aes256ctr_d, 0x00, sizeof(aes256ctr_h));
    if (deverror) {
        std::cerr << SRCLOC() << "[!] warning: Failed to zero-out GPU memory: "
            << cudaGetErrorString(deverror) << "\n";
    }

    cudaFree(aes128ctr_d);
    aes128ctr_d = nullptr;
    cudaFree(aes192ctr_d);
    aes192ctr_d = nullptr;
    cudaFree(aes256ctr_d);
    aes256ctr_d = nullptr;

    // Copy the encrypted file data back to the CPU.
    timedelta = timer.time();
    deverror = cudaMemcpy(data, data_d, size, cudaMemcpyDeviceToHost);
    if (deverror) {
        std::cerr << SRCLOC() << "[!] error: " << cudaGetErrorString(deverror) << "\n";
        goto _fail;
    }
    timedelta = timer.time();

    std::cout << "[*] memcpy() [device -> host] elapsed time: " << timedelta << " microseconds\n";

    cudaFree(data_d);

    return 0;
_fail:
    // These calls do nothing when passed `nullptr`.
    cudaFree(data_d);
    cudaFree(aes128ctr_d);
    cudaFree(aes192ctr_d);
    cudaFree(aes256ctr_d);

    return 1;
}

#else // RT_PARALLEL != 0

int aes_ctr_encrypt(
    Config const& config, unsigned char const nonce[blk_size], void* data, size_t size
    )
{
    Timer<std::chrono::microseconds> timer { };
    auto timedelta = timer.time();

    // Perform AES encryption using CTR mode for the proper key size.
    unsigned char* ptr = reinterpret_cast<unsigned char*>(data);
    switch (config.key_size) {
    case 128: CtrMode<Aes128>(&config.key[0], nonce).encrypt(ptr, size, 0); break;
    case 192: CtrMode<Aes192>(&config.key[0], nonce).encrypt(ptr, size, 0); break;
    case 256: CtrMode<Aes256>(&config.key[0], nonce).encrypt(ptr, size, 0); break;
    default:
        assert("Unsupported AES key size" && false);
        return 1;
    }
    timedelta = timer.time();

    std::cout << "[*] AES encrypt() [sequential] elapsed time: " << timedelta << " microseconds\n";

    return 0;
}

#endif // RT_PARALLEL == 0


int do_encrypt(Config const& config, std::string& data)
{
    // Append a random nonce to the file data.
    std::array<unsigned char, blk_size> nonce { };
    get_random_bytes(std::begin(nonce), std::end(nonce));
    data.resize(data.size() + blk_size);
    std::copy_n(std::begin(nonce), blk_size, std::end(data) - blk_size);

    // Perform the encryption.
    return aes_ctr_encrypt(config, nonce.data(), &data[0], data.size() - blk_size);
}

int do_decrypt(Config const& config, std::string& data)
{
    // Extract the nonce from the end of the file data.
    std::array<unsigned char, blk_size> nonce { };
    std::copy_n(std::end(data) - blk_size, blk_size, std::begin(nonce));
    data.resize(data.size() - blk_size);

    // Perform the decryption.
    return aes_ctr_encrypt(config, nonce.data(), &data[0], data.size());
}

} // anonymous namespace


int main(int argc, char* const argv[])
{
    int error = 0;
    Config config { };

    // Parse any options and/or required arguments, specified at the command-line.
    error = config.parse(argc, argv);
    if (error < 1) {
        return -error;
    }

    // Generate a random key if none was specified at the command-line.
    if (config.key.empty()) {
        config.key.resize(config.key_size / 8);
        get_random_bytes(std::begin(config.key), std::end(config.key));
        std::cout << "[*] Key: ";
        std::for_each(std::begin(config.key), std::end(config.key), [](int byte) {
            std::cout << std::setw(2) << std::setfill('0') << std::hex << std::right << byte;
        });
        std::cout.copyfmt(std::ios{ nullptr });
        std::cout << "\n";
    }

    std::string contents { };

    // Read the file plaintext/ciphertext data.
    try {
        get_file_contents(contents, config.filepath, blk_size /* = space for a potential nonce */);
    } catch (std::ifstream::failure&) {
        if (errno) {
            std::cerr << config.filepath << ": " << std::strerror(errno) << "\n";
        } else {
            std::cerr << config.filepath << ": Failed to read file\n";
        }
        return 1;
    }

    // Perform the specified encryption/decryption operation.
    switch (config.op) {
    case Config::Operation::kEncrypt: error = do_encrypt(config, contents); break;
    case Config::Operation::kDecrypt: error = do_decrypt(config, contents); break;
    default:
        assert("Unsupported AES operation" && false);
        return 1;
    }
    if (error) {
        return 1;
    }

    // Save the file plaintext/ciphertext data.
    try {
        set_file_contents(config.filepath, contents);
    } catch (std::ofstream::failure&) {
        if (errno) {
            std::cerr << config.filepath << ": " << std::strerror(errno) << "\n";
        } else {
            std::cerr << config.filepath << ": Failed to save file\n";
        }
        return 1;
    }

    return 0;
}
