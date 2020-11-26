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


#include "fsc.hh"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <type_traits>
#include <utility>

#include <cuda_runtime.h>
#include <device_launch_parameters.h>

#include <gtest/gtest.h>


using crypto::FixedSizeCounter;

template <size_t N>
using bytearr_t = std::array<unsigned char, N>;


namespace { // anonymous

constexpr bytearr_t<1> const arr_0 { 0x00 };
constexpr bytearr_t<1> const arr_1 { 0x7f };
constexpr bytearr_t<1> const arr_2 { 0x80 };
constexpr bytearr_t<1> const arr_3 { 0xff };
constexpr bytearr_t<2> const arr_4 { 0x4b, 0x1d };
constexpr bytearr_t<2> const arr_5 { 0xde, 0xad };
constexpr bytearr_t<2> const arr_6 { 0xc0, 0xde };
constexpr bytearr_t<3> const arr_7 { 0x0f, 0xf1, 0xce };
constexpr bytearr_t<3> const arr_8 { 0x0b, 0x00, 0xb5 };
constexpr bytearr_t<4> const arr_9 { 0x8b, 0xad, 0xf0, 0x0d };

FixedSizeCounter<1> const fsc_0 { arr_0.data(), 1 };
FixedSizeCounter<1> const fsc_1 { arr_1.data(), 1 };
FixedSizeCounter<1> const fsc_2 { arr_2.data(), 1 };
FixedSizeCounter<1> const fsc_3 { arr_3.data(), 1 };
FixedSizeCounter<2> const fsc_4 { arr_4.data(), 2 };
FixedSizeCounter<2> const fsc_5 { arr_5.data(), 2 };
FixedSizeCounter<2> const fsc_6 { arr_6.data(), 2 };
FixedSizeCounter<3> const fsc_7 { arr_7.data(), 3 };
FixedSizeCounter<3> const fsc_8 { arr_8.data(), 3 };
FixedSizeCounter<4> const fsc_9 { arr_9.data(), 4 };

template <size_t N, typename... T>
__global__ void exec_fsc_ctor(unsigned char* data, T... args)
{
    std::memcpy(data, FixedSizeCounter<N>(args...).data, N);
}

template <size_t N, typename... T>
void test_fsc_ctor(T&&... args, bytearr_t<N> const& expected)
{
    bytearr_t<N>* received = nullptr;
    cudaError_t error = cudaMallocManaged(&received, sizeof(*received));
    if (error) {
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }
    received = new(received) bytearr_t<N>();
    exec_fsc_ctor<N, std::remove_reference_t<T>...><<<1, 1>>>(received->data(), std::forward<T>(args)...);
    cudaDeviceSynchronize();
    EXPECT_EQ(*received, expected);
    cudaFree(received);
}


template <size_t N, typename T>
__global__ void exec_fsc_add(FixedSizeCounter<N>* fsc, T value)
{
    *fsc += value;
}

template <size_t N, typename T>
void test_fsc_add(FixedSizeCounter<N>* fsc, T value, bytearr_t<N> const& expected)
{
    bytearr_t<N> received { };
    exec_fsc_add<N, T><<<1, 1>>>(fsc, value);
    cudaDeviceSynchronize();
    std::copy_n(fsc->data, N, received.begin());
    EXPECT_EQ(received, expected);
}


template <size_t N, typename T>
__global__ void exec_fsc_increment(unsigned char* received, unsigned char* expected, T beg, T end)
{
    auto const set_expected_value_ = [&expected](auto value) {
        for (size_t i = 0; i < N; ++i) {
            expected[i] = (value >> (8 * (N - 1 - i))) & 0xff;
        }
    };

    FixedSizeCounter<N> ctr { beg };
    for ( ; beg != end; ++beg) {
        for (size_t i = 0; i < N; ++i) {
            if (ctr.data[i] != (beg >> (8 * (N - 1 - i))) & 0xff) {
                std::memcpy(received, ctr.data, N);
                set_expected_value_(beg);
                return;
            }
        }
        ++ctr;
    }
}

template <size_t N, typename T>
void test_fsc_increment(T beg, T end)
{
    cudaError_t error { };
    bytearr_t<N>* expected = nullptr;
    bytearr_t<N>* received = nullptr;
    error = cudaMallocManaged(&expected, sizeof(*expected));
    if (error) {
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }
    error = cudaMallocManaged(&received, sizeof(*received));
    if (error) {
        cudaFree(received);
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }
    expected = new(expected) bytearr_t<N>();
    received = new(received) bytearr_t<N>();
    exec_fsc_increment<N, T><<<1, 1>>>(received->data(), expected->data(), beg, end);
    cudaDeviceSynchronize();
    EXPECT_EQ(*received, *expected);
    cudaFree(received);
    cudaFree(expected);
}

} // anonymous namespace


TEST(FixedSizeCounterCudaTest, Constructor) {
    // Test default constructor.
    test_fsc_ctor<1>({ 0x00 });
    test_fsc_ctor<2>({ 0x00, 0x00 });
    test_fsc_ctor<3>({ 0x00, 0x00, 0x00 });
    test_fsc_ctor<4>({ 0x00, 0x00, 0x00, 0x00 });

    // Test constructor, taking signed/unsigned  8-bit integer.
    test_fsc_ctor<1,  uint8_t>(static_cast< uint8_t>(0x00000000U), { 0x00 });
    test_fsc_ctor<1,  uint8_t>(static_cast< uint8_t>(0x0000007fU), { 0x7f });
    test_fsc_ctor<1,  uint8_t>(static_cast< uint8_t>(0x00000080U), { 0x80 });
    test_fsc_ctor<1,  uint8_t>(static_cast< uint8_t>(0x000000ffU), { 0xff });
    test_fsc_ctor<1,   int8_t>(static_cast<  int8_t>(0x00000000U), { 0x00 });
    test_fsc_ctor<1,   int8_t>(static_cast<  int8_t>(0x0000007fU), { 0x7f });
    test_fsc_ctor<1,   int8_t>(static_cast<  int8_t>(0x00000080U), { 0x80 });
    test_fsc_ctor<1,   int8_t>(static_cast<  int8_t>(0x000000ffU), { 0xff });

    // Test constructor, taking signed/unsigned 16-bit integer.
    test_fsc_ctor<2, uint16_t>(static_cast<uint16_t>(0x00000000U), { 0x00, 0x00 });
    test_fsc_ctor<2, uint16_t>(static_cast<uint16_t>(0x00007fffU), { 0x7f, 0xff });
    test_fsc_ctor<2, uint16_t>(static_cast<uint16_t>(0x00008000U), { 0x80, 0x00 });
    test_fsc_ctor<2, uint16_t>(static_cast<uint16_t>(0x0000ffffU), { 0xff, 0xff });
    test_fsc_ctor<2,  int16_t>(static_cast< int16_t>(0x00000000U), { 0x00, 0x00 });
    test_fsc_ctor<2,  int16_t>(static_cast< int16_t>(0x00007fffU), { 0x7f, 0xff });
    test_fsc_ctor<2,  int16_t>(static_cast< int16_t>(0x00008000U), { 0x80, 0x00 });
    test_fsc_ctor<2,  int16_t>(static_cast< int16_t>(0x0000ffffU), { 0xff, 0xff });

    // Test constructor, taking signed/unsigned 32-bit integer.
    test_fsc_ctor<4, uint32_t>(static_cast<uint32_t>(0x00000000U), { 0x00, 0x00, 0x00, 0x00 });
    test_fsc_ctor<4, uint32_t>(static_cast<uint32_t>(0x7fffffffU), { 0x7f, 0xff, 0xff, 0xff });
    test_fsc_ctor<4, uint32_t>(static_cast<uint32_t>(0x80000000U), { 0x80, 0x00, 0x00, 0x00 });
    test_fsc_ctor<4, uint32_t>(static_cast<uint32_t>(0xffffffffU), { 0xff, 0xff, 0xff, 0xff });
    test_fsc_ctor<4,  int32_t>(static_cast< int32_t>(0x00000000U), { 0x00, 0x00, 0x00, 0x00 });
    test_fsc_ctor<4,  int32_t>(static_cast< int32_t>(0x7fffffffU), { 0x7f, 0xff, 0xff, 0xff });
    test_fsc_ctor<4,  int32_t>(static_cast< int32_t>(0x80000000U), { 0x80, 0x00, 0x00, 0x00 });
    test_fsc_ctor<4,  int32_t>(static_cast< int32_t>(0xffffffffU), { 0xff, 0xff, 0xff, 0xff });

    // Test constructor, taking array of bytes.
    cudaError_t error { };
    bytearr_t<1>* bytearr_size_1 = nullptr;
    bytearr_t<2>* bytearr_size_2 = nullptr;
    bytearr_t<3>* bytearr_size_3 = nullptr;
    bytearr_t<4>* bytearr_size_4 = nullptr;
    error = cudaMallocManaged(&bytearr_size_1, sizeof(*bytearr_size_1));
    if (error) {
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }
    error = cudaMallocManaged(&bytearr_size_2, sizeof(*bytearr_size_2));
    if (error) {
        cudaFree(bytearr_size_1);
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }
    error = cudaMallocManaged(&bytearr_size_3, sizeof(*bytearr_size_3));
    if (error) {
        cudaFree(bytearr_size_1);
        cudaFree(bytearr_size_2);
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }
    error = cudaMallocManaged(&bytearr_size_4, sizeof(*bytearr_size_4));
    if (error) {
        cudaFree(bytearr_size_1);
        cudaFree(bytearr_size_2);
        cudaFree(bytearr_size_3);
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }
    bytearr_size_1 = new(bytearr_size_1) bytearr_t<1>({ 0x11 });
    test_fsc_ctor<1, unsigned char*, size_t>(bytearr_size_1->data(), 1, { 0x11 });
    bytearr_size_1 = new(bytearr_size_1) bytearr_t<1>({ 0xca });
    test_fsc_ctor<1, unsigned char*, size_t>(bytearr_size_1->data(), 1, { 0xca });
    bytearr_size_1 = new(bytearr_size_1) bytearr_t<1>({ 0x22 });
    test_fsc_ctor<2, unsigned char*, size_t>(bytearr_size_1->data(), 1, { 0x00, 0x22 });
    bytearr_size_1 = new(bytearr_size_1) bytearr_t<1>({ 0xfe });
    test_fsc_ctor<2, unsigned char*, size_t>(bytearr_size_1->data(), 1, { 0xff, 0xfe });
    bytearr_size_2 = new(bytearr_size_2) bytearr_t<2>({ 0x11, 0x22 });
    test_fsc_ctor<2, unsigned char*, size_t>(bytearr_size_2->data(), 2, { 0x11, 0x22 });
    bytearr_size_2 = new(bytearr_size_2) bytearr_t<2>({ 0xca, 0xfe });
    test_fsc_ctor<2, unsigned char*, size_t>(bytearr_size_2->data(), 2, { 0xca, 0xfe });
    bytearr_size_1 = new(bytearr_size_1) bytearr_t<1>({ 0x44 });
    test_fsc_ctor<4, unsigned char*, size_t>(bytearr_size_1->data(), 1, { 0x00, 0x00, 0x00, 0x44 });
    bytearr_size_1 = new(bytearr_size_1) bytearr_t<1>({ 0xbe });
    test_fsc_ctor<4, unsigned char*, size_t>(bytearr_size_1->data(), 1, { 0xff, 0xff, 0xff, 0xbe });
    bytearr_size_2 = new(bytearr_size_2) bytearr_t<2>({ 0x33, 0x44 });
    test_fsc_ctor<4, unsigned char*, size_t>(bytearr_size_2->data(), 2, { 0x00, 0x00, 0x33, 0x44 });
    bytearr_size_2 = new(bytearr_size_2) bytearr_t<2>({ 0xba, 0xbe });
    test_fsc_ctor<4, unsigned char*, size_t>(bytearr_size_2->data(), 2, { 0xff, 0xff, 0xba, 0xbe });
    bytearr_size_3 = new(bytearr_size_3) bytearr_t<3>({ 0x22, 0x33, 0x44 });
    test_fsc_ctor<4, unsigned char*, size_t>(bytearr_size_3->data(), 3, { 0x00, 0x22, 0x33, 0x44 });
    bytearr_size_3 = new(bytearr_size_3) bytearr_t<3>({ 0xfe, 0xba, 0xbe });
    test_fsc_ctor<4, unsigned char*, size_t>(bytearr_size_3->data(), 3, { 0xff, 0xfe, 0xba, 0xbe });
    bytearr_size_4 = new(bytearr_size_4) bytearr_t<4>({ 0x11, 0x22, 0x33, 0x44 });
    test_fsc_ctor<4, unsigned char*, size_t>(bytearr_size_4->data(), 4, { 0x11, 0x22, 0x33, 0x44 });
    bytearr_size_4 = new(bytearr_size_4) bytearr_t<4>({ 0xca, 0xfe, 0xba, 0xbe });
    test_fsc_ctor<4, unsigned char*, size_t>(bytearr_size_4->data(), 4, { 0xca, 0xfe, 0xba, 0xbe });

    // Test constructor, taking object of type `FixedSizeCounter<size_t>`.
    test_fsc_ctor<fsc_0.size(), std::add_lvalue_reference_t<decltype(fsc_0)>>(fsc_0, arr_0);
    test_fsc_ctor<fsc_1.size(), std::add_lvalue_reference_t<decltype(fsc_1)>>(fsc_1, arr_1);
    test_fsc_ctor<fsc_2.size(), std::add_lvalue_reference_t<decltype(fsc_2)>>(fsc_2, arr_2);
    test_fsc_ctor<fsc_3.size(), std::add_lvalue_reference_t<decltype(fsc_3)>>(fsc_3, arr_3);
    test_fsc_ctor<fsc_4.size(), std::add_lvalue_reference_t<decltype(fsc_4)>>(fsc_4, arr_4);
    test_fsc_ctor<fsc_5.size(), std::add_lvalue_reference_t<decltype(fsc_5)>>(fsc_5, arr_5);
    test_fsc_ctor<fsc_6.size(), std::add_lvalue_reference_t<decltype(fsc_6)>>(fsc_6, arr_6);
    test_fsc_ctor<fsc_7.size(), std::add_lvalue_reference_t<decltype(fsc_7)>>(fsc_7, arr_7);
    test_fsc_ctor<fsc_8.size(), std::add_lvalue_reference_t<decltype(fsc_8)>>(fsc_8, arr_8);
    test_fsc_ctor<fsc_9.size(), std::add_lvalue_reference_t<decltype(fsc_9)>>(fsc_9, arr_9);

    cudaFree(bytearr_size_1);
    cudaFree(bytearr_size_2);
    cudaFree(bytearr_size_3);
    cudaFree(bytearr_size_4);
}

TEST(FixedSizeCounterCudaTest, Add) {
    cudaError_t error { };
    FixedSizeCounter<4>* x = nullptr;
    FixedSizeCounter<4>* y = nullptr;
    error = cudaMallocManaged(&x, sizeof(*x));
    if (error) {
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }
    error = cudaMallocManaged(&y, sizeof(*y));
    if (error) {
        cudaFree(x);
        FAIL() << "[error]: " << cudaGetErrorString(error) << "\n";
    }
    x = new(x) FixedSizeCounter<4>();
    y = new(y) FixedSizeCounter<4>();

    test_fsc_add(x, static_cast<uint32_t>(0x00000000U), { 0x00, 0x00, 0x00, 0x00 });
    test_fsc_add(x, static_cast<uint32_t>(0x00000001U), { 0x00, 0x00, 0x00, 0x01 });
    test_fsc_add(x, static_cast<uint32_t>(0x00000002U), { 0x00, 0x00, 0x00, 0x03 });
    test_fsc_add(x, static_cast<uint32_t>(0x00112233U), { 0x00, 0x11, 0x22, 0x36 });
    test_fsc_add(x, static_cast<uint32_t>(0x00ffff00U), { 0x01, 0x11, 0x21, 0x36 });
    test_fsc_add(x, *y, { 0x01, 0x11, 0x21, 0x36 });
    test_fsc_add(y, *x, { 0x01, 0x11, 0x21, 0x36 });
    test_fsc_add(x, *y, { 0x02, 0x22, 0x42, 0x6c });
    test_fsc_add(x, static_cast<uint32_t>(0xffffffffU), { 0x02, 0x22, 0x42, 0x6b });
    test_fsc_add(x, static_cast<uint32_t>(0xfdddbd95U), { 0x00, 0x00, 0x00, 0x00 });

    cudaFree(x);
    cudaFree(y);
}

TEST(FixedSizeCounterCudaTest, Inc) {
    {
        int8_t beg = INT8_MIN;
        int8_t end = INT8_MAX;
        test_fsc_increment<1>(beg, end);
    }

    {
        int16_t beg = INT16_MIN;
        int16_t end = INT16_MAX;
        test_fsc_increment<2>(beg, end);
    }

    {
        int32_t beg = 0xff000000;
        int32_t end = 0x00ffffff;
        test_fsc_increment<4>(beg, end);
    }
}
