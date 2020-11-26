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
#include <initializer_list>
#include <type_traits>

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
void test_fsc_ctor(T... args, bytearr_t<N> const& expected)
{
    bytearr_t<N> received { };
    FixedSizeCounter<N> counter { args... };
    std::copy_n(counter.data, N, received.begin());
    EXPECT_EQ(received, expected);
}

} // anonymous namespace


TEST(FixedSizeCounterTest, Constructor) {
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
    test_fsc_ctor<1, unsigned char*, size_t>(bytearr_t<1>({ 0x11 }).data(), 1, { 0x11 });
    test_fsc_ctor<1, unsigned char*, size_t>(bytearr_t<1>({ 0xca }).data(), 1, { 0xca });
    test_fsc_ctor<2, unsigned char*, size_t>(bytearr_t<1>({ 0x22 }).data(), 1, { 0x00, 0x22 });
    test_fsc_ctor<2, unsigned char*, size_t>(bytearr_t<1>({ 0xfe }).data(), 1, { 0xff, 0xfe });
    test_fsc_ctor<2, unsigned char*, size_t>(bytearr_t<2>({ 0x11, 0x22 }).data(), 2, { 0x11, 0x22 });
    test_fsc_ctor<2, unsigned char*, size_t>(bytearr_t<2>({ 0xca, 0xfe }).data(), 2, { 0xca, 0xfe });
    test_fsc_ctor<4, unsigned char*, size_t>(bytearr_t<1>({ 0x44 }).data(), 1, { 0x00, 0x00, 0x00, 0x44 });
    test_fsc_ctor<4, unsigned char*, size_t>(bytearr_t<1>({ 0xbe }).data(), 1, { 0xff, 0xff, 0xff, 0xbe });
    test_fsc_ctor<4, unsigned char*, size_t>(bytearr_t<2>({ 0x33, 0x44 }).data(), 2, { 0x00, 0x00, 0x33, 0x44 });
    test_fsc_ctor<4, unsigned char*, size_t>(bytearr_t<2>({ 0xba, 0xbe }).data(), 2, { 0xff, 0xff, 0xba, 0xbe });
    test_fsc_ctor<4, unsigned char*, size_t>(bytearr_t<3>({ 0x22, 0x33, 0x44 }).data(), 3, { 0x00, 0x22, 0x33, 0x44 });
    test_fsc_ctor<4, unsigned char*, size_t>(bytearr_t<3>({ 0xfe, 0xba, 0xbe }).data(), 3, { 0xff, 0xfe, 0xba, 0xbe });
    test_fsc_ctor<4, unsigned char*, size_t>(bytearr_t<4>({ 0x11, 0x22, 0x33, 0x44 }).data(), 4, { 0x11, 0x22, 0x33, 0x44 });
    test_fsc_ctor<4, unsigned char*, size_t>(bytearr_t<4>({ 0xca, 0xfe, 0xba, 0xbe }).data(), 4, { 0xca, 0xfe, 0xba, 0xbe });

    // Test constructor, taking object of type `FixedSizeCounter<size_t>`.
    test_fsc_ctor<fsc_0.size(), decltype(fsc_0)>(fsc_0, arr_0);
    test_fsc_ctor<fsc_1.size(), decltype(fsc_1)>(fsc_1, arr_1);
    test_fsc_ctor<fsc_2.size(), decltype(fsc_2)>(fsc_2, arr_2);
    test_fsc_ctor<fsc_3.size(), decltype(fsc_3)>(fsc_3, arr_3);
    test_fsc_ctor<fsc_4.size(), decltype(fsc_4)>(fsc_4, arr_4);
    test_fsc_ctor<fsc_5.size(), decltype(fsc_5)>(fsc_5, arr_5);
    test_fsc_ctor<fsc_6.size(), decltype(fsc_6)>(fsc_6, arr_6);
    test_fsc_ctor<fsc_7.size(), decltype(fsc_7)>(fsc_7, arr_7);
    test_fsc_ctor<fsc_8.size(), decltype(fsc_8)>(fsc_8, arr_8);
    test_fsc_ctor<fsc_9.size(), decltype(fsc_9)>(fsc_9, arr_9);
}

TEST(FixedSizeCounterTest, Add) {
    FixedSizeCounter<4> x;
    FixedSizeCounter<4> y;

    uint32_t v = 0;

    x += v;
    EXPECT_EQ(x.data[0], 0x00);
    EXPECT_EQ(x.data[1], 0x00);
    EXPECT_EQ(x.data[2], 0x00);
    EXPECT_EQ(x.data[3], 0x00);
    v  = 1;
    x += v;
    EXPECT_EQ(x.data[0], 0x00);
    EXPECT_EQ(x.data[1], 0x00);
    EXPECT_EQ(x.data[2], 0x00);
    EXPECT_EQ(x.data[3], 0x01);
    v  = 2;
    x += v;
    EXPECT_EQ(x.data[0], 0x00);
    EXPECT_EQ(x.data[1], 0x00);
    EXPECT_EQ(x.data[2], 0x00);
    EXPECT_EQ(x.data[3], 0x03);
    v  = 0x00112233;
    x += v;
    EXPECT_EQ(x.data[0], 0x00);
    EXPECT_EQ(x.data[1], 0x11);
    EXPECT_EQ(x.data[2], 0x22);
    EXPECT_EQ(x.data[3], 0x36);
    v  = 0x00ffff00;
    x += v;
    EXPECT_EQ(x.data[0], 0x01);
    EXPECT_EQ(x.data[1], 0x11);
    EXPECT_EQ(x.data[2], 0x21);
    EXPECT_EQ(x.data[3], 0x36);
    x += y;
    EXPECT_EQ(x.data[0], 0x01);
    EXPECT_EQ(x.data[1], 0x11);
    EXPECT_EQ(x.data[2], 0x21);
    EXPECT_EQ(x.data[3], 0x36);
    EXPECT_EQ(y.data[0], 0x00);
    EXPECT_EQ(y.data[1], 0x00);
    EXPECT_EQ(y.data[2], 0x00);
    EXPECT_EQ(y.data[3], 0x00);
    y += x;
    EXPECT_EQ(y.data[0], 0x01);
    EXPECT_EQ(y.data[1], 0x11);
    EXPECT_EQ(y.data[2], 0x21);
    EXPECT_EQ(y.data[3], 0x36);
    x += y;
    EXPECT_EQ(x.data[0], 0x02);
    EXPECT_EQ(x.data[1], 0x22);
    EXPECT_EQ(x.data[2], 0x42);
    EXPECT_EQ(x.data[3], 0x6c);
    v  = 0xffffffff;
    x += v;
    EXPECT_EQ(x.data[0], 0x02);
    EXPECT_EQ(x.data[1], 0x22);
    EXPECT_EQ(x.data[2], 0x42);
    EXPECT_EQ(x.data[3], 0x6b);
    v  = 0xfdddbd95;
    x += v;
    EXPECT_EQ(x.data[0], 0x00);
    EXPECT_EQ(x.data[1], 0x00);
    EXPECT_EQ(x.data[2], 0x00);
    EXPECT_EQ(x.data[3], 0x00);
}

TEST(FixedSizeCounterTest, Inc) {
    {
        int8_t beg = INT8_MIN;
        int8_t end = INT8_MAX;
        FixedSizeCounter<1> ctr { beg };
        for ( int8_t i = beg; i < end; ++i) {
            EXPECT_EQ(ctr.data[0], (i >>  0) & 0xff);
            ++ctr;
        }
    }

    {
        int16_t beg = INT16_MIN;
        int16_t end = INT16_MAX;
        FixedSizeCounter<2> ctr { beg };
        for (int16_t i = beg; i < end; ++i) {
            EXPECT_EQ(ctr.data[0], (i >>  8) & 0xff);
            EXPECT_EQ(ctr.data[1], (i >>  0) & 0xff);
            ++ctr;
        }
    }

    {
        int32_t beg = 0xff000000;
        int32_t end = 0x00ffffff;
        FixedSizeCounter<4> ctr { beg };
        for (int32_t i = beg; i < end; ++i) {
            EXPECT_EQ(ctr.data[0], (i >> 24) & 0xff);
            EXPECT_EQ(ctr.data[1], (i >> 16) & 0xff);
            EXPECT_EQ(ctr.data[2], (i >>  8) & 0xff);
            EXPECT_EQ(ctr.data[3], (i >>  0) & 0xff);
            ++ctr;
        }
    }
}
