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

#include <algorithm>
#include <cstdint>

#include <gtest/gtest.h>


using namespace aes;


TEST(AesExpandKeyTest, Aes128) {
    // Example 128-bit cipher key taken from NIST FIPS-197 Appendix A.1.
    constexpr unsigned char const key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    uint32_t rks[44];

    std::fill_n(rks, 44, 0U);
    Aes128(key).getkeys(rks);

    EXPECT_EQ(rks[ 0], 0x2b7e1516U);
    EXPECT_EQ(rks[ 1], 0x28aed2a6U);
    EXPECT_EQ(rks[ 2], 0xabf71588U);
    EXPECT_EQ(rks[ 3], 0x09cf4f3cU);
    EXPECT_EQ(rks[ 4], 0xa0fafe17U);
    EXPECT_EQ(rks[ 5], 0x88542cb1U);
    EXPECT_EQ(rks[ 6], 0x23a33939U);
    EXPECT_EQ(rks[ 7], 0x2a6c7605U);
    EXPECT_EQ(rks[ 8], 0xf2c295f2U);
    EXPECT_EQ(rks[ 9], 0x7a96b943U);
    EXPECT_EQ(rks[10], 0x5935807aU);
    EXPECT_EQ(rks[11], 0x7359f67fU);
    EXPECT_EQ(rks[12], 0x3d80477dU);
    EXPECT_EQ(rks[13], 0x4716fe3eU);
    EXPECT_EQ(rks[14], 0x1e237e44U);
    EXPECT_EQ(rks[15], 0x6d7a883bU);
    EXPECT_EQ(rks[16], 0xef44a541U);
    EXPECT_EQ(rks[17], 0xa8525b7fU);
    EXPECT_EQ(rks[18], 0xb671253bU);
    EXPECT_EQ(rks[19], 0xdb0bad00U);
    EXPECT_EQ(rks[20], 0xd4d1c6f8U);
    EXPECT_EQ(rks[21], 0x7c839d87U);
    EXPECT_EQ(rks[22], 0xcaf2b8bcU);
    EXPECT_EQ(rks[23], 0x11f915bcU);
    EXPECT_EQ(rks[24], 0x6d88a37aU);
    EXPECT_EQ(rks[25], 0x110b3efdU);
    EXPECT_EQ(rks[26], 0xdbf98641U);
    EXPECT_EQ(rks[27], 0xca0093fdU);
    EXPECT_EQ(rks[28], 0x4e54f70eU);
    EXPECT_EQ(rks[29], 0x5f5fc9f3U);
    EXPECT_EQ(rks[30], 0x84a64fb2U);
    EXPECT_EQ(rks[31], 0x4ea6dc4fU);
    EXPECT_EQ(rks[32], 0xead27321U);
    EXPECT_EQ(rks[33], 0xb58dbad2U);
    EXPECT_EQ(rks[34], 0x312bf560U);
    EXPECT_EQ(rks[35], 0x7f8d292fU);
    EXPECT_EQ(rks[36], 0xac7766f3U);
    EXPECT_EQ(rks[37], 0x19fadc21U);
    EXPECT_EQ(rks[38], 0x28d12941U);
    EXPECT_EQ(rks[39], 0x575c006eU);
    EXPECT_EQ(rks[40], 0xd014f9a8U);
    EXPECT_EQ(rks[41], 0xc9ee2589U);
    EXPECT_EQ(rks[42], 0xe13f0cc8U);
    EXPECT_EQ(rks[43], 0xb6630ca6U);
}

TEST(AesExpandKeyTest, Aes192) {
    // Example 192-bit cipher key taken from NIST FIPS-197 Appendix A.2.
    constexpr unsigned char const key[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    uint32_t rks[52];

    std::fill_n(rks, 52, 0U);
    Aes192(key).getkeys(rks);

    EXPECT_EQ(rks[ 0], 0x8e73b0f7U);
    EXPECT_EQ(rks[ 1], 0xda0e6452U);
    EXPECT_EQ(rks[ 2], 0xc810f32bU);
    EXPECT_EQ(rks[ 3], 0x809079e5U);
    EXPECT_EQ(rks[ 4], 0x62f8ead2U);
    EXPECT_EQ(rks[ 5], 0x522c6b7bU);
    EXPECT_EQ(rks[ 6], 0xfe0c91f7U);
    EXPECT_EQ(rks[ 7], 0x2402f5a5U);
    EXPECT_EQ(rks[ 8], 0xec12068eU);
    EXPECT_EQ(rks[ 9], 0x6c827f6bU);
    EXPECT_EQ(rks[10], 0x0e7a95b9U);
    EXPECT_EQ(rks[11], 0x5c56fec2U);
    EXPECT_EQ(rks[12], 0x4db7b4bdU);
    EXPECT_EQ(rks[13], 0x69b54118U);
    EXPECT_EQ(rks[14], 0x85a74796U);
    EXPECT_EQ(rks[15], 0xe92538fdU);
    EXPECT_EQ(rks[16], 0xe75fad44U);
    EXPECT_EQ(rks[17], 0xbb095386U);
    EXPECT_EQ(rks[18], 0x485af057U);
    EXPECT_EQ(rks[19], 0x21efb14fU);
    EXPECT_EQ(rks[20], 0xa448f6d9U);
    EXPECT_EQ(rks[21], 0x4d6dce24U);
    EXPECT_EQ(rks[22], 0xaa326360U);
    EXPECT_EQ(rks[23], 0x113b30e6U);
    EXPECT_EQ(rks[24], 0xa25e7ed5U);
    EXPECT_EQ(rks[25], 0x83b1cf9aU);
    EXPECT_EQ(rks[26], 0x27f93943U);
    EXPECT_EQ(rks[27], 0x6a94f767U);
    EXPECT_EQ(rks[28], 0xc0a69407U);
    EXPECT_EQ(rks[29], 0xd19da4e1U);
    EXPECT_EQ(rks[30], 0xec1786ebU);
    EXPECT_EQ(rks[31], 0x6fa64971U);
    EXPECT_EQ(rks[32], 0x485f7032U);
    EXPECT_EQ(rks[33], 0x22cb8755U);
    EXPECT_EQ(rks[34], 0xe26d1352U);
    EXPECT_EQ(rks[35], 0x33f0b7b3U);
    EXPECT_EQ(rks[36], 0x40beeb28U);
    EXPECT_EQ(rks[37], 0x2f18a259U);
    EXPECT_EQ(rks[38], 0x6747d26bU);
    EXPECT_EQ(rks[39], 0x458c553eU);
    EXPECT_EQ(rks[40], 0xa7e1466cU);
    EXPECT_EQ(rks[41], 0x9411f1dfU);
    EXPECT_EQ(rks[42], 0x821f750aU);
    EXPECT_EQ(rks[43], 0xad07d753U);
    EXPECT_EQ(rks[44], 0xca400538U);
    EXPECT_EQ(rks[45], 0x8fcc5006U);
    EXPECT_EQ(rks[46], 0x282d166aU);
    EXPECT_EQ(rks[47], 0xbc3ce7b5U);
    EXPECT_EQ(rks[48], 0xe98ba06fU);
    EXPECT_EQ(rks[49], 0x448c773cU);
    EXPECT_EQ(rks[50], 0x8ecc7204U);
    EXPECT_EQ(rks[51], 0x01002202U);
}

TEST(AesExpandKeyTest, Aes256) {
    // Example 256-bit cipher key taken from NIST FIPS-197 Appendix A.3.
    constexpr unsigned char const key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    uint32_t rks[60];

    std::fill_n(rks, 60, 0U);
    Aes256(key).getkeys(rks);

    EXPECT_EQ(rks[ 0], 0x603deb10U);
    EXPECT_EQ(rks[ 1], 0x15ca71beU);
    EXPECT_EQ(rks[ 2], 0x2b73aef0U);
    EXPECT_EQ(rks[ 3], 0x857d7781U);
    EXPECT_EQ(rks[ 4], 0x1f352c07U);
    EXPECT_EQ(rks[ 5], 0x3b6108d7U);
    EXPECT_EQ(rks[ 6], 0x2d9810a3U);
    EXPECT_EQ(rks[ 7], 0x0914dff4U);
    EXPECT_EQ(rks[ 8], 0x9ba35411U);
    EXPECT_EQ(rks[ 9], 0x8e6925afU);
    EXPECT_EQ(rks[10], 0xa51a8b5fU);
    EXPECT_EQ(rks[11], 0x2067fcdeU);
    EXPECT_EQ(rks[12], 0xa8b09c1aU);
    EXPECT_EQ(rks[13], 0x93d194cdU);
    EXPECT_EQ(rks[14], 0xbe49846eU);
    EXPECT_EQ(rks[15], 0xb75d5b9aU);
    EXPECT_EQ(rks[16], 0xd59aecb8U);
    EXPECT_EQ(rks[17], 0x5bf3c917U);
    EXPECT_EQ(rks[18], 0xfee94248U);
    EXPECT_EQ(rks[19], 0xde8ebe96U);
    EXPECT_EQ(rks[20], 0xb5a9328aU);
    EXPECT_EQ(rks[21], 0x2678a647U);
    EXPECT_EQ(rks[22], 0x98312229U);
    EXPECT_EQ(rks[23], 0x2f6c79b3U);
    EXPECT_EQ(rks[24], 0x812c81adU);
    EXPECT_EQ(rks[25], 0xdadf48baU);
    EXPECT_EQ(rks[26], 0x24360af2U);
    EXPECT_EQ(rks[27], 0xfab8b464U);
    EXPECT_EQ(rks[28], 0x98c5bfc9U);
    EXPECT_EQ(rks[29], 0xbebd198eU);
    EXPECT_EQ(rks[30], 0x268c3ba7U);
    EXPECT_EQ(rks[31], 0x09e04214U);
    EXPECT_EQ(rks[32], 0x68007bacU);
    EXPECT_EQ(rks[33], 0xb2df3316U);
    EXPECT_EQ(rks[34], 0x96e939e4U);
    EXPECT_EQ(rks[35], 0x6c518d80U);
    EXPECT_EQ(rks[36], 0xc814e204U);
    EXPECT_EQ(rks[37], 0x76a9fb8aU);
    EXPECT_EQ(rks[38], 0x5025c02dU);
    EXPECT_EQ(rks[39], 0x59c58239U);
    EXPECT_EQ(rks[40], 0xde136967U);
    EXPECT_EQ(rks[41], 0x6ccc5a71U);
    EXPECT_EQ(rks[42], 0xfa256395U);
    EXPECT_EQ(rks[43], 0x9674ee15U);
    EXPECT_EQ(rks[44], 0x5886ca5dU);
    EXPECT_EQ(rks[45], 0x2e2f31d7U);
    EXPECT_EQ(rks[46], 0x7e0af1faU);
    EXPECT_EQ(rks[47], 0x27cf73c3U);
    EXPECT_EQ(rks[48], 0x749c47abU);
    EXPECT_EQ(rks[49], 0x18501ddaU);
    EXPECT_EQ(rks[50], 0xe2757e4fU);
    EXPECT_EQ(rks[51], 0x7401905aU);
    EXPECT_EQ(rks[52], 0xcafaaae3U);
    EXPECT_EQ(rks[53], 0xe4d59b34U);
    EXPECT_EQ(rks[54], 0x9adf6aceU);
    EXPECT_EQ(rks[55], 0xbd10190dU);
    EXPECT_EQ(rks[56], 0xfe4890d1U);
    EXPECT_EQ(rks[57], 0xe6188d0bU);
    EXPECT_EQ(rks[58], 0x046df344U);
    EXPECT_EQ(rks[59], 0x706c631eU);
}


TEST(AesEncryptTest, Aes128) {
    // Example 128-bit cipher key taken from NIST FIPS-197 Appendix C.1.
    constexpr unsigned char const key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    // Example plaintext taken from NIST FIPS-197 Appendix C.1.
    unsigned char blk[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    Aes128(key).encrypt(blk);

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
}

TEST(AesEncryptTest, Aes192) {
    // Example 192-bit cipher key taken from NIST FIPS-197 Appendix C.2.
    constexpr unsigned char const key[24] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };

    // Example plaintext taken from NIST FIPS-197 Appendix C.2.
    unsigned char blk[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    Aes192(key).encrypt(blk);

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
}

TEST(AesEncryptTest, Aes256) {
    // Example 256-bit cipher key taken from NIST FIPS-197 Appendix C.3.
    constexpr unsigned char const key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    // Example plaintext taken from NIST FIPS-197 Appendix C.3.
    unsigned char blk[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    Aes256(key).encrypt(blk);

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
}
