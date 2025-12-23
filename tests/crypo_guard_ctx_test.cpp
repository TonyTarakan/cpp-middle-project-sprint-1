#include "crypto_guard_ctx.h"
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>

TEST(CryptoGuardCtx, EncryptFileGood) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream in{"01234567890123456789"};
    std::stringstream out;
    std::stringstream expected{"\xd8\x86\x7f\x57\xc5\x49\x36\x2f\x4d\xab\xf2\xea\xe1\xaa\x88\x0e\xcd\x50\x4d\x27\x74"
                               "\x56\xcc\xbd\x94\xa8\xa7\x3f\x7e\xb7\x1b\x30"};

    ctx.EncryptFile(in, out, "12341234");
    EXPECT_EQ(expected.str(), out.str());
}

TEST(CryptoGuardCtx, DecryptFileGood) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream in{"\xd8\x86\x7f\x57\xc5\x49\x36\x2f\x4d\xab\xf2\xea\xe1\xaa\x88\x0e\xcd\x50\x4d\x27\x74"
                         "\x56\xcc\xbd\x94\xa8\xa7\x3f\x7e\xb7\x1b\x30"};
    std::stringstream out;
    std::stringstream expected{"01234567890123456789"};

    ctx.DecryptFile(in, out, "12341234");
    EXPECT_EQ(expected.str(), out.str());
}

TEST(CryptoGuardCtx, EncryptNoFile) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::fstream in{"WrongFilePath", std::ios::in};
    std::stringstream out;

    ASSERT_THROW(ctx.EncryptFile(in, out, "12341234"), std::exception);
}

TEST(CryptoGuardCtx, DecryptNoFile) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream in{"MySampleString"};
    std::stringstream outEmptyStream;

    ASSERT_THROW(ctx.DecryptFile(in, outEmptyStream, "123"), std::runtime_error);
}

TEST(CryptoGuardCtx, ChecksumGood) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream in("MySampleString");

    EXPECT_EQ(ctx.CalculateChecksum(in), "3b968d1e0f12a2e826459899ed65c0ab6de685daa1a7ac45820b2e4783d6280c");
}

TEST(CryptoGuardCtx, ChecksumBad) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream in("MyAnotherString");

    EXPECT_NE(ctx.CalculateChecksum(in), "3b968d1e0f12a2e826459899ed65c0ab6de685daa1a7ac45820b2e4783d6280c");
}

TEST(CryptoGuardCtx, EncryptAndDecrypt) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::string str{"testTestTest"};
    std::string pass{"passsssss"};
    std::stringstream in{str};
    std::stringstream out;
    std::stringstream reverse;

    ctx.EncryptFile(in, out, pass);
    ctx.DecryptFile(out, reverse, pass);
    EXPECT_TRUE(str == reverse.str());
}