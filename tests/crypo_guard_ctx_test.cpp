#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>

constexpr std::string_view kPassword = "12341234";

// encrypted plaintext (not using our encrypt func)
const std::string kCiphertextPlaintext{"\xD8\x86\x7F\x57\xC5\x49\x36\x2F"
                                       "\x4D\xAB\xF2\xEA\xE1\xAA\x88\x0E"
                                       "\xCD\x50\x4D\x27\x74\x56\xCC\xBD"
                                       "\x94\xA8\xA7\x3F\x7E\xB7\x1B\x30",
                                       32};

const std::string kPlaintext = "01234567890123456789";

std::string MakeBinaryData(std::size_t size) {
    std::string data(size, '\0');
    for (std::size_t i = 0; i < size; ++i)
        data[i] = static_cast<char>(i % 256);
    return data;
}

// check input vars

TEST(CryptoGuardCtxTest, ThrowsEmptyPassword) {
    std::stringstream input("data");
    std::stringstream output;

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    ASSERT_THROW(cryptoCtx.EncryptFile(input, output, std::string_view{}), std::invalid_argument);
    EXPECT_TRUE(output.str().empty());
}

TEST(CryptoGuardCtxTest, ThrowsInvalidInStream) {
    std::stringstream input("data");
    std::stringstream output;
    input.setstate(std::ios::badbit);

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    ASSERT_THROW(cryptoCtx.EncryptFile(input, output, kPassword), std::runtime_error);
    EXPECT_TRUE(output.str().empty());
}

TEST(CryptoGuardCtxTest, ThrowsInvalidOutputStream) {
    std::stringstream input("data");
    std::stringstream output;
    output.setstate(std::ios::failbit);

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    ASSERT_THROW(cryptoCtx.EncryptFile(input, output, kPassword), std::runtime_error);
    EXPECT_TRUE(output.str().empty());
}

TEST(CryptoGuardCtxTest, ThrowsSameStream) {
    std::stringstream stream("data");

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    ASSERT_THROW(cryptoCtx.EncryptFile(stream, stream, kPassword), std::invalid_argument);
    EXPECT_EQ(stream.str(), "data");
}

// encrypt + decrypt

TEST(CryptoGuardCtxTest, EncryptsTwentyBytes) {
    std::stringstream input(kPlaintext);
    std::stringstream output;

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    ASSERT_NO_THROW(cryptoCtx.EncryptFile(input, output, kPassword));

    const auto ciphertext = output.str();
    ASSERT_EQ(ciphertext.size(), 32u);
    EXPECT_EQ(ciphertext, kCiphertextPlaintext);

    std::stringstream restored;
    ASSERT_NO_THROW(cryptoCtx.DecryptFile(output, restored, kPassword));
    EXPECT_EQ(restored.str(), kPlaintext);
}

TEST(CryptoGuardCtxTest, EncryptsEmptyInput) {
    std::stringstream input;
    std::stringstream output;

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    ASSERT_NO_THROW(cryptoCtx.EncryptFile(input, output, kPassword));

    // 1 block cos PKCS
    const auto ciphertext = output.str();
    ASSERT_EQ(ciphertext.size(), 16u);

    std::stringstream restored;
    ASSERT_NO_THROW(cryptoCtx.DecryptFile(output, restored, kPassword));
    EXPECT_TRUE(restored.str().empty());
}

TEST(CryptoGuardCtxTest, PreservesBinaryData) {
    // 1024 bin '\0'
    const auto plaintext = MakeBinaryData(1024);
    std::stringstream input(plaintext);
    std::stringstream output;

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    ASSERT_NO_THROW(cryptoCtx.EncryptFile(input, output, kPassword));

    std::stringstream restored;
    ASSERT_NO_THROW(cryptoCtx.DecryptFile(output, restored, kPassword));
    EXPECT_EQ(restored.str(), plaintext);
}

// decrypt

TEST(CryptoGuardCtxTest, DecryptsKnownCiphertext) {
    std::stringstream input(kCiphertextPlaintext);
    std::stringstream output;

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    ASSERT_NO_THROW(cryptoCtx.DecryptFile(input, output, kPassword));
    EXPECT_EQ(output.str(), kPlaintext);
}

TEST(CryptoGuardCtxTest, ThrowsOnTruncatedCiphertext) {
    auto truncated = kCiphertextPlaintext;
    truncated.pop_back();
    std::stringstream input(truncated);
    std::stringstream output;

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    ASSERT_THROW(cryptoCtx.DecryptFile(input, output, kPassword), std::runtime_error);
}

// checksum

TEST(CryptoGuardCtxTest, HashesAbc) {
    std::stringstream input("abc");

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    EXPECT_EQ(cryptoCtx.CalculateChecksum(input), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(CryptoGuardCtxTest, HashesEmptyInput) {
    std::stringstream input;

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    EXPECT_EQ(cryptoCtx.CalculateChecksum(input), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(CryptoGuardCtxTest, HandlesBinaryDataAcrossChunkBoundary) {
    // zeros data
    std::string data(64 * 1024 + 1, '\0');
    data.back() = static_cast<char>(0xff);

    std::stringstream input(data);

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    EXPECT_EQ(cryptoCtx.CalculateChecksum(input), "230afa6e5ff3a73189b22de6afcfc635222fa35e317713c7ae35e8447e7a2081");
}

TEST(CryptoGuardCtxTest, ThrowsOnInvalidStream) {
    std::stringstream input("abc");
    input.setstate(std::ios::badbit);

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    ASSERT_THROW(cryptoCtx.CalculateChecksum(input), std::runtime_error);
}