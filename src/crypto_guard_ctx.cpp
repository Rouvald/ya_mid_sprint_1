#include "crypto_guard_ctx.h"
#include <array>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <print>
#include <sstream>
#include <stdexcept>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl {

public:
    Impl() = default;
    ~Impl() = default;

    Impl(const Impl &) = delete;
    Impl &operator=(const Impl &) = delete;

    Impl(Impl &&) noexcept = delete;
    Impl &operator=(Impl &&) noexcept = delete;

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        doCrypt(inStream, outStream, password);
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        doCrypt(inStream, outStream, password, 0);
    }

    std::string CalculateChecksum(std::iostream &inStream) {
        if (!inStream.good()) {
            throw std::runtime_error("Invalid stream");
        }
        using CtxUniquePtr = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })>;

        CtxUniquePtr ctx(EVP_MD_CTX_new());
        if (!ctx) {
            ThrowOpenSSLError("CalculateChecksum: EVP_MD_CTX_new");
        }
        if (EVP_DigestInit_ex2(ctx.get(), EVP_sha256(), nullptr) != 1) {
            ThrowOpenSSLError("CalculateChecksum: EVP_DigestInit_ex2");
        }
        constexpr std::size_t chunkSize = 1024;
        std::array<char, chunkSize> buffer{};

        for (;;) {
            inStream.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));

            if (inStream.bad() || (inStream.fail() && !inStream.eof())) {
                throw std::runtime_error("Input read failed");
            }

            const auto bytesRead = inStream.gcount();

            if (bytesRead > 0) {
                if (EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<std::size_t>(bytesRead)) != 1) {
                    ThrowOpenSSLError("CalculateChecksum: EVP_DigestUpdate");
                }
            }
            if (inStream.eof())
                break;
        }
        std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
        unsigned int digestSize = 0;

        if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &digestSize) != 1) {
            ThrowOpenSSLError("CalculateChecksum: EVP_DigestFinal_ex");
        }

        std::stringstream checksum;
        checksum << std::hex << std::setfill('0');

        for (unsigned int i = 0; i < digestSize; ++i) {
            checksum << std::setw(2) << static_cast<unsigned int>(digest[i]);
        }
        return checksum.str();
    }

private:
    AesCipherParams CreateChipherParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        if (EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                           reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                           params.key.data(), params.iv.data()) == 0) {
            ThrowOpenSSLError("CreateChipherParamsFromPassword: EVP_BytesToKey");
        }
        return params;
    }
    void doCrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password, int encrypt = 1) {
        if (password.empty()) {
            throw std::invalid_argument("password empty");
        }
        if (!inStream.good() || !outStream.good()) {
            throw std::runtime_error("Invalid stream");
        }
        if (inStream.rdbuf() == outStream.rdbuf()) {
            throw std::invalid_argument("Streams must be separate");
        }

        auto params = CreateChipherParamsFromPassword(password);
        params.encrypt = encrypt;

        using CtxUniquePtr =
            std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;

        CtxUniquePtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) {
            ThrowOpenSSLError("doCrypt: EVP_CIPHER_CTX_new");
        }

        if (EVP_CipherInit_ex(ctx.get(),          //
                              params.cipher,      //
                              nullptr,            //
                              params.key.data(),  //
                              params.iv.data(),   //
                              params.encrypt) != 1) {
            ThrowOpenSSLError("doCrypt: EVP_CipherInit_ex");
        }

        constexpr std::size_t chunkSize = 1024;
        std::array<char, chunkSize> inBuf{};
        std::array<unsigned char, chunkSize + EVP_MAX_BLOCK_LENGTH> outBuf{};
        int outLen{0};

        auto writeOutStream = [&](int size) {
            outStream.write(reinterpret_cast<char *>(outBuf.data()), static_cast<std::streamsize>(size));

            if (!outStream)
                throw std::runtime_error("Output write failed");
        };

        while (true) {
            inStream.read(inBuf.data(), static_cast<std::streamsize>(inBuf.size()));
            if (inStream.bad() || (inStream.fail() && !inStream.eof())) {
                throw std::runtime_error("Input read failed");
            }
            const auto bytesReaded{inStream.gcount()};
            if (bytesReaded > 0) {
                if (EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen,
                                     reinterpret_cast<const unsigned char *>(inBuf.data()),
                                     static_cast<int>(bytesReaded)) != 1) {
                    ThrowOpenSSLError("doCrypt: EVP_CipherUpdate");
                }
                writeOutStream(outLen);
            }
            if (inStream.eof()) {
                break;
            }
        }
        if (EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen) != 1) {
            ThrowOpenSSLError("doCrypt: EVP_CipherFinal_ex");
        }
        writeOutStream(outLen);
        outStream.flush();
        if (!outStream) {
            throw std::runtime_error("OutStream flush failed");
        }
    }
    void ThrowOpenSSLError(std::string_view operation) {
        std::ostringstream message;
        message << operation << " failed";

        bool hasErrors = false;

        while (const unsigned long code = ERR_get_error()) {
            constexpr std::size_t textSize = 256;
            std::array<char, textSize> text{};

            ERR_error_string_n(code, text.data(), text.size());

            message << "\n  " << text.data();
            hasErrors = true;
        }

        if (!hasErrors) {
            message << ": OpenSSL error queue is empty";
        }
        throw std::runtime_error(message.str());
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
