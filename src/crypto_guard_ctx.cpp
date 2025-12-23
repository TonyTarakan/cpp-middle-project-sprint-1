#include "crypto_guard_ctx.h"
#include <array>
#include <iostream>
#include <memory>
#include <openssl/evp.h>
#include <string>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm
    int encrypt;                                   // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;       // Encryption key
    std::array<unsigned char, IV_SIZE> iv;         // Initialization vector
};

class CryptoGuardCtx::Impl {
public:
    Impl() { OpenSSL_add_all_algorithms(); }

    ~Impl() { EVP_cleanup(); }

public:
    const void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        AesCipherParams params = CreateCipherParamsFromPassword(password);
        params.encrypt = 1;
        DoCrypt(inStream, outStream, params);
    }

    const void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        AesCipherParams params = CreateCipherParamsFromPassword(password);
        params.encrypt = 0;
        DoCrypt(inStream, outStream, params);
    }

    const std::string CalculateChecksum(std::iostream &inStream) {

        if (!inStream.good()) {
            throw std::runtime_error{"Stream error"};
        }

        std::array<unsigned char, AesCipherParams::IV_SIZE> inBuf;
        std::array<unsigned char, EVP_MAX_MD_SIZE> outBuf;

        if (!EVP_DigestInit_ex(ctxCS_.get(), EVP_sha256(), nullptr)) {
            throw std::runtime_error{"EVP_DigestInit_ex failed"};
        }

        while (inStream) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
            if (!EVP_DigestUpdate(ctxCS_.get(), inBuf.data(), inStream.gcount())) {
                throw std::runtime_error{"EVP_DigestUpdate failed"};
            }
        }

        unsigned int outLen;
        if (!EVP_DigestFinal_ex(ctxCS_.get(), outBuf.data(), &outLen)) {
            throw std::runtime_error{"EVP_DigestFinal_ex failed"};
        }

        std::string result;
        std::for_each(outBuf.begin(), outBuf.begin() + outLen,
                      [&result](auto byte) { std::format_to(std::back_inserter(result), "{:02x}", byte); });
        return result;
    }

private:
    const AesCipherParams CreateCipherParamsFromPassword(const std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }

    const void DoCrypt(std::iostream &inStream, std::iostream &outStream, const AesCipherParams &params) {

        if (!inStream.good() || !outStream.good()) {
            throw std::runtime_error{"Stream error"};
        }

        EVP_CIPHER_CTX_reset(ctx_.get());

        if (!EVP_CipherInit_ex(ctx_.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                               params.encrypt)) {
            throw std::runtime_error{"EVP_CipherInit_ex failed"};
        }

        std::array<unsigned char, AesCipherParams::IV_SIZE> inBuf;
        std::array<unsigned char, AesCipherParams::IV_SIZE + EVP_MAX_BLOCK_LENGTH> outBuf;
        int outLen{0};

        while (inStream) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());

            if (!EVP_CipherUpdate(ctx_.get(), outBuf.data(), &outLen, inBuf.data(), inStream.gcount())) {
                throw std::runtime_error{"EVP_CipherUpdate failed"};
            }
            // std::cout << "inLen = " << inLen << ", outLen = " << outLen << std::endl;
            outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
        }

        if (!inStream.eof() && inStream.fail()) {
            throw std::runtime_error{"Input stream error"};
        }

        if (!EVP_CipherFinal_ex(ctx_.get(), outBuf.data(), &outLen)) {
            throw std::runtime_error{"EVP_CipherFinal_ex failed"};
        }
        outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
    }

private:
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx_{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctxCS_{EVP_MD_CTX_new(), EVP_MD_CTX_free};
};

// Redefinitions

CryptoGuardCtx::CryptoGuardCtx() : pImpl_{std::make_unique<Impl>()} {};

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
};

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); };

}  // namespace CryptoGuard
