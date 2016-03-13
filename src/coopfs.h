#ifndef __COOPFS_H__
#define __COOPFS_H__

#include <tuple>
#include <vector>
#include <memory>

#include <sodium.h>
#include <zmq.hpp>

#include "gsl.h"

template<typename T>
using CofsSpan = gsl::span<T>;

using CofsContentHash = std::array<uint8_t, crypto_generichash_BYTES>;

std::array<uint8_t, crypto_sign_BYTES> CofsSignContent(CofsSpan<uint8_t> secret_key, CofsSpan<uint8_t> name, uint64_t version, CofsSpan<uint8_t> content);
bool CofsVerifySignedContent(CofsSpan<uint8_t> public_key, CofsSpan<uint8_t> name, uint64_t version, CofsSpan<uint8_t> content, CofsSpan<uint8_t> signature);

class CofsKeyValue {
public:
    virtual ~CofsKeyValue();

    // return.0 is true iff the key exists
    // return.1 is the content
    virtual std::tuple<bool, std::vector<uint8_t>> get_content(CofsContentHash key) = 0;
    // return the key to retrieve the content
    virtual CofsContentHash set_content(CofsSpan<uint8_t> content) = 0;

    // return.0 is true iff the public_key/name combination exists
    // return.1 is the content
    // return.2 is the content version
    virtual std::tuple<bool, size_t, std::vector<uint8_t>> get_signed(CofsSpan<uint8_t> public_key, CofsSpan<uint8_t> name) = 0;
    // return true if the signature was valid
    virtual bool set_signed(CofsSpan<uint8_t> public_key, CofsSpan<uint8_t> name, uint64_t version, CofsSpan<uint8_t> content, CofsSpan<uint8_t> signature) = 0;
};


class CofsKeyValueMemory : public CofsKeyValue
{
public:
    CofsKeyValueMemory();
    virtual ~CofsKeyValueMemory();
    virtual std::tuple<bool, std::vector<uint8_t>> get_content(CofsContentHash key);
    virtual CofsContentHash set_content(CofsSpan<uint8_t> content);
    virtual std::tuple<bool, size_t, std::vector<uint8_t>> get_signed(CofsSpan<uint8_t> public_key, CofsSpan<uint8_t> name);
    virtual bool set_signed(CofsSpan<uint8_t> public_key, CofsSpan<uint8_t> name, uint64_t version, CofsSpan<uint8_t> content, CofsSpan<uint8_t> signature);
private:
    struct Private;
    std::unique_ptr<Private> m_priv;
};

#endif