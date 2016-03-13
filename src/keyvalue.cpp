#include "coopfs.h"

#include <unordered_map>
#include <map>

CofsKeyValue::~CofsKeyValue()
{

}

CofsContentHash CofsHashContent(CofsSpan<uint8_t> content)
{
    CofsContentHash out;
    crypto_generichash(out.data(), out.size(),
                   content.data(), content.size(),
                   NULL, 0);
    return out;
}

std::array<uint8_t, crypto_sign_BYTES> CofsSignContent(CofsSpan<uint8_t> secret_key, CofsSpan<uint8_t> name, uint64_t version, CofsSpan<uint8_t> content)
{
    Expects(secret_key.size() == crypto_sign_SECRETKEYBYTES);

    std::array<uint8_t, crypto_sign_BYTES> signature;

    std::vector<uint8_t> m;
    CofsSpan<uint8_t> version_span((uint8_t *)&version, sizeof(version));
    m.insert(m.end(), name.begin(), name.end());
    m.insert(m.end(), version_span.begin(), version_span.end());
    m.insert(m.end(), content.begin(), content.end());

    int ret = crypto_sign_detached(signature.data(), NULL,
                         m.data(), m.size(),
                         secret_key.data());
    Ensures(ret == 0);

    return signature;
}

bool CofsVerifySignedContent(CofsSpan<uint8_t> public_key, CofsSpan<uint8_t> name, uint64_t version, CofsSpan<uint8_t> content, CofsSpan<uint8_t> signature)
{
    Expects(public_key.size() == crypto_sign_PUBLICKEYBYTES);
    Expects(signature.size() == crypto_sign_BYTES);

    std::vector<uint8_t> m;
    CofsSpan<uint8_t> version_span((uint8_t *)&version, sizeof(version));
    m.insert(m.end(), name.begin(), name.end());
    m.insert(m.end(), version_span.begin(), version_span.end());
    m.insert(m.end(), content.begin(), content.end());

    return crypto_sign_verify_detached(signature.data(),
                                m.data(), m.size(),
                                public_key.data()) == 0;
}

class CofsContentHashHash {
public:
    CofsContentHashHash()
    {
        randombytes_buf(m_key, sizeof(m_key));
    }
    size_t operator()(const CofsContentHash &content_hash) const
    {
        static_assert(crypto_shorthash_BYTES == sizeof(size_t), "shorthash must return size_t bytes");
        size_t out;
        crypto_shorthash((uint8_t*)&out, content_hash.data(), content_hash.size(), m_key);
        return out;
    }
private:
    uint8_t m_key[crypto_shorthash_KEYBYTES];
};

class CofsSignedHash {
public:
    CofsSignedHash()
    {
        randombytes_buf(m_key, sizeof(m_key));
    }
    size_t operator()(const std::tuple<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>, std::vector<uint8_t>> &key) const
    {
        static_assert(crypto_shorthash_BYTES == sizeof(size_t), "shorthash must return size_t bytes");
        size_t out[2];
        crypto_shorthash((uint8_t*)&out[0], std::get<0>(key).data(), std::get<0>(key).size(), m_key);
        crypto_shorthash((uint8_t*)&out[1], std::get<1>(key).data(), std::get<1>(key).size(), m_key);
        return out[0] ^ out[1];
    }
private:
    uint8_t m_key[crypto_shorthash_KEYBYTES];
};

struct CofsKeyValueMemory::Private {
    std::unordered_map<CofsContentHash, std::vector<uint8_t>, CofsContentHashHash> content_map;
    using content_iterator = decltype(content_map)::iterator;

    std::unordered_map<
        std::tuple<
            std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>,
            std::vector<uint8_t>>,
        std::map<
            uint64_t,
            std::vector<uint8_t>>,
        CofsSignedHash> signed_map;
    using signed_iterator = decltype(signed_map)::iterator;
};

CofsKeyValueMemory::CofsKeyValueMemory() : m_priv(new Private)
{
}

CofsKeyValueMemory::~CofsKeyValueMemory()
{
}

std::tuple<bool, std::vector<uint8_t>> CofsKeyValueMemory::get_content(CofsContentHash key)
{
    auto it = m_priv->content_map.find(key);
    if (it == m_priv->content_map.end()) {
        return std::tuple<bool, std::vector<uint8_t>>();
    }
    return std::make_tuple(true, it->second);
}

CofsContentHash CofsKeyValueMemory::set_content(CofsSpan<uint8_t> content)
{
    Private::content_iterator it;
    std::tie(it, std::ignore) = m_priv->content_map.emplace(std::piecewise_construct,
        std::forward_as_tuple(CofsHashContent(content)),
        std::forward_as_tuple(content.begin(), content.end()));
    return it->first;
}

std::tuple<bool, size_t, std::vector<uint8_t>> CofsKeyValueMemory::get_signed(CofsSpan<uint8_t> public_key, CofsSpan<uint8_t> name)
{
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pk;
    std::copy(public_key.begin(), public_key.end(), pk.begin());
    auto it = m_priv->signed_map.find(std::make_tuple(pk, std::vector<uint8_t>(name.begin(), name.end())));
    if (it != m_priv->signed_map.end()) {
        auto content_it = it->second.begin();
        return std::make_tuple(true, content_it->first, content_it->second);
    }
    return std::make_tuple(0, 0, std::vector<uint8_t>());
}

bool CofsKeyValueMemory::set_signed(CofsSpan<uint8_t> public_key, CofsSpan<uint8_t> name, uint64_t version, CofsSpan<uint8_t> content, CofsSpan<uint8_t> signature)
{
    if (!CofsVerifySignedContent(public_key, name, version, content, signature))
        return false;
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pk;
    std::copy(public_key.begin(), public_key.end(), pk.begin());
    m_priv->signed_map[std::make_tuple(pk, std::vector<uint8_t>(name.begin(), name.end()))].emplace(std::piecewise_construct,
        std::forward_as_tuple(version),
        std::forward_as_tuple(content.begin(), content.end()));
    return true;
}