#include "catch.hpp"

#include "coopfs.h"

TEST_CASE("sign", "[keyvalue]")
{
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
    int ret = crypto_sign_keypair(pk, sk);
    REQUIRE(ret == 0);

    uint8_t name[] = "hello";
    uint8_t content[] = "world";
    auto signature = CofsSignContent(sk, name, 1001, content);

    SECTION("verify failure") {
        SECTION("bad public key") {
            pk[0] ^= 1;
            bool verified = CofsVerifySignedContent(pk, name, 1001, content, signature);
            CHECK(!verified);
        }
        SECTION("bad name") {
            uint8_t fake_name[] = "byeee";
            bool verified = CofsVerifySignedContent(pk, fake_name, 1001, content, signature);
            CHECK(!verified);
        }
        SECTION("bad version") {
            bool verified = CofsVerifySignedContent(pk, name, 9999, content, signature);
            CHECK(!verified);
        }
        SECTION("bad signature") {
            signature[0] ^= 1;
            bool verified = CofsVerifySignedContent(pk, name, 1001, content, signature);
            CHECK(!verified);
        }
        SECTION("bad content") {
            content[0] = 'm';
            bool verified = CofsVerifySignedContent(pk, name, 1001, content, signature);
            CHECK(!verified);
        }
    }

    SECTION("verify success") {
        bool verified = CofsVerifySignedContent(pk, name, 1001, content, signature);
        CHECK(verified);
    }
}

TEST_CASE("memory", "[keyvalue]")
{
    CofsKeyValueMemory kv;

    SECTION("content") {
        uint8_t content[] = "hello";
        auto key = kv.set_content(content);

        bool exists;
        std::vector<uint8_t> content_got;

        std::tie(exists, content_got) = kv.get_content(key);
        CHECK(exists);
        CHECK(gsl::as_span(content_got) == gsl::as_span(content));

        SECTION("bad key") {
            key[0] ^= 1;
            std::tie(exists, content_got) = kv.get_content(key);
            CHECK(!exists);
        }
    }

    SECTION("signed") {
        uint8_t pk[crypto_sign_PUBLICKEYBYTES];
        uint8_t sk[crypto_sign_SECRETKEYBYTES];
        int ret = crypto_sign_keypair(pk, sk);
        REQUIRE(ret == 0);

        uint8_t name[] = "stacy";
        uint8_t content[] = "has the latest shipment";
        std::array<uint8_t, crypto_sign_BYTES> signature = CofsSignContent(sk, name, 1002, content);

        bool success = kv.set_signed(pk, name, 1002, content, signature);
        CHECK(success);

        bool exists;
        std::vector<uint8_t> content_got;
        uint64_t version;
        std::tie(exists, version, content_got) = kv.get_signed(pk, name);
        CHECK(exists);
        CHECK(gsl::as_span(content_got) == gsl::as_span(content));

        SECTION("verify failure") {
            SECTION("bad key") {
                pk[0] ^= 1;
                bool success = kv.set_signed(pk, name, 1002, content, signature);
                CHECK(!success);
            }
            SECTION("bad name") {
                name[0] ^= 1;
                bool success = kv.set_signed(pk, name, 1002, content, signature);
                CHECK(!success);
            }
            SECTION("bad version") {
                bool success = kv.set_signed(pk, name, 1003, content, signature);
                CHECK(!success);
            }
            SECTION("bad signature") {
                signature[0] ^= 1;
                bool success = kv.set_signed(pk, name, 1002, content, signature);
                CHECK(!success);
            }
            SECTION("bad content") {
                content[0] ^= 1;
                bool success = kv.set_signed(pk, name, 1002, content, signature);
                CHECK(!success);
            }
        }
    }
}