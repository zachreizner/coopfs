#include "catch.hpp"

TEST_CASE("running catch", "[trivial]")
{
    REQUIRE(1 + 1 == 2);
    REQUIRE(1 + 0 < 3);
    REQUIRE(5 + 11 > 15);
}