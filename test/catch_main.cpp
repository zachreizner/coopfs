#include <iostream>

#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

#include <sodium.h>

int main(int argc, char **argv)
{
    if (sodium_init() == -1) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    Catch::Session session;
    int ret = session.applyCommandLine(argc, argv);
    if (ret)
        return ret;

    ret = session.run();

    return ret;
}
