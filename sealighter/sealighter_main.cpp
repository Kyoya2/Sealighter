#include <iostream>
#include <fstream>
#include <string>
#include "sealighter_handler.h"
#include "sealighter_util.h"
#include "sealighter_controller.h"
#include "sealighter_exception.h"

int main
(
    int argc,
    char* argv[]
)
{
    try
    {
        if (2 != argc) {
            throw SealighterException("Usage: sealighter.exe <config_file>");
        }

        std::string config_path = argv[1];

        std::ifstream config_stream(config_path);
        std::string config_string((std::istreambuf_iterator<char>(config_stream)),
            (std::istreambuf_iterator<char>()));
        config_stream.close();

        run_sealighter(config_string);
    }
    catch (const std::exception& e)
    {
        Utils::log_message("%s", e.what());
    }

    return 0;
}
