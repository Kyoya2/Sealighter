#pragma once

#include <exception>
#include <cstdarg>
#include <cstdio>
#include <string>

class SealighterException : public std::exception
{
public:
    SealighterException(const char* format, ...) :
        std::exception(),
        description()
    {
        va_list arg_ptr;
        va_start(arg_ptr, format);
        description = std::string(1 + std::vsnprintf(nullptr, 0, format, arg_ptr), '\0');
        std::vsnprintf(description.data(), description.size(), format, arg_ptr);
        va_end(arg_ptr);
    }

    [[nodiscard]] virtual char const* what() const { return description.c_str(); }

private:
    std::string description;
};