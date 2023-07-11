#include "krabs.hpp"
#include <sstream>
#include <fstream>
#include <codecvt>
#include <cwctype>
#include <locale>
#include "sealighter_json.h"
#include "sealighter_util.h"


std::string Utils::Convert::to_lowercase(const std::string& from)
{
    std::string to = from;
    std::transform(to.begin(), to.end(), to.begin(),
        [](char c) { return (char)std::tolower(c); });
    return to;
}


std::wstring Utils::Convert::to_lowercase(const std::wstring& from)
{
    std::wstring to = from;
    std::transform(to.begin(), to.end(), to.begin(),
        [](wchar_t c) { return std::towlower(c); });
    return to;
}


std::string Utils::Convert::wstr_to_str(const std::wstring& from)
{
    int result_size = WideCharToMultiByte(CP_UTF8, 0, from.c_str(), (int)from.size(), nullptr, 0, nullptr, nullptr);
    std::string result(result_size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, from.c_str(), (int)from.size(), result.data(), result_size, nullptr, nullptr);
    return result;
}


std::wstring Utils::Convert::str_to_wstr(const std::string& from)
{
    int result_size = MultiByteToWideChar(CP_UTF8, 0, from.c_str(), (int)from.size(), nullptr, 0);
    std::wstring result(result_size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, from.c_str(), (int)from.size(), result.data(), result_size);
    return result;
}


std::wstring Utils::Convert::str_to_lower_wstr(const std::string& from)
{
    return Utils::Convert::str_to_wstr(Utils::Convert::to_lowercase(from));
}


std::vector<BYTE> Utils::Convert::str_to_lower_bytes(const std::string& from)
{
    std::string from_lower = Utils::Convert::to_lowercase(from);
    std::vector<BYTE> to(from_lower.begin(), from_lower.end());
    return to;
}


std::vector<BYTE> Utils::Convert::str_to_lower_wstr_bytes(const std::string& from)
{
    std::wstring from_wide_lower = Utils::Convert::str_to_lower_wstr(from);
    BYTE* from_bytes = (BYTE*)from_wide_lower.c_str();
    // Size returns string len, so double as they are widechars
    // But don't copy in trailing NULL so we can match mid-string
    size_t from_bytes_size = from_wide_lower.size() * sizeof(WCHAR);

    std::vector<BYTE> to(from_bytes, from_bytes + from_bytes_size);
    return to;
}


std::string Utils::Convert::guid_to_str(const GUID& from)
{
    std::string result(38, '\0'); // 2 braces + 32 hex chars + 4 hyphens
    snprintf(result.data(), result.size() + 1,
             "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
             from.Data1, from.Data2, from.Data3,
             from.Data4[0], from.Data4[1], from.Data4[2],
             from.Data4[3], from.Data4[4], from.Data4[5],
             from.Data4[6], from.Data4[7]);

    return result;
}


GUID Utils::Convert::wstr_to_guid(const std::wstring& from)
{
    GUID to = GUID_NULL;
    (void)CLSIDFromString(from.c_str(), (LPCLSID)&to);

    return to;
}


GUID Utils::Convert::str_to_guid(const std::string& from)
{
    return Utils::Convert::wstr_to_guid(Utils::Convert::str_to_wstr(from));
}


std::string Utils::Convert::time_to_str(const LARGE_INTEGER& from)
{
    FILETIME ft = { (DWORD)from.LowPart, (DWORD)from.HighPart };
    return Utils::Convert::time_to_str(ft);
}


std::string Utils::Convert::time_to_str(const FILETIME& from)
{
    FILETIME local_ftime;
    SYSTEMTIME stime;

    ::FileTimeToLocalFileTime(&from, &local_ftime);
    ::FileTimeToSystemTime(&local_ftime, &stime);

    return Utils::Convert::time_to_str(stime);
}


std::string Utils::Convert::time_to_str(const SYSTEMTIME& from)
{
    std::string result(sizeof("1970-01-01 00:00:00.000") - 1, '\0');
    snprintf(result.data(), result.size() + 1,
             "%04hu-%02hu-%02hu %02hu:%02hu:%02hu.%03hu",
             from.wYear, from.wMonth, from.wDay, from.wHour,
             from.wMinute, from.wSecond, from.wMilliseconds);

    return result;
}


std::string Utils::Convert::bytes_to_hex_str(const std::vector<BYTE>& from)
{
    return Utils::Convert::bytes_to_hex_str(from.data(), (int)from.size());
}


std::string Utils::Convert::bytes_to_hex_str(const BYTE* from, int len)
{
    static constexpr char hexmap[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                       '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    std::string result(len * 2, '\0');
    for (int i = 0; i < len; ++i)
    {
        result[2 * i]     = hexmap[(from[i] & 0xF0) >> 4];
        result[2 * i + 1] = hexmap[from[i] & 0x0F];
    }
    return result;
}


std::string Utils::Convert::ulong64_to_hex_str(const ULONG64 from)
{
    std::stringstream to;
    to << "0x" << std::uppercase << std::hex << from;
    return to.str();
}


std::string Utils::Convert::json_to_string(json item, bool pretty_print)
{
    if (pretty_print) {
        return item.dump(4, ' ', false, nlohmann::detail::error_handler_t::ignore);
    }
    else {
        return item.dump(-1, ' ', false, nlohmann::detail::error_handler_t::ignore);
    }
}


bool Utils::file_exists(const std::string& file_name)
{
    DWORD file_attributes = GetFileAttributesA(file_name.c_str());
    return (file_attributes != INVALID_FILE_ATTRIBUTES &&
           !(file_attributes & FILE_ATTRIBUTE_DIRECTORY));
}


VOID Utils::log_message(const CHAR* format, ...)
{
    CHAR message[0x1000];

    va_list arg_ptr;
    va_start(arg_ptr, format);
    _vsnprintf_s(message, sizeof(message), sizeof(message) - 1, format, arg_ptr);
    va_end(arg_ptr);
    OutputDebugStringA(message);
    printf("%s", message);
}
