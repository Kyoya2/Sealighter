#pragma once
#include "sealighter_json.h"


namespace Utils
{
    namespace Convert
    {
        // String manipulation
        std::string to_lowercase(const std::string& from);
        std::wstring to_lowercase(const std::wstring& from);
        std::string wstr_to_str(const std::wstring& from);
        std::wstring str_to_wstr(const std::string& from);
        std::wstring str_to_lower_wstr(const std::string& from);
        std::vector<BYTE> str_to_lower_bytes(const std::string& from);
        std::vector<BYTE> str_to_lower_wstr_bytes(const std::string& from);

        // Timne convertion
        std::string time_to_str(const LARGE_INTEGER& from);
        std::string time_to_str(const FILETIME& from);
        std::string time_to_str(const SYSTEMTIME& from);

        // GUID convertion
        std::string guid_to_str(const GUID& from);
        GUID wstr_to_guid(const std::wstring& from);
        GUID str_to_guid(const std::string& from);

        // Binary convertion
        std::string bytes_to_hex_str(const std::vector<BYTE>& from);
        std::string bytes_to_hex_str(const BYTE* from, int len);
        std::string ulong64_to_hex_str(const ULONG64 from);

        std::string json_to_string(json item, bool pretty_print);
    }

    bool file_exists(const std::string& file_name);

    void log_message(const CHAR* format, ...);
}