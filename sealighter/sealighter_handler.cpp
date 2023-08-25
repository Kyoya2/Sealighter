#include "krabs.hpp"
#include "sealighter_handler.h"
#include "sealighter_util.h"
#include "sealighter_provider.h"
#include "sealighter_exception.h"

#include <fstream>
#include <mutex>
#include <atomic>

using namespace krabs;

// -------------------------
// GLOBALS - START
// -------------------------

// Output file to write events to
static std::ofstream g_outfile;

// Helper mutex to ensure threaded functions
// print a whole event without interruption
static std::mutex g_print_mutex;

// Holds format
static Output_format g_output_format;

// Hold data for buffering
static std::map<std::string, std::vector<event_buffer_list_t>> g_buffer_lists;
// Default to 30 seconds
static std::uint32_t g_buffer_lists_timeout_seconds = 5;
static std::mutex g_buffer_lists_mutex;
static std::thread g_buffer_list_thread;
static std::atomic_bool g_buffer_thread_stop = false;
static std::condition_variable g_buffer_list_con_var;

// -------------------------
// GLOBALS - END
// -------------------------
// PRIVATE FUNCTIONS - START
// -------------------------


/*
    Print a line to stdout, using a mutex
    to ensure we print each event wholey before
    another can
*/
void threaded_print_ln
(
    std::string event_string
)
{
    g_print_mutex.lock();
    Utils::log_message("%s\n", event_string.c_str());
    g_print_mutex.unlock();
}


/*
    Write to Event Log
*/
void write_event_log
(
    const json& json_event,
    std::string event_string
)
{
    const json header_json = json_event.at("header");

    // TODO: Make sure we didn't break this
    // Also fix up schema, no need to to all the str_wstr converting
    // Also fix up timestamp string
    DWORD status = EventWriteSEALIGHTER_REPORT_EVENT(
        event_string.c_str(),
        header_json.at("activity_id").get<std::string>().c_str(),
        (USHORT)header_json.at("event_flags").get<std::uint32_t>(),
        (USHORT)header_json.at("event_id").get<std::uint32_t>(),
        Utils::Convert::str_to_wstr(header_json.at("event_name").get<std::string>()).c_str(),
        (UCHAR)header_json.at("event_opcode").get<std::uint32_t>(),
        (UCHAR)header_json.at("event_version").get<std::uint32_t>(),
        header_json.at("process_id").get<std::uint32_t>(),
        Utils::Convert::str_to_wstr(header_json.at("provider_name").get<std::string>()).c_str(),
        Utils::Convert::str_to_wstr(header_json.at("task_name").get<std::string>()).c_str(),
        header_json.at("thread_id").get<std::uint32_t>(),
        0,  // schema.timestamp().quadPart
        header_json.at("trace_name").get<std::string>().c_str()
    );

    if (status != ERROR_SUCCESS) {
        throw SealighterException("Failed to report event, error %ul", status);
    }
}


/*
    Print a line to an output file, using a mutex
    to ensure we print each event wholey before
    another can
*/
void threaded_write_file_ln
(
    std::string event_string
)
{
    g_print_mutex.lock();
    g_outfile << event_string << std::endl;
    g_print_mutex.unlock();
}


/*
    Convert an ETW Event to JSON
*/
json parse_event_to_json
(
    const EVENT_RECORD& record,
    const trace_context&,
    std::shared_ptr<sealighter_context_t> sealighter_context,
    krabs::schema schema
)
{
    // Define some macros to easilly handle simillar switch-cases
#pragma region MacroDefinition

// Converts any (enum _TDH_IN_TYPE) property type identifier to a string
// that describes the type only, without the "TDH_INTYPE_" prefix.
// This is done by stringifying the enum name and adding the value
// of the length of the prefix.
#define SELAIGHTER_GET_TYPE_NAME(property_type) (#property_type + 11)

// Handles the parsing of the given property type with the
// given value (will be evaluated when encountered)
#define SEALIGHTER_PARSE_PROPERTY_TEMPLATE(property_type, additional_code) \
case property_type:                                                        \
    property_type_string = SELAIGHTER_GET_TYPE_NAME(property_type);        \
    additional_code;                                                       \
    break

// Handles the parsing of proprty types that can parsed in a
// single C++ statement
#define SEALIGHTER_PARSE_PROPERTY_STATEMENT(property_type, value) \
    SEALIGHTER_PARSE_PROPERTY_TEMPLATE(                           \
        property_type,                                            \
        json_properties[prop_name] = (value)                      \
    );

// Same as above but handles simple types that can be converted
// directly using krabs::parser::pasre
#define SEALIGHTER_PARSE_PROPERTY(property_type, simple_value_type) \
    SEALIGHTER_PARSE_PROPERTY_STATEMENT(property_type, parser.parse<simple_value_type>(prop_name_wstr))

// Parses all of the "TDH_INTYPE_*COUNTED*STRING" types. The reason that
// "krabs::parser::pasre<krabs::counted_string>" is not used here is because
// it doesn't take the endianness of the uint16_t prefix into concideration
// and always assumes that it's little-endian, which isn't true for types like
// "TDH_INTYPE_REVERSEDCOUNTEDSTRING". This macro parses the counted-string
// without even reading the value of the size prefix, which allows it to parse
// counted-strings of any endianness,
#define SEALIGHTER_PARSE_COUNTED_STRING(property_type, is_wide)            \
    SEALIGHTER_PARSE_PROPERTY_TEMPLATE(                                    \
        property_type,                                                     \
        {auto buffer = parser.parse<krabs::binary>(prop_name_wstr);        \
        auto str_begin = buffer.bytes().data() + sizeof(uint16_t);         \
        auto str_end = buffer.bytes().data() + buffer.bytes().size();      \
        if (is_wide) {                                                     \
            json_properties[prop_name] =                                   \
                Utils::Convert::wstr_to_str(                               \
                    std::wstring((wchar_t*)str_begin, (wchar_t*)str_end)); \
        } else {                                                           \
            json_properties[prop_name] = std::string(str_begin, str_end);  \
        }}                                                                 \
    );

// Used for types that don't have parser implementations,
// will be parsed as a hex-string.
#define SEALIGHTER_PARSE_AS_BINARY(property_type) \
    SEALIGHTER_PARSE_PROPERTY_TEMPLATE(           \
        property_type,                            \
        parse_as_binary = true;                   \
    );
#pragma endregion

    std::string trace_name = sealighter_context->trace_name;
    json json_properties;
    json json_properties_types;
    json json_header = {
        { "event_id", schema.event_id() },
        { "event_name", Utils::Convert::wstr_to_str(schema.event_name()) },
        { "task_name", Utils::Convert::wstr_to_str(schema.task_name()) },
        { "thread_id", schema.thread_id() },
        { "timestamp", Utils::Convert::time_to_str(schema.timestamp()) },
        { "event_flags", schema.event_flags() },
        { "event_opcode", schema.event_opcode() },
        { "event_version", schema.event_version() },
        { "process_id", schema.process_id()},
        { "provider_name", Utils::Convert::wstr_to_str(schema.provider_name()) },
        { "activity_id", Utils::Convert::guid_to_str(schema.activity_id()) },
        { "trace_name", trace_name},
    };

    json json_event = { {"header", json_header} };

    // Check if we are just dumping the raw event, or attempting to parse it
    if (sealighter_context->dump_raw_event) {
        std::string raw_hex = Utils::Convert::bytes_to_hex_str((BYTE*)record.UserData, record.UserDataLength);
        json_event["raw"] = raw_hex;
    }
    else {
        krabs::parser parser(schema);
        for (krabs::property& prop : parser.properties()) {
            std::wstring prop_name_wstr = prop.name();
            std::string prop_name = Utils::Convert::wstr_to_str(prop_name_wstr);
            bool parse_as_binary = false;
            const char* property_type_string = nullptr;

            try
            {
                switch (prop.type())
                {
                    // Types that can be parsed directly by krabsetw
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_BOOLEAN,     bool);
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_INT8,        int8_t);
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_UINT8,       uint8_t);
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_ANSICHAR,    char);
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_INT16,       int16_t);
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_UINT16,      uint16_t);
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_UNICODECHAR, wchar_t);
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_INT32,       int32_t);
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_UINT32,      uint32_t);
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_HEXINT32,    uint32_t);
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_INT64,       int64_t);
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_UINT64,      uint64_t);
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_HEXINT64,    uint64_t);
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_FLOAT,       float_t);
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_DOUBLE,      double_t);
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_SIZET,       SIZE_T);
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_ANSISTRING,  std::string);
                    SEALIGHTER_PARSE_PROPERTY(TDH_INTYPE_NONNULLTERMINATEDANSISTRING, std::string);

                    // String types that have a `uint_16` before their value (counted types)
                    SEALIGHTER_PARSE_COUNTED_STRING(TDH_INTYPE_COUNTEDANSISTRING,          false);
                    SEALIGHTER_PARSE_COUNTED_STRING(TDH_INTYPE_MANIFEST_COUNTEDANSISTRING, false);
                    SEALIGHTER_PARSE_COUNTED_STRING(TDH_INTYPE_REVERSEDCOUNTEDANSISTRING,  false);
                    SEALIGHTER_PARSE_COUNTED_STRING(TDH_INTYPE_COUNTEDSTRING,              true);
                    SEALIGHTER_PARSE_COUNTED_STRING(TDH_INTYPE_MANIFEST_COUNTEDSTRING,     true);
                    SEALIGHTER_PARSE_COUNTED_STRING(TDH_INTYPE_REVERSEDCOUNTEDSTRING,      true);

                    // Types with single-statement parsers
                    SEALIGHTER_PARSE_PROPERTY_STATEMENT(TDH_INTYPE_POINTER,       Utils::Convert::ulong64_to_hex_str(parser.parse<krabs::pointer>(prop_name_wstr).address));
                    SEALIGHTER_PARSE_PROPERTY_STATEMENT(TDH_INTYPE_FILETIME,      Utils::Convert::time_to_str(parser.parse<FILETIME>(prop_name_wstr)));
                    SEALIGHTER_PARSE_PROPERTY_STATEMENT(TDH_INTYPE_SYSTEMTIME,    Utils::Convert::time_to_str(parser.parse<SYSTEMTIME>(prop_name_wstr)));
                    SEALIGHTER_PARSE_PROPERTY_STATEMENT(TDH_INTYPE_GUID,          Utils::Convert::guid_to_str(parser.parse<GUID>(prop_name_wstr)));
                    SEALIGHTER_PARSE_PROPERTY_STATEMENT(TDH_INTYPE_SID,           std::move(parser.parse<krabs::sid>(prop_name_wstr).sid_string));
                    SEALIGHTER_PARSE_PROPERTY_STATEMENT(TDH_INTYPE_WBEMSID,       std::move(parser.parse<krabs::sid>(prop_name_wstr).sid_string));
                    SEALIGHTER_PARSE_PROPERTY_STATEMENT(TDH_INTYPE_UNICODESTRING, Utils::Convert::wstr_to_str(parser.parse<std::wstring>(prop_name_wstr)));
                    SEALIGHTER_PARSE_PROPERTY_STATEMENT(TDH_INTYPE_NONNULLTERMINATEDSTRING, Utils::Convert::wstr_to_str(parser.parse<std::wstring>(prop_name_wstr)));

                    // Types that need multiline-implementations
                    SEALIGHTER_PARSE_PROPERTY_TEMPLATE(TDH_INTYPE_MANIFEST_COUNTEDBINARY, {
                        auto buffer = parser.parse<krabs::binary>(prop_name_wstr);
                        json_properties[prop_name] = Utils::Convert::bytes_to_hex_str(
                            buffer.bytes().data() + sizeof(uint16_t),
                            (int)buffer.bytes().size() - sizeof(uint16_t)
                        );
                    });

                    // Types that should be interpreted as binary
                    SEALIGHTER_PARSE_AS_BINARY(TDH_INTYPE_HEXDUMP);
                    SEALIGHTER_PARSE_AS_BINARY(TDH_INTYPE_BINARY);

                    // Types with no supported parsers (also interpreted as binary)
                    SEALIGHTER_PARSE_AS_BINARY(TDH_INTYPE_RESERVED24);
                    SEALIGHTER_PARSE_AS_BINARY(TDH_INTYPE_NULL);

                default:
                    property_type_string = "UNKNOWN";
                    break;
                }

                // Interpret non-parsable types as a hex string
                if (parse_as_binary)
                    json_properties[prop_name] = Utils::Convert::bytes_to_hex_str(parser.parse<krabs::binary>(prop_name_wstr).bytes());

                if (sealighter_context->record_property_types)
                    json_properties_types[prop_name] = property_type_string;
            }
            catch (...)
            {
                // If encountered a parsing error, try to parse as hex-string.
                // 
                // This flow is common with providers that provide more data than needed for small integral data types.
                // for example, we may get a proprety with type 'uint8_t' but the actual data size is 4 bytes so the
                // parsing function "krabs::parser::parse<uint8_t>" will throw a "type_mismatch_assert" exception
                // which will lead us here.
                try
                {
                    json_properties[prop_name] =
                        Utils::Convert::bytes_to_hex_str(parser.parse<krabs::binary>(prop_name_wstr).bytes());

                    if (sealighter_context->record_property_types)
                        if (nullptr != property_type_string)
                        {
                            // Keep the name of the original type if it was deduced successfully
                            json_properties_types[prop_name] = std::string(property_type_string) + " (ERROR)";
                        }
                        else
                            json_properties_types[prop_name] = "ERROR";

                }
                catch (...) { /* Encountered a parsing error the second time, skip the current property */ }
            }
        }

        json_event["properties"] = json_properties;
        if (sealighter_context->record_property_types)
            json_event["property_types"] = json_properties_types;
    }

    // Check if we're meant to parse any extended data
    if (record.ExtendedDataCount != 0) {
        // At the moment we only support EVENT_HEADER_EXT_TYPE_STACK_TRACE64
        // The extra field is TRACE64 (and not TRACE32) even in the event the
        // process that generated the event is 32Bit
        for (USHORT i = 0; i < record.ExtendedDataCount; i++)
        {
            EVENT_HEADER_EXTENDED_DATA_ITEM data_item = record.ExtendedData[i];

            if (data_item.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
                PEVENT_EXTENDED_ITEM_STACK_TRACE64 stacktrace =
                    (PEVENT_EXTENDED_ITEM_STACK_TRACE64)data_item.DataPtr;
                uint32_t stack_length = (data_item.DataSize - sizeof(ULONG64)) / sizeof(ULONG64);

                json json_stacktrace = json::array();
                for (size_t x = 0; x < stack_length; x++)
                {
                    // Stacktraces make more sense in hex
                    json_stacktrace.push_back(Utils::Convert::ulong64_to_hex_str(stacktrace->Address[x]));
                }
                // We're ignoring the MatchId, which if not 0 then the stack is split across events
                // But stiching it together would be too much of a pain for the mostly-stateless
                // Sealighter. So we'll just collect what we've got.
                json_event["stack_trace"] = json_stacktrace;
            }
        }
    }

    return json_event;
}


void output_json_event
(
    const json& json_event
)
{
    // If writing to a file, don't pretty print
    // This makes it 1 line per event
    bool pretty_print = (Output_format::output_file != g_output_format);
    std::string event_string = Utils::Convert::json_to_string(json_event, pretty_print);

    // Log event if we successfully parsed it
    if (!event_string.empty()) {
        switch (g_output_format)
        {
        case output_stdout:
            threaded_print_ln(event_string);
            break;
        case output_event_log:
            write_event_log(json_event, event_string);
            break;
        case output_file:
            threaded_write_file_ln(event_string);
            break;
        }
    }
}


void handle_event_context
(
    const EVENT_RECORD& record,
    const trace_context& trace_context,
    std::shared_ptr<sealighter_context_t> sealighter_context
)
{
    json json_event;
    schema schema(record, trace_context.schema_locator);
    bool buffered = false;

    std::string trace_name = sealighter_context->trace_name;
    json_event = parse_event_to_json(record, trace_context, sealighter_context, schema);

    // Only care about event buffering if required
    if (g_buffer_lists.size() > 0 && g_buffer_lists.find(trace_name) != g_buffer_lists.end()) {
        // Lock Mutex for safety
        g_buffer_lists_mutex.lock();

        for (event_buffer_list_t& buffer : g_buffer_lists[trace_name]) {
            if (buffer.event_id != (uint32_t)schema.event_id()) {
                continue;
            }
            if (buffer.event_count < buffer.max_before_buffering) {
                // Increment counter but report event
                buffer.event_count += 1;
                break;
            }

            // We're buffering. See if we already have the matching event
            bool matched_event = false;
            for (json& json_event_buffered : buffer.json_event_buffered) {
                bool matched_field = true;
                for (std::string prop_to_compare: buffer.properties_to_compare) {
                    auto field_event = Utils::Convert::json_to_string(json_event["properties"][prop_to_compare], false);
                    auto field_buffered = Utils::Convert::json_to_string(json_event_buffered["properties"][prop_to_compare], false);
                    if (field_event != field_buffered) {
                        // Not a match
                        matched_field = false;
                        break;
                    }
                }
                if (matched_field) {
                    // Matched, increase event count
                    auto old_count = json_event_buffered["header"]["buffered_count"].get<std::uint32_t>();
                    json_event_buffered["header"]["buffered_count"] = old_count + 1;
                    matched_event = true;
                }
            }
            if (!matched_event) {
                // Event wasn't in the list, add it
                json_event["header"]["buffered_count"] = 1;
                buffer.json_event_buffered.push_back(json_event);
            }
            // As we're buffering don't report event
            buffered = true;
            break;
        }
        g_buffer_lists_mutex.unlock();
    }

    // Report event only if not buffering
    if (!buffered) {
        output_json_event(json_event);
    }
}


void handle_event
(
    const EVENT_RECORD& record,
    const trace_context& trace_context
)
{
    auto dummy_context = std::make_shared<sealighter_context_t>("", false, true);
    handle_event_context(record, trace_context, dummy_context);
}


void setup_logger_file
(
    std::string filename
)
{
    g_outfile.open(filename.c_str(), std::ios::out | std::ios::app);
    if (!g_outfile.good()) {
        throw SealighterException("Failed to open output file '%s'", filename.c_str());
    }
}


void teardown_logger_file()
{
    if (g_outfile.is_open()) {
        g_outfile.close();
    }
}


void set_output_format(Output_format format)
{
    g_output_format = format;
}


void add_buffered_list
(
    std::string trace_name,
    event_buffer_list_t buffered_list
)
{
    if (g_buffer_lists.find(trace_name) == g_buffer_lists.end()) {
        g_buffer_lists[trace_name] = std::vector<event_buffer_list_t>();
    }
    g_buffer_lists[trace_name].push_back(buffered_list);
}


void set_buffer_lists_timeout
(
    uint32_t timeout
)
{
    g_buffer_lists_timeout_seconds = timeout;
}


void flush_buffered_lists()
{
    g_buffer_lists_mutex.lock();
    for (auto& buffer_list : g_buffer_lists) {
        for (auto& buffer : buffer_list.second) {
            for (auto& json_event : buffer.json_event_buffered) {
                output_json_event(json_event);
            }
            buffer.json_event_buffered.clear();
            buffer.event_count = 0;
        }
    }
    g_buffer_lists_mutex.unlock();
}


void bufferring_thread()
{
    std::mutex thread_mutex;
    std::unique_lock<std::mutex> lock(thread_mutex);
    auto time_point = std::chrono::system_clock::now() +
        std::chrono::seconds(g_buffer_lists_timeout_seconds);
    while (!g_buffer_thread_stop) {
        while (g_buffer_list_con_var.wait_until(lock, time_point) == std::cv_status::timeout) {
            flush_buffered_lists();
            time_point = std::chrono::system_clock::now() +
                std::chrono::seconds(g_buffer_lists_timeout_seconds);
        }
    }

    // Flush one last time before ending
    flush_buffered_lists();
}


void start_bufferring()
{
    // Only start buffer thread if we need to
    if (g_buffer_lists.size() != 0 && !g_buffer_thread_stop.load()) {
        g_buffer_list_thread = std::thread(bufferring_thread);
    }
}


void stop_bufferring()
{
    if (g_buffer_lists.size() != 0 && !g_buffer_thread_stop.load()) {
        g_buffer_thread_stop = true;
        g_buffer_list_con_var.notify_one();
        g_buffer_list_thread.join();
    }
}
