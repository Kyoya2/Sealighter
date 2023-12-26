#include "krabs.hpp"
#include <iostream>
#include <fstream>
#include <thread>
#include "sealighter_util.h"
#include "sealighter_json.h"
#include "sealighter_predicates.h"
#include "sealighter_handler.h"
#include "sealighter_provider.h"
#include "sealighter_exception.h"

using namespace krabs;

// -------------------------
// GLOBALS - START
// -------------------------

// Add aliases to make code cleaner
namespace kpc = krabs::predicates::comparers;
namespace kpa = krabs::predicates::adapters;


// Holds a KrabsETW User Session Trace if needed
static user_trace* g_user_session = NULL;

// Holds a KrabsETW Kernel Session Trace if needed
static kernel_trace* g_kernel_session = NULL;

// -------------------------
// GLOBALS - END
// -------------------------
// PRIVATE FUNCTIONS - START
// -------------------------

/*
    Adds a single property comparer filter to a list
*/
template <
    typename ComparerA,
    typename ComparerW
>
void add_filter_to_vector_property_compare_item
(
    const json& item,
    std::vector<std::shared_ptr<predicates::details::predicate_base>>& list
)
{
    const std::wstring name = Utils::Convert::str_to_wstr(item.at("name").get<std::string>());
    const std::string value = item.at("value").get<std::string>();
    const std::string type  = item.at("type").get<std::string>();

    if (type == "STRINGA") {
        auto pred = std::make_shared<
            predicates::details::property_view_predicate<
            std::string,
            kpa::generic_string<char>,
            ComparerA
            >
        >(
            name,
            value,
            kpa::generic_string<char>(),
            ComparerA()
        );
        list.emplace_back(pred);
    }
    else if (type == "STRINGW") {
        auto pred = std::make_shared<
            predicates::details::property_view_predicate<
                std::wstring,
                kpa::generic_string<wchar_t>,
                ComparerW
            >
        >(
            name,
            Utils::Convert::str_to_wstr(value),
            kpa::generic_string<wchar_t>(),
            ComparerW()
        );
        list.emplace_back(pred);
    }
    else {
        // Raise a parse error, type has to be a string
        throw SealighterException("The 'type' of a Property Comparer must be 'STRINGA' or 'STRINGW'");
    }
}


/*
    Adds a property comparer filter to a list
*/
template <
    typename ComparerA,
    typename ComparerW
>
void add_filter_to_vector_property_compare
(
    const json& root,
    std::string element,
    std::vector<std::shared_ptr<predicates::details::predicate_base>>& pred_vector
)
{
    std::vector<std::shared_ptr<predicates::details::predicate_base>> list;
    const auto element_json = root.find(element);

    if (element_json == root.end())
        return;

    Utils::log_message("        %s: %s\n", element.c_str(), Utils::Convert::json_to_string(*element_json, false).c_str());
    if (element_json->is_array()) {
        for (const json item : *element_json) {
            add_filter_to_vector_property_compare_item<ComparerA, ComparerW>(item, list);
        }
        if (!list.empty()) {
            pred_vector.emplace_back(std::make_shared<sealighter_any_of>(list));
        }
    }
    else {
        add_filter_to_vector_property_compare_item<ComparerA, ComparerW>(*element_json, pred_vector);
    }
}


/*
    Add a single "property is" filter to a list.
*/
void add_filter_to_vector_property_is_item
(
    const json& item,
    std::vector<std::shared_ptr<predicates::details::predicate_base>>& list
)
{
    const std::wstring name = Utils::Convert::str_to_wstr(item.at("name").get<std::string>());
    const std::string type = item.at("type").get<std::string>();
    const json value_json = item.at("value");

    if (type == "STRINGA") {
        auto val = value_json.get<std::string>();
        list.emplace_back(std::make_shared<sealighter_property_is<std::string>>(name, val));
    }
    else if (type == "STRINGW") {
        auto val = Utils::Convert::str_to_wstr(value_json.get<std::string>());
        list.emplace_back(std::make_shared<sealighter_property_is<std::wstring>>(name, val));
    }
    else if (type == "INT8") {
        auto val = value_json.get<std::int8_t>();
        list.emplace_back(std::make_shared<sealighter_property_is<std::int8_t>>(name, val));
    }
    else if (type == "UINT8") {
        auto val = value_json.get<std::uint8_t>();
        list.emplace_back(std::make_shared<sealighter_property_is<std::uint8_t>>(name, val));
    }
    else if (type == "INT16") {
        auto val = value_json.get<std::int16_t>();
        list.emplace_back(std::make_shared<sealighter_property_is<std::int16_t>>(name, val));
    }
    else if (type == "UINT16") {
        auto val = value_json.get<std::uint16_t>();
        list.emplace_back(std::make_shared<sealighter_property_is<std::uint16_t>>(name, val));
    }
    else if (type == "INT32") {
        auto val = value_json.get<std::int32_t>();
        list.emplace_back(std::make_shared<sealighter_property_is<std::int32_t>>(name, val));
    }
    else if (type == "UINT32") {
        auto val = value_json.get<std::uint32_t>();
        list.emplace_back(std::make_shared<sealighter_property_is<std::uint32_t>>(name, val));
    }
    else if (type == "INT64") {
        auto val = value_json.get<std::int64_t>();
        list.emplace_back(std::make_shared<sealighter_property_is<std::int64_t>>(name, val));
    }
    else if (type == "UINT64") {
        auto val = value_json.get<std::uint64_t>();
        list.emplace_back(std::make_shared<sealighter_property_is<std::uint64_t>>(name, val));
    }
}


/*
    Add the "Property Is" filter to a list,
    if availible. This is a different type of predicate
    to both the basic predicates and the other property comparer ones
*/
void add_filter_to_vector_property_is
(
    const json& root,
    std::vector<std::shared_ptr<predicates::details::predicate_base>>& pred_vector
)
{
    std::vector<std::shared_ptr<predicates::details::predicate_base>> list;

    if (!root.is_null()) {
        Utils::log_message("        Property Is: %s\n", Utils::Convert::json_to_string(root, false).c_str());
        if (root.is_array()) {
            for (const json item : root) {
                add_filter_to_vector_property_is_item(item, list);
            }
            if (!list.empty()) {
                pred_vector.emplace_back(std::make_shared<sealighter_any_of>(list));
            }
        }
        else {
            add_filter_to_vector_property_is_item(root, pred_vector);
        }
    }
};


/*
    Adds a basic filter with two values
*/
template <
    typename TPred,
    typename TJson1 = std::uint64_t,
    typename TJson2 = std::uint64_t
>
void add_filter_to_vector_basic_pair
(
    const json& root,
    std::string element,
    std::string item1_name,
    std::string item2_name,
    std::vector<std::shared_ptr<predicates::details::predicate_base>>& pred_vector
)
{
    std::vector<std::shared_ptr<predicates::details::predicate_base>> list;
    const auto element_json = root.find(element);

    if (element_json == root.end())
        return;

    Utils::log_message("        %s: %s\n", element.c_str(), Utils::Convert::json_to_string(*element_json, false).c_str());
    if (element_json->is_array()) {
        for (const json item : *element_json)
        {
            list.emplace_back(std::make_shared<TPred>(
                item.at(item1_name).get<TJson1>(),
                item.at(item2_name).get<TJson2>()
            ));
        }
        if (!list.empty()) {
            pred_vector.emplace_back(std::make_shared<sealighter_any_of>(list));
        }
    }
    else
    {
        pred_vector.emplace_back(std::make_shared<TPred>(
            element_json->at(item1_name).get<TJson1>(),
            element_json->at(item2_name).get<TJson2>()
        ));
    }
}


/*
    Parse JSON to create a KrabsETW filter and add it to a list
    JSON can be a single item, or an array of items that we will 'OR'
*/
template <
    typename TPred,
    typename TJson1 = std::uint64_t
>
void add_filter_to_vector_basic
(
    const json& root,
    std::string element,
    std::vector<std::shared_ptr<predicates::details::predicate_base>>& pred_vector
)
{
    std::vector<std::shared_ptr<predicates::details::predicate_base>> list;
    const auto element_json = root.find(element);

    if (element_json == root.end())
        return;

    Utils::log_message("        %s: %s\n", element.c_str(), Utils::Convert::json_to_string(*element_json, false).c_str());
    // If a list, filter can be any of them
    if (element_json->is_array()) {
        for (const json item : *element_json) {
            list.emplace_back(std::make_shared<TPred>(item.get<TJson1>()));
        }
        if (!list.empty()) {
            pred_vector.emplace_back(std::make_shared<sealighter_any_of>(list));
        }
    }
    else {
        pred_vector.emplace_back(std::make_shared<TPred>(element_json->get<TJson1>()));
    }
}


/*
    Parse JSON to add filters to a vector list
*/
void add_filters_to_vector
(
    std::vector<std::shared_ptr<predicates::details::predicate_base>>& pred_vector,
    const json& json_list
)
{
    // Add the basic single-value filters
    add_filter_to_vector_basic<predicates::id_is>
        (json_list, "event_id_is", pred_vector);
    add_filter_to_vector_basic<predicates::opcode_is>
        (json_list, "opcode_is", pred_vector);
    add_filter_to_vector_basic<predicates::process_id_is>
        (json_list, "process_id_is", pred_vector);
    add_filter_to_vector_basic<predicates::version_is>
        (json_list, "version_is", pred_vector);
    
    // Add all the property filters
    add_filter_to_vector_property_is(json_list["property_is"], pred_vector);
    
    add_filter_to_vector_property_compare<
        kpc::equals<std::equal_to<kpa::generic_string<char>::value_type>>,
        kpc::equals<std::equal_to<kpa::generic_string<wchar_t>::value_type>>
    >(json_list, "property_equals", pred_vector);
    
    add_filter_to_vector_property_compare<
        kpc::equals<iequal_to<kpa::generic_string<char>::value_type>>,
        kpc::equals<iequal_to<kpa::generic_string<wchar_t>::value_type>>
    >(json_list, "property_iequals", pred_vector);
    
    add_filter_to_vector_property_compare<
        kpc::contains<std::equal_to<kpa::generic_string<char>::value_type>>,
        kpc::contains<std::equal_to<kpa::generic_string<wchar_t>::value_type>>
    >(json_list, "property_contains", pred_vector);
    
    add_filter_to_vector_property_compare<
        kpc::contains<iequal_to<kpa::generic_string<char>::value_type>>,
        kpc::contains<iequal_to<kpa::generic_string<wchar_t>::value_type>>
    >(json_list, "property_icontains", pred_vector);
    
    add_filter_to_vector_property_compare<
        kpc::starts_with<std::equal_to<kpa::generic_string<char>::value_type>>,
        kpc::starts_with<std::equal_to<kpa::generic_string<wchar_t>::value_type>>
    >(json_list, "property_starts_with", pred_vector);
    
    add_filter_to_vector_property_compare<
        kpc::starts_with<iequal_to<kpa::generic_string<char>::value_type>>,
        kpc::starts_with<iequal_to<kpa::generic_string<wchar_t>::value_type>>
    >(json_list, "property_istarts_with", pred_vector);
    
    add_filter_to_vector_property_compare<
        kpc::ends_with<std::equal_to<kpa::generic_string<char>::value_type>>,
        kpc::ends_with<std::equal_to<kpa::generic_string<wchar_t>::value_type>>
    >(json_list, "property_ends_with", pred_vector);
    
    add_filter_to_vector_property_compare<
        kpc::ends_with<iequal_to<kpa::generic_string<char>::value_type>>,
        kpc::ends_with<iequal_to<kpa::generic_string<wchar_t>::value_type>>
    >(json_list, "property_iends_with", pred_vector);
    
    // Add own own created Predicates
    add_filter_to_vector_basic<sealighter_max_events_total, std::uint64_t>
        (json_list, "max_events_total", pred_vector);
    add_filter_to_vector_basic_pair<sealighter_max_events_id>
        (json_list, "max_events_id", "id_is", "max_events", pred_vector);
    add_filter_to_vector_basic<sealighter_any_field_contains, std::string>
        (json_list, "any_field_contains", pred_vector);
    add_filter_to_vector_basic<sealighter_process_name_contains, std::string>
        (json_list, "process_name_contains", pred_vector);
    add_filter_to_vector_basic<sealighter_activity_id_is, std::string>
        (json_list, "activity_id_is", pred_vector);
}


/*
    Add Krabs filters to an ETW provider
*/
template <typename T>
void add_filters
(
    details::base_provider<T>* pNew_provider,
    std::shared_ptr<sealighter_context_t> sealighter_context,
    const json& json_provider
)
{
    const auto filters_json = json_provider.find("filters");
    if (filters_json == json_provider.end())
    {
        // No filters, log everything
        Utils::log_message("    No event filters\n");
        pNew_provider->add_on_event_callback([sealighter_context](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
            handle_event_context(record, trace_context, sealighter_context);
            });
    }
    else
    {
        // Build top-level list
        // All 3 options will eventually be ANDed together
        const auto any_of_json = filters_json->find("any_of");
        const auto all_of_json = filters_json->find("all_of");
        const auto none_of_json = filters_json->find("none_of");

        std::vector<std::shared_ptr<predicates::details::predicate_base>> top_list;
        if (any_of_json != filters_json->end())
        {
            Utils::log_message("    Filtering any of:\n");
            std::vector<std::shared_ptr<predicates::details::predicate_base>> list;
            add_filters_to_vector(list, *any_of_json);
            top_list.emplace_back(std::make_shared<sealighter_any_of>(list));
        }

        if (all_of_json != filters_json->end())
        {
            Utils::log_message("    Filtering all of:\n");
            std::vector<std::shared_ptr<predicates::details::predicate_base>> list;
            add_filters_to_vector(list, *all_of_json);
            top_list.emplace_back(std::make_shared<sealighter_all_of>(list));
        }

        if (none_of_json != filters_json->end())
        {
            Utils::log_message("    Filtering none of:\n");
            std::vector<std::shared_ptr<predicates::details::predicate_base>> list;
            add_filters_to_vector(list, *none_of_json);
            top_list.emplace_back(std::make_shared<sealighter_none_of>(list));
        }

        // Add top level list to a filter
        sealighter_all_of top_pred(top_list);
        event_filter filter(top_pred);

        filter.add_on_event_callback([sealighter_context](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
            handle_event_context(record, trace_context, sealighter_context);
            });
        pNew_provider->add_filter(filter);
    }
}


/*
    Add Kernel Providers and Create Kernel ETW Session
*/
void add_kernel_traces
(
    const json& kernel_traces_config,
    EVENT_TRACE_PROPERTIES  session_properties,
    bool record_property_types_default
)
{
    kernel_provider* pNew_provider;
    std::string provider_name;

    // Initialize Session and props
    g_kernel_session = new kernel_trace();
    g_kernel_session->set_trace_properties(&session_properties);

    // Add any Kernel providers
    for (const auto json_provider : kernel_traces_config)
    {
        std::string trace_name;

        provider_name = json_provider.at("provider_name").get<std::string>();

        if (provider_name == "process") {
            pNew_provider = new kernel::process_provider();
        }
        else if (provider_name == "thread") {
            pNew_provider = new kernel::thread_provider();
        }
        else if (provider_name == "image_load") {
            pNew_provider = new kernel::image_load_provider();
        }
        else if (provider_name == "process_counter") {
            pNew_provider = new kernel::process_counter_provider();
        }
        else if (provider_name == "context_switch") {
            pNew_provider = new kernel::context_switch_provider();
        }
        else if (provider_name == "dpc") {
            pNew_provider = new kernel::dpc_provider();
        }
        else if (provider_name == "debug_print") {
            pNew_provider = new kernel::debug_print_provider();
        }
        else if (provider_name == "interrupt") {
            pNew_provider = new kernel::interrupt_provider();
        }
        else if (provider_name == "system_call") {
            pNew_provider = new kernel::system_call_provider();
        }
        else if (provider_name == "disk_io") {
            pNew_provider = new kernel::disk_io_provider();
        }
        else if (provider_name == "disk_file_io") {
            pNew_provider = new kernel::disk_file_io_provider();
        }
        else if (provider_name == "disk_init_io") {
            pNew_provider = new kernel::disk_init_io_provider();
        }
        else if (provider_name == "thread_dispatch") {
            pNew_provider = new kernel::thread_dispatch_provider();
        }
        else if (provider_name == "memory_page_fault") {
            pNew_provider = new kernel::memory_page_fault_provider();
        }
        else if (provider_name == "memory_hard_fault") {
            pNew_provider = new kernel::memory_hard_fault_provider();
        }
        else if (provider_name == "virtual_alloc") {
            pNew_provider = new kernel::virtual_alloc_provider();
        }
        else if (provider_name == "network_tcpip") {
            pNew_provider = new kernel::network_tcpip_provider();
        }
        else if (provider_name == "registry") {
            pNew_provider = new kernel::registry_provider();
        }
        else if (provider_name == "alpc") {
            pNew_provider = new kernel::alpc_provider();
        }
        else if (provider_name == "split_io") {
            pNew_provider = new kernel::split_io_provider();
        }
        else if (provider_name == "driver") {
            pNew_provider = new kernel::driver_provider();
        }
        else if (provider_name == "profile") {
            pNew_provider = new kernel::profile_provider();
        }
        else if (provider_name == "file_io") {
            pNew_provider = new kernel::file_io_provider();
        }
        else if (provider_name == "file_init_io") {
            pNew_provider = new kernel::file_init_io_provider();
        }
        else if (provider_name == "vamap") {
            pNew_provider = new kernel::vamap_provider();
        }
        else if (provider_name == "object_manager") {
            pNew_provider = new kernel::object_manager_provider();
        }
        else if (provider_name == "timer") {
            pNew_provider = new kernel::timer_provider();
        }
        else {
            throw SealighterException("Invalid kernel provider '%s'", provider_name.c_str());
        }

        // If the current trace configuration has a "record_property_types" attribute, use it.
        // Otherwise, use the global attribute.
        bool record_property_types = json_provider.value("record_property_types", record_property_types_default);

        // Create context with trace name
        trace_name = json_provider.at("trace_name").get<std::string>();

        auto sealighter_context = std::make_shared<sealighter_context_t>(trace_name, false, record_property_types);

        if (const auto buffers_json = json_provider.find("buffers");
            buffers_json != json_provider.end())
        {
            // TODO: move the content of this if statement to a new function that will receive `*buffers_json`
            // also update in user traces
            for (const json json_buffers : *buffers_json)
            {
                auto event_id = json_buffers.at("event_id").get<std::uint32_t>();
                auto max = json_buffers.at("max_before_buffering").get<std::uint32_t>();
                auto buffer_list = event_buffer_list_t(event_id, max);
                for (const json json_buff_prop : json_buffers.at("properties_to_match"))
                {
                    buffer_list.properties_to_compare.push_back(json_buff_prop.get<std::string>());
                }

                add_buffered_list(trace_name, buffer_list);
            }
        }
        
        // Add any filters
        Utils::log_message("Kernel Provider: %s\n", provider_name.c_str());
        add_filters(pNew_provider, sealighter_context, json_provider);
        g_kernel_session->enable(*pNew_provider);
    }
}


/*
    Add User providers and create User ETW Session
*/
void add_user_traces
(
    const json& user_traces_config,
    EVENT_TRACE_PROPERTIES session_properties,
    std::wstring session_name,
    bool record_property_types_default
)
{
    // Initialize Session and props
    g_user_session = new user_trace(session_name);
    g_user_session->set_trace_properties(&session_properties);

    // Parse the Usermode Providers
    for (const json json_provider : user_traces_config) {
        GUID provider_guid;
        provider<>* pNew_provider;
        std::wstring provider_name;
        std::string trace_name;

        provider_name = Utils::Convert::str_to_wstr(json_provider.at("provider_name").get<std::string>());
        trace_name = json_provider.at("trace_name").get<std::string>();

        // If provider_name is a GUID, use that
            // Otherwise pass it off to Krabs to try to resolve
        provider_guid = Utils::Convert::wstr_to_guid(provider_name);
        if (provider_guid != GUID_NULL)
        {
            // TODO: use smart pointers
            pNew_provider = new provider<>(provider_guid);
        }
        else
        {
            pNew_provider = new provider<>(provider_name);
        }
        Utils::log_message("User Provider: %S\n", provider_name.c_str());
        Utils::log_message("    Trace Name: %s\n", trace_name.c_str());

        // If no keywords_all or keywords_any is set
            // then set a default 'match anything'
        if (const auto keywords_all_json = json_provider.find("keywords_all"),
                       keywords_any_json = json_provider.find("keywords_any");

            keywords_all_json == json_provider.end() && keywords_any_json == json_provider.end())
        {
            Utils::log_message("    Keywords: All\n");
        }
        else
        {
            if (keywords_all_json != json_provider.end())
            {
                uint64_t data = keywords_all_json->get<std::uint64_t>();
                Utils::log_message("    Keywords All: 0x%llx\n", data);
                pNew_provider->all(data);
            }

            if (keywords_any_json != json_provider.end())
            {
                uint64_t data = keywords_any_json->get<std::uint64_t>();
                Utils::log_message("    Keywords Any: 0x%llx\n", data);
                pNew_provider->any(data);
            }
        }

        // If no level is specified, set the max level
        pNew_provider->level(json_provider.value("level", 0xff));

        // TODO: support each trace flag individually instead of having
            // a "trace_flags" property that doesn't actually show
            // the addditional info in the result. For more info, see:
            // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
        if (const auto trace_flags_json = json_provider.find("trace_flags");
            trace_flags_json != json_provider.end())
        {
            uint64_t data = trace_flags_json->get<std::uint64_t>();
            Utils::log_message("    Trace Flags: 0x%llx\n", data);
            pNew_provider->trace_flags(data);
        }

        // Check if we want a stacktrace
        // This is just a helper option, you could also set this in the trace_flags
        if (const auto report_stacktrace_json = json_provider.find("report_stacktrace");
            report_stacktrace_json != json_provider.end() && report_stacktrace_json->get<bool>())
        {
            // Add the stacktrace trace flag
            pNew_provider->trace_flags(pNew_provider->trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
        }

        // Check if we're dumping the raw event, or attempting to parse it
        // TODO: unite this and "record_property_types" into an enum
        // called ParsingMode or something.
        bool dump_raw_event = json_provider.value("dump_raw_event", false);
        if (dump_raw_event)
        {
            Utils::log_message("    Recording raw events\n");
        }

        // If the current trace configuration has a "record_property_types" attribute, use it.
        // Otherwise, use the global attribute.
        bool record_property_types = json_provider.value("record_property_types", record_property_types_default);
        if (dump_raw_event && record_property_types)
        {
            throw SealighterException("record_property_types' option is incompatible with 'dump_raw_event' in the same trace");
        }

        // Create context with trace name
        auto sealighter_context = std::make_shared<sealighter_context_t>(trace_name, dump_raw_event, record_property_types);

        if (const auto buffers_json = json_provider.find("buffers");
            buffers_json != json_provider.end())
        {
            for (const json json_buffers : *buffers_json)
            {
                auto event_id = json_buffers.at("event_id").get<std::uint32_t>();
                auto max = json_buffers.at("max_before_buffering").get<std::uint32_t>();
                event_buffer_list_t buffer_list(event_id, max);
                for (const json json_buff_prop : json_buffers.at("properties_to_match"))
                {
                    buffer_list.properties_to_compare.push_back(json_buff_prop.get<std::string>());
                }

                add_buffered_list(trace_name, buffer_list);
            }
        }

        // Add any filters
        add_filters(pNew_provider, sealighter_context, json_provider);
        g_user_session->enable(*pNew_provider);
    }

    g_user_session->set_default_event_callback(handle_event);
}


/*
    Stop any running trace
*/
void stop_sealighter()
{
    if (NULL != g_user_session) {
        g_user_session->stop();
    }
    if (NULL != g_kernel_session) {
        g_kernel_session->stop();
    }
}


void event_listener(HANDLE stop_event)
{
    // Wait until the event is signaled and stop the program
    DWORD wait_result = ::WaitForSingleObject(stop_event, INFINITE);

    if (WAIT_OBJECT_0 == wait_result)
        stop_sealighter();
    else
        Utils::log_message("Failed waiting for event, wait_result: %ul, error: %ul\n", wait_result, ::GetLastError());

    ::CloseHandle(stop_event);
}


void start_event_listener_thread(const std::string& stop_event_name)
{
    HANDLE stop_event = ::CreateEventA(NULL, TRUE, FALSE, stop_event_name.c_str());
    if (stop_event == NULL)
    {
        throw SealighterException("Failed creating event \"%S\", error: %ul\n", stop_event_name.c_str(), ::GetLastError());
    }

    // Let the thread run in the background
    std::thread(event_listener, stop_event).detach();
}


/*
    Parse the Config file, setup
    ETW Session and Krabs filters
*/
void parse_config
(
    std::string config_string
)
{
    EVENT_TRACE_PROPERTIES session_properties = { 0 };
    
    bool record_property_types = true;
    const json json_config = json::parse(config_string);

    // Set defaults
    session_properties.BufferSize = 256;
    session_properties.MinimumBuffers = 12;
    session_properties.MaximumBuffers = 48;
    session_properties.FlushTimer = 1;
    session_properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_INDEPENDENT_SESSION_MODE;

    // Parse the config json for any custom properties
    const json json_props = json_config.at("session_properties");

    std::wstring session_name = Utils::Convert::str_to_wstr(json_props.value("session_name", "Sealighter-Trace"));
    Utils::log_message("Session Name: %S\n", session_name.c_str());

    session_properties.BufferSize     = json_props.value("buffer_size",     256);
    session_properties.MinimumBuffers = json_props.value("minimum_buffers", 12);
    session_properties.MaximumBuffers = json_props.value("maximum_buffers", 48);
    session_properties.FlushTimer     = json_props.value("flush_timer",     1);

    // Parse output format
    std::string format = json_props.at("output_format").get<std::string>();
    if ("stdout" == format)
    {
        set_output_format(Output_format::output_stdout);
    }
    else if ("event_log" == format)
    {
        set_output_format(Output_format::output_event_log);
    }
    else if ("file" == format)
    {
        set_output_format(Output_format::output_file);
        setup_logger_file(json_props.at("output_filename").get<std::string>());
    }
    else
    {
        throw std::exception("Invalid output_format");
    }
    Utils::log_message("Outputs: %s\n", format.c_str());

    set_buffer_lists_timeout(json_props.value("buffering_timout_seconds", 5));

    if (const auto stop_event_json = json_props.find("stop_event");
        stop_event_json != json_props.end())
    {
        auto trace_stop_event_name = stop_event_json->get<std::string>();
        start_event_listener_thread(trace_stop_event_name);
    }

    record_property_types = json_props.value("record_property_types", record_property_types);

    if (const auto user_traces_json = json_config.find("user_traces"),
                   kernel_traces_json = json_config.find("kernel_traces");

        user_traces_json == json_config.end() && kernel_traces_json == json_config.end())
    {
        throw SealighterException("No User or Kernel providers in config file");
    }
    else
    {
        if (user_traces_json != json_config.end())
            add_user_traces(*user_traces_json, session_properties, session_name, record_property_types);

        // Add kernel providers if needed
        if (kernel_traces_json != json_config.end())
            add_kernel_traces(*kernel_traces_json, session_properties, record_property_types);
    }
}


/*
    Run a trace, and ensure we stop if something goes wrong
*/
template <typename T>
void run_trace(trace<T>* trace)
{
    if (NULL != trace){
        // Ensure we always stop the trace afterwards
        try {
            trace->start();
        }
        catch (const std::exception& e) {
            Utils::log_message("%s\n", e.what());
            trace->stop();
            throw;
        }
        catch (...) {
            trace->stop();
            throw;
        }
    }
}

/*
    Handler for Ctrl+C cancel events.
    Makes sure we stop our ETW Session when shutting down
*/
BOOL WINAPI crl_c_handler
(
    DWORD fdwCtrlType
)
{
    switch (fdwCtrlType)
    {
    case CTRL_C_EVENT:
        stop_sealighter();
        return TRUE;
    }
    return FALSE;
}


// -------------------------
// PRIVATE FUNCTIONS - END
// -------------------------
// PUBLIC FUNCTIONS - START
// -------------------------
void run_sealighter
(
    std::string config_string
)
{
    // Setup Event Logging
    // TODO: use this only if the configuration specifies logging to event log
    if (int status = EventRegisterSealighter();
        ERROR_SUCCESS != status)
    {
        throw SealighterException("Error registering event log: %ul\n", status);
    }

    // Add ctrl+C handler to make sure we stop the trace
    if (!SetConsoleCtrlHandler(crl_c_handler, TRUE))
    {
        throw SealighterException("failed to set ctrl-c handler\n");
    }

    // Parse config file
    parse_config(config_string);

    // Setup Buffering thread if needed
    start_bufferring();

    // Start Trace we've configured
    // Don't run multithreaded if we don't have to
    if (NULL != g_user_session && NULL == g_kernel_session) {
        Utils::log_message("Starting User Trace...\n");
        Utils::log_message("-----------------------------------------\n");
        run_trace(g_user_session);
    }
    else if (NULL == g_user_session && NULL != g_kernel_session) {
        Utils::log_message("Starting Kernel Trace...\n");
        Utils::log_message("-----------------------------------------\n");
        run_trace(g_kernel_session);
    }
    else {
        // Have to multi-thread it
        Utils::log_message("Starting User and Kernel Traces...\n");
        Utils::log_message("-----------------------------------------\n");
        std::thread user_thread = std::thread(run_trace<details::ut>, g_user_session);
        std::thread kernel_thread = std::thread(run_trace<details::kt>, g_kernel_session);

        // Call join, blocking until both have shut down
        user_thread.join();
        kernel_thread.join();
    }

    // Teardown and cleanup
    stop_bufferring();
    teardown_logger_file();
    (void)EventUnregisterSealighter();
}
