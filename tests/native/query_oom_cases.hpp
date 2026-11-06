#pragma once
struct Case {const char* name;const char* input;const char* id;};
inline constexpr Case cases[]={
 {"v1",R"({"schema_version":1,"relation":"method_defs","where":{"return_type":"I","parameters":[],"using_strings":{"all":[{"op":"exact","value":"quality settings:"}]}},"intent":"unique","max_results":2,"evidence_profile":"minimal"})","query:v1:283ae5fd16c5c58a2c7690abdb0b7cfb3a8edf7644c63cf5b43956967d8e4a63"},
 {"v2",R"({"schema_version":1,"relation":"field_defs"})","query:v2:6d119cc5d61d304582f915944e04db2a8b482aad25d7a694f6024907308a185a"},
 {"v3",R"({"schema_version":1,"relation":{"op":"scan","relation":"method_defs"}})","query:v3:d3b9d916113de0403046db0ee9b5b4247591d5ccc2904e17809eadace97eff23"},
 {"v4",R"({"schema_version":1,"relation":{"op":"scan","relation":"invoke_sites"}})","query:v4:c026266fb392c395224c2d8659d259303e4e112a62ee7d18a12dd725ae4ad90f"}
};
