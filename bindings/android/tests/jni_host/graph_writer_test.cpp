// Internal test-only translation unit: accesses the same bounded writer used by JNI.
#include "../../dexmeguviz-android/src/main/cpp/dexmeguviz_jni.cpp"
#include <iostream>
#include <stdexcept>
#define CHECK(x) do{if(!(x))throw std::runtime_error("check failed: " #x);}while(false)
int main(){try{
    GraphWriter full;
    for(size_t i=0;i<GraphWriter::limit/4;++i)full.u32(0);
    CHECK(full.data.size()==GraphWriter::limit);
    try{full.u32(1);CHECK(false);}catch(const GraphError& e){CHECK(e.status==DMG_BUDGET_EXCEEDED);}
    CHECK(full.data.size()==GraphWriter::limit);
    GraphWriter items;items.item(GraphWriter::item_limit);
    try{items.item(1);CHECK(false);}catch(const GraphError& e){CHECK(e.status==DMG_BUDGET_EXCEEDED);}
    std::vector<uint16_t> chars(GraphWriter::text_limit,0);GraphWriter text;
    text.text(true,chars.data(),chars.size());CHECK(text.text_units==GraphWriter::text_limit);
    try{text.text(true,chars.data(),1);CHECK(false);}catch(const GraphError& e){CHECK(e.status==DMG_BUDGET_EXCEEDED);}
    CHECK(text.text_units==GraphWriter::text_limit);
    GraphWriter malformed;const uint8_t invalid=2;dmg_binding_path path{&invalid,1};
    try{malformed.path(path);CHECK(false);}catch(const GraphError& e){CHECK(e.status==DMG_INTERNAL_ERROR);}
    std::string label(1025,'a');try{malformed.ascii(label.c_str());CHECK(false);}catch(const GraphError& e){CHECK(e.status==DMG_BUDGET_EXCEEDED);}
    std::cout<<"PASS bounded graph wire, text, item, path and identity controls\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
