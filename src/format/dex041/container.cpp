#include "container.hpp"
#include "format/reader.hpp"
#include <limits>
namespace dexmeguviz::dex041 {
std::pmr::vector<Header> enumerate(std::span<const uint8_t> bytes,std::pmr::memory_resource* memory,uint32_t maximum){
    if(!memory||!maximum||maximum>1024)throw std::invalid_argument("invalid 041 header limit");
    if(bytes.size()>UINT32_MAX)throw ReadError(ReadCode::budget,0,"041 container exceeds uint32 extent");
    auto fail=[](uint64_t at,const char* message)->void{throw ReadError(ReadCode::corrupt,at,message);};
    auto word=[&](uint64_t at){if(at>bytes.size()||4>bytes.size()-at)fail(at,"truncated 041 word");return uint32_t(bytes[at])|(uint32_t(bytes[at+1])<<8)|(uint32_t(bytes[at+2])<<16)|(uint32_t(bytes[at+3])<<24);};
    std::pmr::vector<Header> result(memory);uint64_t at=0;
    do{
        if(result.size()==maximum)throw ReadError(ReadCode::budget,at,"041 logical header limit");
        if(at%4||at>bytes.size()||120>bytes.size()-at)fail(at,"truncated or unaligned 041 header");
        constexpr uint8_t magic[]{'d','e','x','\n','0','4','1',0};
        for(size_t i=0;i<8;++i)if(bytes[at+i]!=magic[i])throw ReadError(ReadCode::unsupported,at,"explicit 041 container requires 041 logical headers");
        const auto size=word(at+32);if(word(at+36)!=120||word(at+40)!=0x12345678)fail(at+36,"041 header size/endian mismatch");
        if(word(at+112)!=bytes.size()||word(at+116)!=at)fail(at+112,"041 container/header offset mismatch");
        if(size<120||size>bytes.size()-at)fail(at+32,"041 logical extent outside container");
        result.push_back({static_cast<uint32_t>(at),size,static_cast<uint32_t>(bytes.size())});at+=size;
    }while(at<bytes.size());
    return result;
}
}
