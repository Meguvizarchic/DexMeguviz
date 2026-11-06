#pragma once
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>

namespace dexmeguviz {
// Scalar SHA-1 for the DEX header comparison only; this is not authentication.
inline std::array<uint8_t,20> sha1(std::span<const uint8_t> input) noexcept {
    std::array<uint32_t,5> h{0x67452301u,0xefcdab89u,0x98badcfeu,0x10325476u,0xc3d2e1f0u};
    auto block=[&](const uint8_t* p){
        std::array<uint32_t,80> w{};
        for(size_t i=0;i<16;++i)w[i]=(uint32_t(p[4*i])<<24)|(uint32_t(p[4*i+1])<<16)|(uint32_t(p[4*i+2])<<8)|uint32_t(p[4*i+3]);
        for(size_t i=16;i<80;++i)w[i]=std::rotl(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
        auto a=h[0],b=h[1],c=h[2],d=h[3],e=h[4];
        for(size_t i=0;i<80;++i){
            uint32_t f,k;
            if(i<20){f=(b&c)|((~b)&d);k=0x5a827999u;}
            else if(i<40){f=b^c^d;k=0x6ed9eba1u;}
            else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8f1bbcdcu;}
            else{f=b^c^d;k=0xca62c1d6u;}
            const auto next=std::rotl(a,5)+f+e+k+w[i];e=d;d=c;c=std::rotl(b,30);b=a;a=next;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;
    };
    size_t at=0;while(input.size()-at>=64){block(input.data()+at);at+=64;}
    std::array<uint8_t,128> tail{};const auto remaining=input.size()-at;
    for(size_t i=0;i<remaining;++i)tail[i]=input[at+i];
    tail[remaining]=0x80;const size_t padded=remaining<56?64:128;
    const uint64_t bits=static_cast<uint64_t>(input.size())*8;
    for(size_t i=0;i<8;++i)tail[padded-1-i]=static_cast<uint8_t>(bits>>(8*i));
    block(tail.data());if(padded==128)block(tail.data()+64);
    std::array<uint8_t,20> out{};
    for(size_t i=0;i<h.size();++i)for(size_t j=0;j<4;++j)out[4*i+j]=static_cast<uint8_t>(h[i]>>(24-8*j));
    return out;
}
}
