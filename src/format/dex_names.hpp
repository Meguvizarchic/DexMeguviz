#pragma once
#include <cstdint>
#include <cstddef>
#include <string_view>
namespace dexmeguviz::dex_names {
inline bool simple_name(std::u16string_view value,uint32_t version) noexcept {
    if(value.empty())return false;
    for(std::size_t i=0;i<value.size();++i){const auto c=uint16_t(value[i]);
        if((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='$'||c=='-'||c=='_')continue;
        if((c>=0x00a1&&c<=0x1fff)||(c>=0x2010&&c<=0x2027)||(c>=0x2030&&c<=0xd7ff)||(c>=0xe000&&c<=0xffef))continue;
        if(version>=40&&(c==0x20||c==0xa0||(c>=0x2000&&c<=0x200a)||c==0x202f))continue;
        if(c>=0xd800&&c<=0xdbff&&i+1<value.size()&&value[i+1]>=0xdc00&&value[i+1]<=0xdfff){++i;continue;}
        return false;
    }return true;
}
inline bool member_name(std::u16string_view value,uint32_t version) noexcept {
    if(value.size()>=3&&value.front()==u'<'&&value.back()==u'>')return simple_name(value.substr(1,value.size()-2),version);
    return simple_name(value,version);
}
inline bool descriptor(std::u16string_view value,uint32_t version) noexcept {
    std::size_t arrays=0;while(arrays<value.size()&&value[arrays]==u'[')++arrays;
    if(arrays>255||arrays==value.size())return false;value.remove_prefix(arrays);
    if(value.size()==1)return value[0]==u'V'?arrays==0:std::u16string_view(u"ZBSCIJFD").find(value[0])!=std::u16string_view::npos;
    if(value.front()!=u'L'||value.back()!=u';')return false;value.remove_prefix(1);value.remove_suffix(1);
    while(true){const auto slash=value.find(u'/');if(!simple_name(value.substr(0,slash),version))return false;if(slash==std::u16string_view::npos)return true;value.remove_prefix(slash+1);}
}
inline bool class_descriptor(std::u16string_view value,uint32_t version) noexcept {
    return !value.empty()&&value.front()==u'L'&&descriptor(value,version);
}
}
