#include "dexmeguviz/dexmeguviz.h"
#include <stdio.h>
#include <string.h>

int main(void){
    dmg_inherited_witness out,before;
    memset(&out,0xa5,sizeof(out));before=out;
    if(dmg_result_get_inherited_witness(NULL,0,0,&out,sizeof(out))!=DMG_INVALID_ARGUMENT||memcmp(&out,&before,sizeof(out)))return 1;
    if(DMG_WITNESS_INHERITED!=8||DMG_INHERITED_FIELD!=4||DMG_INHERITED_END_CYCLE!=3)return 2;
    puts("PASS C inherited getter: symbol, constants and untouched invalid output");return 0;
}
