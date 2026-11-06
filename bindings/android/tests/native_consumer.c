#include "dexmeguviz/dexmeguviz.h"

int main(void) {
    dmg_engine* engine = 0;
    dmg_error error = {0};
    if (dmg_abi_version() != DMG_ABI_VERSION) return 1;
    if (dmg_engine_create(0, &engine, &error) != DMG_OK || !engine) return 2;
    dmg_engine_release(engine);
    return 0;
}
