#ifndef DEXMEGUVIZ_METHOD_PARAMETERS_V1_H
#define DEXMEGUVIZ_METHOD_PARAMETERS_V1_H
#include "dexmeguviz.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct dmg_method_parameters_v1 dmg_method_parameters_v1;
/* Status is about encoded DEX facts, not Java reflection/ART metadata. */
enum { DMG_PARAMETER_DEBUG_NO_DEFINITION=0, DMG_PARAMETER_DEBUG_NO_BODY=1,
       DMG_PARAMETER_DEBUG_NOT_PRESENT=2, DMG_PARAMETER_DEBUG_PRESENT=3 };
enum { DMG_PARAMETER_NAME_UNKNOWN=0, DMG_PARAMETER_NAME_NO_INDEX=1, DMG_PARAMETER_NAME_PRESENT=2 };
typedef struct {
    uint32_t struct_size,abi_version,max_parameters,max_text_units;
    uint64_t max_work,deadline_after_ms;
    uint32_t reserved;
} dmg_method_parameters_options_v1;
typedef struct {
    uint32_t source_index,method_ref,method_ordinal,debug_state,debug_offset,parameter_count;
    uint64_t work_units;
    const char* snapshot_id;
} dmg_method_parameters_info_v1;
typedef struct {const uint16_t* value;uint64_t length;} dmg_parameter_text_v1;
typedef struct {
    uint32_t ordinal,type_index,name_state,name_string_index;
    const uint16_t* type_descriptor;uint64_t type_descriptor_length;
    const uint16_t* name;uint64_t name_length;
} dmg_method_parameter_v1;
/* Same-source method reference; external refs still expose prototype types.
 * No definition/body/debug is reported explicitly, not as an empty name.
 * On failure *out is NULL. Caller retains snapshot throughout this call. */
dmg_status dmg_snapshot_get_method_parameters_v1(dmg_snapshot* snapshot,uint32_t source_index,uint32_t method_ref,
    const dmg_method_parameters_options_v1* options,dmg_method_parameters_v1** out,dmg_error* error);
void dmg_method_parameters_retain_v1(dmg_method_parameters_v1* result);
void dmg_method_parameters_release_v1(dmg_method_parameters_v1* result);
dmg_status dmg_method_parameters_get_info_v1(const dmg_method_parameters_v1*,dmg_method_parameters_info_v1*,uint32_t out_size);
dmg_status dmg_method_parameters_get_source_v1(const dmg_method_parameters_v1*,dmg_source_info*,uint32_t out_size);
dmg_status dmg_method_parameters_get_return_type_v1(const dmg_method_parameters_v1*,dmg_parameter_text_v1*,uint32_t out_size);
dmg_status dmg_method_parameters_get_parameter_v1(const dmg_method_parameters_v1*,uint32_t ordinal,dmg_method_parameter_v1*,uint32_t out_size);
#ifdef __cplusplus
}
#endif
#endif
