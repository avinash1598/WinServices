#include <windows.h> //NOTE: Important to include windows.h before fwpmu.h
#include <fwpmu.h>
#include "WFPFilter.h"
#define INITGUID
#include <guiddef.h>

HANDLE FilterEngineHandle = NULL;
DWORD WFP_RESULT = ERROR_SUCCESS;
UINT64 FilterId = 0;

//35fe9c81-3516-40af-b4ba-95a7a8f1f914
DEFINE_GUID
(
    WFP_SAMPLE_SUBLAYER_GUID,
    0x35fe9c81,
    0x3516,
    0x40af,
    0xb4, 0xba, 0x95, 0xa7, 0xa8, 0xf1, 0xf9, 0x14
);

//96ebd471-62ea-4b06-8c3e-33ab71b6c6d7
DEFINE_GUID
(
    STREAM_VIEW_STREAM_CALLOUT_V4,
    0x96ebd471,
    0x62ea,
    0x4b06,
    0x8c, 0x3e, 0x33, 0xab, 0x71, 0xb6, 0xc6, 0xd7
);


void UnInitializeWfp()
{
    if (FilterEngineHandle != NULL) {

        if (FilterId != NULL) 
            FwpmFilterDeleteById(FilterEngineHandle, FilterId);

        FwpmSubLayerDeleteByKey(FilterEngineHandle, &WFP_SAMPLE_SUBLAYER_GUID);

        FwpmEngineClose(FilterEngineHandle);
    }
}

DWORD
WfpAddSublayer()
{
    FWPM_SUBLAYER mSubLayer = { 0 };

    mSubLayer.flags = 0;
    mSubLayer.displayData.name = L"RanjanUserNetworkFilterWfpSubLayer";
    mSubLayer.displayData.description = L"RanjanUserNetworkFilterWfpSubLayer";
    mSubLayer.subLayerKey = WFP_SAMPLE_SUBLAYER_GUID;
    mSubLayer.weight = 65500;

    return FwpmSubLayerAdd(FilterEngineHandle, &mSubLayer, NULL);
}

DWORD
WfpAddFilter()
{
    FWPM_FILTER mFilter = { 0 };
    FWPM_FILTER_CONDITION filterConditions[1] = { 0 };

    mFilter.displayData.name = L"RanjanUserNetworkFilterWfpFilter";
    mFilter.displayData.description = L"RanjanUserNetworkFilterWfpFilter";
    
    // For user mode application
    //mFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    //mFilter.action.type = FWP_ACTION_BLOCK;

    //For callout
    mFilter.layerKey = FWPM_LAYER_STREAM_V4;
    mFilter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    mFilter.action.calloutKey = STREAM_VIEW_STREAM_CALLOUT_V4;

    mFilter.subLayerKey = WFP_SAMPLE_SUBLAYER_GUID;
    mFilter.weight.type = FWP_EMPTY; // auto-weight.
    mFilter.numFilterConditions = 1;
    mFilter.filterCondition = filterConditions;
    
    filterConditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    filterConditions[0].matchType = FWP_MATCH_EQUAL;
    filterConditions[0].conditionValue.type = FWP_UINT16;
    filterConditions[0].conditionValue.uint16 = 443;

    return FwpmFilterAdd(FilterEngineHandle, &mFilter, NULL, &FilterId);
}

DWORD InitializeWfp() 
{
    // Open a session to the filter engine
    WFP_RESULT = FwpmEngineOpen(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        NULL,
        &FilterEngineHandle);

    if (WFP_RESULT != ERROR_SUCCESS)
        goto Exit;
    
    // Add sublayer for isolated filtering
    WFP_RESULT = WfpAddSublayer();

    if (WFP_RESULT != ERROR_SUCCESS)
        goto Exit;

    // Add fiter conditions to sublayer
    WFP_RESULT = WfpAddFilter();

    if (WFP_RESULT != ERROR_SUCCESS)
        goto Exit;

Exit:
    if (WFP_RESULT != ERROR_SUCCESS)
        UnInitializeWfp();

    return WFP_RESULT;
}

