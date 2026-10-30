#pragma once
// Nonvirtual exported methods omitted by the pinned upstream headers.
// Exact 24G90 definitions: 0xffffff80022dbd50 / 0xffffff80022dbd92.
// These copy into interface-owned storage; no radio operation or ownership loan.
// Keep this bridge outside upstream headers and do not modify the class layout.
extern "C" IOReturn ath10kStoreIPv4Params(IO80211InfraInterface *,const void *)
    __asm__("__ZN21IO80211InfraInterface13setIPv4ParamsEP22apple80211_ipv4_params");
extern "C" IOReturn ath10kStoreIPv6Params(IO80211InfraInterface *,const void *)
    __asm__("__ZN21IO80211InfraInterface13setIPv6ParamsEP22apple80211_ipv6_params");
// Borrowed interface-owned pointer; consume synchronously under the gate.
extern "C" const void *ath10kReadIPv4Params(IO80211InfraInterface *)
    __asm__("__ZN21IO80211InfraInterface13getIPv4ParamsEv");

// Unlike address-cache copies, this can synchronously invoke DLIL callbacks.
// Call only from WCL with the radio gate released and a live BSD binding.
extern "C" void ath10kSetFastlaneCapable(IO80211InfraInterface *,bool)
    __asm__("__ZN25IOSkywalkNetworkInterface18setFastlaneCapableEb");
