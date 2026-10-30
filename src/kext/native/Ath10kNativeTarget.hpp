#pragma once
// Select the wire ABI before any WCL structure is declared.
#define __MAC_12_0 120000
#define __MAC_13_0 130000
#define __MAC_14_0 140000
#define __MAC_14_4 140400
#define __MAC_15_2 150200
#define __MAC_26_0 260000
#ifndef __IO80211_TARGET
#define __IO80211_TARGET __MAC_15_2
#endif
#if __IO80211_TARGET != __MAC_15_2
#error "This adapter implements the Sequoia ABI only; use a separately validated Tahoe adapter."
#endif
