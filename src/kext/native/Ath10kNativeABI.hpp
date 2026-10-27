#pragma once
#define __PRIVATE_SPI__ 1
#include <sys/types.h>
typedef u_int32_t ifnet_ctl_cmd_t;
#include <libkern/libkern.h>
#include <IOKit/IOTypes.h>
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
#define AIRPORT_WCL 1
#define IO80211FAMILY_V2 1
#include <Airport/Apple80211.h>
#include <Airport/macOS15/FaultReporter.h>
#include <IOKit/IOCommandGate.h>
#include <WCL.hpp>
