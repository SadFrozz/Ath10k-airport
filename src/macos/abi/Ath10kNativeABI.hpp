#pragma once
#define __PRIVATE_SPI__ 1
#include <sys/types.h>
typedef u_int32_t ifnet_ctl_cmd_t;
#include <libkern/libkern.h>
#include <IOKit/IOTypes.h>
#include "Ath10kNativeTarget.hpp"
#define AIRPORT_WCL 1
#define IO80211FAMILY_V2 1
#include <Airport/Apple80211.h>
#include <Airport/macOS15/FaultReporter.h>
#include <IOKit/IOCommandGate.h>
#include <WCL.hpp>
