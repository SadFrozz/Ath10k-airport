#pragma once
// Opt-in expensive bring-up diagnostics; errors keep using IOLog.
#ifndef ATH10K_DIAGNOSTICS
#define ATH10K_DIAGNOSTICS 0
#endif
#if ATH10K_DIAGNOSTICS
#define ATH10K_TRACE(...) IOLog(__VA_ARGS__)
#else
#define ATH10K_TRACE(...) do { if (false) IOLog(__VA_ARGS__); } while (0)
#endif
