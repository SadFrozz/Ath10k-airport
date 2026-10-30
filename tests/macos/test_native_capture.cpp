#include <cassert>
#include <cstdint>
#include <cstring>
#include "../../src/macos/native/Ath10kNativeCapture.hpp"
struct Options {uint64_t pipe_type,log_data_type,pipe_size,min_log_size_notify,notify_threshold,pad9,pad10;uint8_t reserved[32];};
int main(){
 Options o;memset(&o,0x7f,sizeof(o));assert(nativeCaptureOptions(2,o));
 assert(o.pipe_type==0x200000001ULL && o.log_data_type==2 && o.pipe_size==128);
 assert(!o.min_log_size_notify && !o.notify_threshold && !o.pad9 && !o.pad10);
 for(auto b:o.reserved)assert(!b);
 for(unsigned i=0;i<2;++i){assert(nativeCaptureOptions(i,o));assert(o.min_log_size_notify<=o.pipe_size);assert(o.notify_threshold<=o.pipe_size);}
 // Switching a streaming configuration to snapshot must erase its flags.
 assert(nativeCaptureOptions(2,o));assert(!o.min_log_size_notify && !o.pad9 && !o.pad10);
 assert(!nativeCaptureOptions(3,o));
}
