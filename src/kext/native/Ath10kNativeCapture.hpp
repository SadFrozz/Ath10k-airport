#pragma once
// CoreCapture uses distinct schemas for streaming logs and state snapshots.
// Snapshot pipe size is a record limit; streaming watermarks/options do not
// apply to it. Keep this policy shared with the host regression.
template<class Options> bool nativeCaptureOptions(unsigned role,Options &out) {
    if(role>2)return false;
    out={};
    if(role==2){out.pipe_type=0x200000001ULL;out.log_data_type=2;out.pipe_size=128;return true;}
    out.pipe_type=0;out.log_data_type=role==0?1:0;out.pipe_size=0x200000;
    out.min_log_size_notify=0xccccc;out.notify_threshold=1000;
    out.pad9=role==0?0x1000000:2;out.pad10=role==0?2:0x2800000;
    return true;
}
