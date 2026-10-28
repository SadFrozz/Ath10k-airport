#pragma once
#include "../../shared/Ath10kPMFTransport.hpp"
namespace AthNative {
// Radio-owner-only bounded copies; WMI DMA storage is reused after parsing.
class PMFInbox {
public:
 struct Frame {uint8_t bytes[512]{};size_t length=0;uint32_t status=0,channel=0,snr=0;AthSecurity::PMFCCMPRXLayout layout=AthSecurity::PMFCCMPRXLayout::Ciphertext;};
 static constexpr unsigned Capacity=4;
private:
 Frame frames[Capacity]{};unsigned read=0,count=0;
public:
 ~PMFInbox(){clear();}
 void clear(){AthSecurity::wipe(frames,sizeof(frames));read=count=0;}
 bool push(const uint8_t *bytes,size_t length,uint32_t status,uint32_t channel,uint32_t snr,AthSecurity::PMFCCMPRXLayout layout){
  if(!bytes || length<26 || length>512 || (status&0x39u) || count==Capacity ||
     (layout!=AthSecurity::PMFCCMPRXLayout::Ciphertext && layout!=AthSecurity::PMFCCMPRXLayout::PlaintextWithEncryptedTag))return false;
  auto &frame=frames[(read+count)%Capacity];AthSecurity::copy(frame.bytes,bytes,length);
  frame.length=length;frame.status=status;frame.channel=channel;frame.snr=snr;frame.layout=layout;++count;return true;
 }
 const Frame *peek() const {return count?&frames[read]:nullptr;}
 void pop(){if(!count)return;AthSecurity::wipe(&frames[read],sizeof(frames[read]));read=(read+1)%Capacity;--count;}
 unsigned size() const {return count;}
};
}
