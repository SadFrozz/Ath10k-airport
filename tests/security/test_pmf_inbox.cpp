#include <initializer_list>
#include <cassert>
#include <cstring>
#include "../../src/macos/native/Ath10kNativePMFInbox.hpp"
int main(){
 AthNative::PMFInbox inbox;using Layout=AthSecurity::PMFCCMPRXLayout;
 uint8_t frame[512]{};frame[0]=0xd0;frame[1]=0x40;
 assert(!inbox.peek() && !inbox.push(nullptr,26,0,1,20,Layout::Ciphertext));
 for(unsigned n=0;n<26;++n)assert(!inbox.push(frame,n,0,1,20,Layout::Ciphertext));
 assert(!inbox.push(frame,513,0,1,20,Layout::Ciphertext));
 for(unsigned status:{1u,8u,16u,32u})assert(!inbox.push(frame,26,status,1,20,Layout::Ciphertext));
 for(unsigned cycle=0;cycle<3;++cycle){
  for(unsigned i=0;i<inbox.Capacity;++i){frame[24]=i;assert(inbox.push(frame,512,0,36+i,20+i,Layout::PlaintextWithEncryptedTag));}
  assert(!inbox.push(frame,26,0,1,20,Layout::Ciphertext));memset(frame,0xa5,sizeof(frame));
  for(unsigned i=0;i<inbox.Capacity;++i){const auto *entry=inbox.peek();assert(entry && entry->length==512 && entry->bytes[24]==i && entry->channel==36+i);
   assert(entry->layout==Layout::PlaintextWithEncryptedTag);inbox.pop();}
  assert(!inbox.peek() && !inbox.size());inbox.pop();
 }
 assert(inbox.push(frame,26,0,1,20,Layout::Authenticated));assert(inbox.peek()->layout==Layout::Authenticated);inbox.clear();assert(!inbox.size() && !inbox.peek());
}
