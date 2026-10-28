#pragma once
#include "Ath10kSecurity.hpp"
namespace AthSecurity {
// IEEE 802.11 SHA256 KDF and RFC 4493 AES-CMAC. The provider supplies
// HMAC-SHA256 and single-block AES encryption; no keys leave the provider.
template<class Crypto> struct SHA256Personal {
 static bool derive(const uint8_t *pmk,const uint8_t *context,uint8_t *ptk){
  if(!pmk || !context || !ptk)return false;
  static constexpr char label[]="Pairwise key expansion";
  uint8_t input[2+sizeof(label)-1+76+2]{},digest[32]{};
  copy(input+2,reinterpret_cast<const uint8_t *>(label),sizeof(label)-1);
  copy(input+2+sizeof(label)-1,context,76);
  input[sizeof(input)-2]=0x80;input[sizeof(input)-1]=1; // 384 bits LE
  bool ok=true;
  for(unsigned block=1;block<=2;++block){input[0]=uint8_t(block);
   if(!Crypto::hmac256(pmk,32,input,sizeof(input),digest)){ok=false;break;}
   copy(ptk+(block-1)*32,digest,block==1?32:16);
  }
  wipe(input,sizeof(input));wipe(digest,sizeof(digest));if(!ok)wipe(ptk,48);return ok;
 }
 static void doubleBlock(uint8_t *p){
  const uint8_t carry=p[0]>>7;
  for(unsigned i=0;i<15;++i)p[i]=uint8_t((p[i]<<1)|(p[i+1]>>7));
  p[15]=uint8_t(p[15]<<1);p[15]^=uint8_t(0x87 & uint8_t(0-carry));
 }
 static bool mic(const uint8_t *key,const uint8_t *data,size_t length,uint8_t *out){
  if(!key || !out || (!data && length) || length>512)return false;
  uint8_t sub[16]{},state[16]{},block[16]{};
  bool ok=Crypto::encrypt(key,state,sub);doubleBlock(sub);
  const size_t blocks=length?(length+15)/16:1;
  for(size_t i=0;i+1<blocks && ok;++i){
   for(unsigned j=0;j<16;++j)block[j]=state[j]^data[16*i+j];
   ok=Crypto::encrypt(key,block,state);
  }
  if(ok){
   const size_t tail=length-16*(blocks-1);wipe(block,16);
   if(tail)copy(block,data+16*(blocks-1),tail);
   if(tail!=16){doubleBlock(sub);block[tail]=0x80;}
   for(unsigned j=0;j<16;++j)block[j]^=state[j]^sub[j];
   ok=Crypto::encrypt(key,block,out);
  }
  wipe(sub,16);wipe(state,16);wipe(block,16);if(!ok)wipe(out,16);return ok;
 }
};
// BIP-CMAC-128 verification for group deauthentication/disassociation only.
// Caller supplies the installed key epoch and commits acceptedIPN only while
// that epoch remains current. No state changes or key installation occur here.
template<class Crypto> inline bool verifyBIPDisconnect(const uint8_t *frame,size_t bytes,
 const uint8_t *ap,const IGTKCMAC128 &key,uint64_t lastIPN,uint64_t &acceptedIPN){
 if(!frame || !ap || bytes<44 || bytes>512 || (key.keyID!=4 && key.keyID!=5))return false;
 const uint16_t fc=rsnLE16(frame);
 if((fc&0x00ff)!=0x00c0 && (fc&0x00ff)!=0x00a0)return false;
 if((fc&0x8700) || (rsnLE16(frame+22)&15) || !(frame[4]&1) || !equal(frame+10,ap,6) || !equal(frame+16,ap,6))return false;
 const uint8_t *mmie=frame+bytes-18;
 if(mmie[0]!=76 || mmie[1]!=16 || rsnLE16(mmie+2)!=key.keyID)return false;
 uint64_t ipn=0;for(unsigned i=0;i<6;++i)ipn|=uint64_t(mmie[4+i])<<(8*i);
 if(ipn<=lastIPN)return false;
 uint8_t input[512]{},digest[16]{};
 const uint16_t masked=uint16_t(fc&~0x3800u);
 input[0]=uint8_t(masked);input[1]=uint8_t(masked>>8);
 copy(input+2,frame+4,18);copy(input+20,frame+24,bytes-24);
 wipe(input+bytes-12,8);
 const bool ok=SHA256Personal<Crypto>::mic(key.key,input,bytes-4,digest) && equal(digest,frame+bytes-8,8);
 wipe(input,sizeof(input));wipe(digest,sizeof(digest));
 if(ok)acceptedIPN=ipn;
 return ok;
}

struct SAEGroup19Keys {uint8_t kck[32]{},pmk[32]{},pmkid[16]{};};
// Group 19, SHA-256 KDF only. Caller validates/computes the group secret,
// mode-specific keyseed and fixed-width big-endian scalar sum modulo order.
// Does not implement password element derivation, H2E salt or commit/confirm.
template<class Crypto> inline bool deriveSAEGroup19Keys(const uint8_t *keyseed,size_t seedBytes,
 const uint8_t *scalarSum,size_t sumBytes,SAEGroup19Keys &out){
 if(!keyseed || seedBytes!=32 || !scalarSum || sumBytes!=32)return false;
 static constexpr char label[]="SAE KCK and PMK";
 uint8_t input[2+sizeof(label)-1+32+2]{},keys[64]{};
 copy(input+2,reinterpret_cast<const uint8_t *>(label),sizeof(label)-1);
 copy(input+2+sizeof(label)-1,scalarSum,32);
 input[sizeof(input)-1]=2; // 512 bits, little endian.
 bool ok=true;
 for(unsigned block=1;block<=2;++block){
  input[0]=uint8_t(block);
  if(!Crypto::hmac256(keyseed,32,input,sizeof(input),keys+32*(block-1))){ok=false;break;}
 }
 if(ok){copy(out.kck,keys,32);copy(out.pmk,keys+32,32);copy(out.pmkid,input+2+sizeof(label)-1,16);}
 wipe(input,sizeof(input));wipe(keys,sizeof(keys));return ok;
}

// Group-19, AKM 8 only. Rejected-group inputs are the exact, prevalidated LE16
// list payloads (without IE headers), retained from this exchange. Session/frame
// validation and authenticated key publication are separate responsibilities.
template<class Crypto> inline bool deriveSAEGroup19ExchangeKeys(const uint8_t *secret,size_t secretBytes,
 const uint8_t *scalarSum,size_t sumBytes,bool h2e,const uint8_t *localMAC,const uint8_t *peerMAC,
 const uint8_t *localRejected,size_t localBytes,const uint8_t *peerRejected,size_t peerBytes,
 SAEGroup19Keys &out){
 if(!secret || secretBytes!=32 || !scalarSum || sumBytes!=32 || !localMAC || !peerMAC ||
    (localMAC[0]&1) || (peerMAC[0]&1) || equal(localMAC,peerMAC,6) ||
    (!localRejected && localBytes) || (!peerRejected && peerBytes) ||
    localBytes>254 || peerBytes>254 || (localBytes&1) || (peerBytes&1) ||
    (!h2e && (localBytes || peerBytes)))return false;
 uint8_t localNonzero=0,peerNonzero=0;
 for(unsigned i=0;i<6;++i){localNonzero|=localMAC[i];peerNonzero|=peerMAC[i];}
 if(!localNonzero || !peerNonzero)return false;
 uint8_t salt[508]{},seed[32]{};size_t saltBytes=32;
 if(h2e && (localBytes || peerBytes)){
  bool localHigher=false;
  for(unsigned i=0;i<6;++i){if(localMAC[i]==peerMAC[i])continue;localHigher=localMAC[i]>peerMAC[i];break;}
  if(localHigher){
   if(localBytes)copy(salt,localRejected,localBytes);
   if(peerBytes)copy(salt+localBytes,peerRejected,peerBytes);
  }else{
   if(peerBytes)copy(salt,peerRejected,peerBytes);
   if(localBytes)copy(salt+peerBytes,localRejected,localBytes);
  }
  saltBytes=localBytes+peerBytes;
 }
 const bool ok=Crypto::hmac256(salt,saltBytes,secret,32,seed) &&
     deriveSAEGroup19Keys<Crypto>(seed,32,scalarSum,32,out);
 wipe(salt,sizeof(salt));wipe(seed,sizeof(seed));return ok;
}

// Sender/receiver commits are 32-byte scalar || 64-byte affine X/Y, all BE.
// Their curve/scalar validity and session binding must already be established.
template<class Crypto> inline bool saeGroup19Confirm(const uint8_t *kck,size_t keyBytes,uint16_t counter,
 const uint8_t *sender,size_t senderBytes,const uint8_t *receiver,size_t receiverBytes,
 uint8_t *out,size_t capacity){
 if(!kck || keyBytes!=32 || !sender || senderBytes!=96 || !receiver || receiverBytes!=96 || !out || capacity<32)return false;
 uint8_t message[194]{},digest[32]{};
 message[0]=uint8_t(counter);message[1]=uint8_t(counter>>8);
 copy(message+2,sender,96);copy(message+98,receiver,96);
 const bool ok=Crypto::hmac256(kck,32,message,sizeof(message),digest);
 if(ok)copy(out,digest,32);
 wipe(message,sizeof(message));wipe(digest,sizeof(digest));return ok;
}

// Group-19 confirm body only, excluding authentication header/extensions.
// Caller enforces session state, peer identity and the current key generation.
template<class Crypto> inline bool verifySAEGroup19PeerConfirm(const uint8_t *kck,size_t keyBytes,
 const uint8_t *localCommit,size_t localBytes,const uint8_t *peerCommit,size_t peerBytes,
 const uint8_t *body,size_t bytes,bool sessionAccepted,uint16_t previousCounter,uint16_t &acceptedCounter){
 if(!body || bytes!=34)return false;
 const uint16_t counter=rsnLE16(body);
 // Accepted-state replay rules are distinct from initial confirmation retries.
 if(sessionAccepted && (counter<=previousCounter || counter==0xffff))return false;
 uint8_t expected[32]{};
 const bool ok=saeGroup19Confirm<Crypto>(kck,keyBytes,counter,peerCommit,peerBytes,
     localCommit,localBytes,expected,sizeof(expected)) && equal(expected,body+2,32);
 wipe(expected,sizeof(expected));
 if(ok)acceptedCounter=counter;
 return ok;
}

// Group-19 H2E password-to-HKDF values before field reduction/SSWU.
// Bounds match native credential transport; output is u1[48] || u2[48].
template<class Crypto> inline bool saeGroup19H2EValues(const uint8_t *ssid,size_t ssidBytes,
 const uint8_t *password,size_t passwordBytes,const uint8_t *identifier,size_t identifierBytes,
 uint8_t *out,size_t capacity){
 if((!ssid && ssidBytes) || ssidBytes>32 || !password || !passwordBytes || passwordBytes>64 ||
    (!identifier && identifierBytes) || identifierBytes>254 || !out || capacity<96)return false;
 uint8_t material[318]{},seed[32]{},values[96]{},message[64]{},digest[32]{},zero=0;
 copy(material,password,passwordBytes);if(identifierBytes)copy(material+passwordBytes,identifier,identifierBytes);
 bool ok=Crypto::hmac256(ssid?ssid:&zero,ssidBytes,material,passwordBytes+identifierBytes,seed);
 static constexpr char labels[2][sizeof("SAE Hash to Element u1 P1")]={"SAE Hash to Element u1 P1","SAE Hash to Element u2 P2"};
 for(unsigned part=0;part<2 && ok;++part){
  const size_t labelBytes=sizeof(labels[0])-1;
  for(unsigned block=1;block<=2 && ok;++block){
   size_t at=0;if(block==2){copy(message,digest,32);at=32;}
   copy(message+at,reinterpret_cast<const uint8_t *>(labels[part]),labelBytes);message[at+labelBytes]=uint8_t(block);
   ok=Crypto::hmac256(seed,32,message,at+labelBytes+1,digest);
   if(ok)copy(values+48*part+32*(block-1),digest,block==1?32:16);
  }
 }
 if(ok)copy(out,values,96);
 wipe(material,sizeof(material));wipe(seed,sizeof(seed));wipe(values,sizeof(values));
 wipe(message,sizeof(message));wipe(digest,sizeof(digest));return ok;
}

}
