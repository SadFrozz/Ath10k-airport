#pragma once
// Native PMF/lifecycle fixtures do not create an SAE transport.
struct Ath10kSAERadio {
 enum class State {Idle,Progress,Accepted,Failed};
 void cancel(){}
 bool boundTo(const Ath10kSAESession *,uint32_t) const {return false;}
 State service(uint64_t){return State::Failed;}
 void receive(const uint8_t *,size_t,uint32_t,uint64_t){}
 bool prepareTX(uint16_t,uint64_t,const uint8_t *&,size_t &){return false;}
 bool completeTX(bool,uint64_t){return false;}
 template<class E> bool beginEAPOL(E &,const uint8_t *,const uint8_t *,const uint8_t *,const uint8_t *,size_t,uint64_t){return false;}
};
