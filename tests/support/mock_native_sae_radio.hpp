#pragma once
// Native PMF/lifecycle fixtures do not create an SAE transport.
struct Ath10kSAERadio {
 enum class State {Idle,Progress,Accepted,Failed};
 void cancel(){}
 template<class Queue> bool bind(Ath10kSAESession *,Queue *,uint32_t,uint64_t){return false;}
 bool boundTo(const Ath10kSAESession *,uint32_t) const {return false;}
 State service(uint64_t){return State::Failed;}
 void receive(const uint8_t *,size_t,uint32_t,uint64_t){}
 bool prepareTX(uint16_t,uint64_t,const uint8_t *&,size_t &){return false;}
 bool completeTX(bool,uint64_t){return false;}
 template<class E> bool beginEAPOL(E &,const uint8_t *,const uint8_t *,const uint8_t *,const uint8_t *,size_t,uint64_t){return false;}
};

struct Ath10kNativeSAEPreparation {
 enum class State {Pending,Ready,Failed};
 struct Result {State state;Ath10kSAESession *session=nullptr;};
 void cancel(){}bool active() const{return false;}
 template<class AP> Result collect(const uint8_t *,size_t,const AP &,const uint8_t *,uint32_t,uint64_t){return {State::Failed};}
};
