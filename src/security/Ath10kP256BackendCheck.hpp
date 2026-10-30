#pragma once
#include "Ath10kP256CoreCrypto.hpp"
namespace AthSecurity {
struct P256BackendCheckReport {
 enum class Step : uint8_t { None,FieldMultiply,FieldAdd,FieldSubtract,FieldInverse,
  FieldSquareRoot,FieldNonSquare,PointValidate,PointReject,PointMultiply,PointAdd,PointSubtract,Passed };
 Step step=Step::None;uint32_t passed=0;bool complete=false;
};
struct P256BackendCheckWorkspace {
 P256CoreCryptoWorkspace point{};P256FieldWorkspace field{};
 uint8_t out[80]{},temporary[32]{},scalar[32]{};
 void clear(){wipe(this,sizeof(*this));}
};
// Public known-answer checks only. Caller owns the workspace on a worker;
// neither construction nor report collection may call this under an owner gate.
// Passing checks is evidence for the supplied provider, never native admission.
inline bool checkP256Backend(const P256CoreCryptoAPI &pointAPI,const P256FieldAPI &fieldAPI,
 P256BackendCheckWorkspace &w,P256BackendCheckReport &report){
 using Step=P256BackendCheckReport::Step;report={};w.clear();
 struct Cleanup {P256BackendCheckWorkspace &w;~Cleanup(){w.clear();}} cleanup{w};
 P256CoreCryptoCandidate points(pointAPI);P256FieldCandidate field(fieldAPI);
 static constexpr uint8_t one[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
 static constexpr uint8_t two[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2};
 static constexpr uint8_t four[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4};
 static constexpr uint8_t zero[64]{};
 static constexpr uint8_t minusOne[32]={0xff,0xff,0xff,0xff,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe};
 static constexpr uint8_t nonSquare[32]={0xff,0xff,0xff,0xff,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xf5};
 static constexpr uint8_t generator[64]={0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5};
 static constexpr uint8_t doubled[64]={0x7c,0xf2,0x7b,0x18,0x8d,0x03,0x4f,0x7e,0x8a,0x52,0x38,0x03,0x04,0xb5,0x1a,0xc3,0xc0,0x89,0x69,0xe2,0x77,0xf2,0x1b,0x35,0xa6,0x0b,0x48,0xfc,0x47,0x66,0x99,0x78,0x07,0x77,0x55,0x10,0xdb,0x8e,0xd0,0x40,0x29,0x3d,0x9a,0xc6,0x9f,0x74,0x30,0xdb,0xba,0x7d,0xad,0xe6,0x3c,0xe9,0x82,0x29,0x9e,0x04,0xb7,0x9d,0x22,0x78,0x73,0xd1};
 auto begin=[&](Step step){report.step=step;for(auto &v:w.out)v=0xa5;};
 auto guard=[&](size_t size){uint8_t mismatch=0;for(size_t i=size;i<sizeof(w.out);++i)mismatch|=uint8_t(w.out[i]^0xa5);return mismatch==0;};
 auto passed=[&](){report.passed|=uint32_t(1)<<(unsigned(report.step)-1);};
 begin(Step::FieldMultiply);
 if(!field.multiply(two,32,two,32,w.out,80,w.field) || !equal(w.out,four,32) || !guard(32))return false;passed();
 begin(Step::FieldAdd);
 if(!field.add(one,one,32,w.out,80,w.field) || !equal(w.out,two,32) || !guard(32))return false;passed();
 begin(Step::FieldSubtract);
 if(!field.subtract(one,two,32,w.out,80,w.field) || !equal(w.out,minusOne,32) || !guard(32))return false;passed();
 begin(Step::FieldInverse);
 if(!field.inverse(two,32,w.temporary,32,w.field) || !field.multiply(two,32,w.temporary,32,w.out,80,w.field) || !equal(w.out,one,32) || !guard(32))return false;passed();
 begin(Step::FieldSquareRoot);
 if(!field.squareRoot(four,32,w.temporary,32,w.field) || !field.multiply(w.temporary,32,w.temporary,32,w.out,80,w.field) || !equal(w.out,four,32) || !guard(32))return false;passed();
 begin(Step::FieldNonSquare);
 if(field.squareRootStatus(nonSquare,32,w.out,80,w.field)!=P256FieldResult::NotSquare || !guard(0))return false;passed();
 begin(Step::PointValidate);
 if(!points.validate(generator,64,w.point))return false;passed();
 begin(Step::PointReject);
 if(points.validate(zero,64,w.point))return false;passed();
 begin(Step::PointMultiply);copy(w.scalar,two,32);
 if(!points.multiply(w.scalar,32,generator,64,w.out,80,w.point) || !equal(w.out,doubled,64) || !guard(64))return false;passed();
 begin(Step::PointAdd);
 if(!points.add(generator,64,generator,64,w.out,80,w.point) || !equal(w.out,doubled,64) || !guard(64))return false;passed();
 begin(Step::PointSubtract);
 if(!points.subtract(doubled,64,generator,64,w.out,80,w.point) || !equal(w.out,generator,64) || !guard(64))return false;passed();
 report.step=Step::Passed;report.complete=true;return true;
}
}
