// Executes only in an ordinary user process. Does not load or call a kernel module.
#include "../../src/shared/Ath10kP256CoreCrypto.hpp"
#include "../../tests/p256_corecrypto_fixtures.hpp"
#include <dlfcn.h>
#include <CommonCrypto/CommonHMAC.h>
#include <mach-o/loader.h>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
using API=AthSecurity::P256CoreCryptoAPI;
using Engine=AthSecurity::P256CoreCryptoCandidate;
using Workspace=AthSecurity::P256CoreCryptoWorkspace;
static API real;
static unsigned calls=0,failAt=0;
static bool fail(){return ++calls==failAt;}
static const void *curve(){return fail()?nullptr:real.curve();}
static int importPoint(const void *c,size_t n,const uint8_t *p,void *k){return fail()?-1:real.importPoint(c,n,p,k);}
static bool validatePoint(void *p){return !fail() && real.validatePoint(p);}
static int exportPoint(int full,void *out,const void *p){return fail()?-1:real.exportPoint(full,out,p);}
static int project(const void *c,void *r,const void *p,void *rng){return fail()?-1:real.project(c,r,p,rng);}
static int affine(const void *c,void *r,const void *p){return fail()?-1:real.affine(c,r,p);}
static int multiply(const void *c,void *r,const uint64_t *d,const void *p,void *rng){return fail()?-1:real.multiply(c,r,d,p,rng);}
static int add(const void *c,void *r,const void *a,const void *b){return fail()?-1:real.add(c,r,a,b);}
static int subtract(const void *c,void *r,const void *a,const void *b){return fail()?-1:real.subtract(c,r,a,b);}
static int readScalar(size_t n,uint64_t *r,size_t len,const void *p){return fail()?-1:real.readScalar(n,r,len,p);}
static void *rng(int *error){if(fail()){*error=-1;return nullptr;}return real.rng(error);}
template<class T> static T symbol(void *lib,const char *name){auto p=dlsym(lib,name);assert(p);return reinterpret_cast<T>(p);}
template<size_t N> static std::array<uint8_t,N> decode(const char *text){
    assert(strlen(text)==2*N);std::array<uint8_t,N> result{};
    for(size_t i=0;i<N;++i){unsigned b=0;assert(sscanf(text+2*i,"%2x",&b)==1);result[i]=static_cast<uint8_t>(b);}return result;
}
static void clean(const Workspace &w){auto p=reinterpret_cast<const uint8_t *>(&w);for(size_t i=0;i<sizeof(w);++i)assert(p[i]==0);}
static void unchanged(const std::array<uint8_t,80> &out){for(auto b:out)assert(b==0xa5);}
static std::string uuid(){
    Dl_info info{};assert(dladdr(reinterpret_cast<const void *>(real.curve),&info));
    auto h=static_cast<const mach_header_64 *>(info.dli_fbase);assert(h->magic==MH_MAGIC_64 && h->sizeofcmds<65536 && h->ncmds<1024);
    auto p=reinterpret_cast<const uint8_t *>(h+1);size_t used=0;
    for(unsigned i=0;i<h->ncmds;++i){auto c=reinterpret_cast<const load_command *>(p+used);assert(c->cmdsize>=8 && used+c->cmdsize<=h->sizeofcmds);
        if(c->cmd==LC_UUID){assert(c->cmdsize==sizeof(uuid_command));auto u=reinterpret_cast<const uuid_command *>(c);char text[37];
            snprintf(text,sizeof(text),"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",u->uuid[0],u->uuid[1],u->uuid[2],u->uuid[3],u->uuid[4],u->uuid[5],u->uuid[6],u->uuid[7],u->uuid[8],u->uuid[9],u->uuid[10],u->uuid[11],u->uuid[12],u->uuid[13],u->uuid[14],u->uuid[15]);return text;}
        used+=c->cmdsize;
    }assert(false);return {};
}
static decltype(AthSecurity::P256FieldAPI::multiply) actualFieldMultiply;
static decltype(AthSecurity::P256FieldAPI::inverse) actualFieldInverse;
static int fieldMultiply(const void *c,uint64_t *r,const uint64_t *a,const uint64_t *b){return fail()?-1:actualFieldMultiply(c,r,a,b);}
static int fieldInverse(const void *c,uint64_t *r,const uint64_t *a){return fail()?-1:actualFieldInverse(c,r,a);}
struct H2ETestCrypto {
 static bool hmac256(const uint8_t *k,size_t kl,const uint8_t *p,size_t n,uint8_t *out){
  if(fail()){memset(out,0x77,32);return false;}CCHmac(kCCHmacAlgSHA256,k,kl,p,n,out);return true;
 }
};
int main(){
#if !defined(__x86_64__)
    fprintf(stderr,"This context experiment is restricted to x86_64\n");return 2;
#endif
    void *lib=dlopen("/usr/lib/system/libcorecrypto.dylib",RTLD_NOW|RTLD_LOCAL);assert(lib);
#define LOAD(field,name) real.field=symbol<decltype(real.field)>(lib,name)
    LOAD(curve,"ccec_cp_256");LOAD(importPoint,"ccec_x963_import_pub");LOAD(validatePoint,"ccec_validate_pub");LOAD(exportPoint,"ccec_x963_export");
    LOAD(project,"ccec_projectify");LOAD(affine,"ccec_affinify");LOAD(multiply,"ccec_mult_blinded");LOAD(add,"ccec_full_add");
    LOAD(subtract,"ccec_full_sub");LOAD(readScalar,"ccn_read_uint");LOAD(rng,"ccrng");
#undef LOAD
    API tracked={curve,importPoint,validatePoint,exportPoint,project,affine,multiply,add,subtract,readScalar,rng};
    Engine engine(tracked);Workspace w;std::array<uint8_t,80> out{};unsigned faultChecks=0;
    const auto g=decode<64>(P256Fixtures::generator);assert(engine.validate(g.data(),64,w));clean(w);
    for(auto &v:P256Fixtures::multiply){auto s=decode<32>(v.scalar);auto p=decode<64>(v.point),expected=decode<64>(v.result);out.fill(0xa5);
        assert(engine.multiply(s.data(),32,p.data(),64,out.data(),out.size(),w));assert(!memcmp(out.data(),expected.data(),64));
        for(size_t i=64;i<out.size();++i)assert(out[i]==0xa5);clean(w);
    }
    for(auto &v:P256Fixtures::combine){auto a=decode<64>(v.a),b=decode<64>(v.b),sum=decode<64>(v.sum),difference=decode<64>(v.difference);
        assert(engine.add(a.data(),64,b.data(),64,out.data(),out.size(),w));assert(!memcmp(out.data(),sum.data(),64));clean(w);
        assert(engine.subtract(a.data(),64,b.data(),64,out.data(),out.size(),w));assert(!memcmp(out.data(),difference.data(),64));clean(w);
    }
    const auto scalar=decode<32>(P256Fixtures::multiply[3].scalar);const auto point=decode<64>(P256Fixtures::multiply[3].point);
    for(unsigned op=0;op<4;++op){
        auto run=[&](){if(op==0)return engine.validate(g.data(),64,w);if(op==1)return engine.multiply(scalar.data(),32,point.data(),64,out.data(),out.size(),w);
            if(op==2)return engine.add(g.data(),64,point.data(),64,out.data(),out.size(),w);return engine.subtract(g.data(),64,point.data(),64,out.data(),out.size(),w);};
        calls=failAt=0;assert(run());const unsigned total=calls;
        for(unsigned n=1;n<=total;++n){calls=0;failAt=n;out.fill(0xa5);memset(&w,0x7d,sizeof(w));assert(!run());unchanged(out);clean(w);++faultChecks;}
        failAt=0;
    }
    for(auto text:{P256Fixtures::order,P256Fixtures::aboveOrder,"0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}){
        auto s=decode<32>(text);out.fill(0xa5);assert(!engine.multiply(s.data(),32,g.data(),64,out.data(),out.size(),w));unchanged(out);clean(w);
    }
    auto zero=g;zero.fill(0);auto wrong=g;wrong[0]^=0x80;auto range=g;auto prime=decode<32>(P256Fixtures::prime);memcpy(range.data(),prime.data(),32);
    for(auto p:{zero,wrong,range}){out.fill(0xa5);assert(!engine.validate(p.data(),64,w));clean(w);assert(!engine.multiply(scalar.data(),32,p.data(),64,out.data(),out.size(),w));unchanged(out);clean(w);}
    auto doubled=decode<64>(P256Fixtures::multiply[1].result);
    assert(engine.add(g.data(),64,g.data(),64,out.data(),out.size(),w));assert(!memcmp(out.data(),doubled.data(),64));clean(w);
    auto negative=decode<64>(P256Fixtures::negativeGenerator);out.fill(0xa5);
    assert(!engine.add(g.data(),64,negative.data(),64,out.data(),out.size(),w));unchanged(out);clean(w);
    assert(!engine.subtract(g.data(),64,g.data(),64,out.data(),out.size(),w));unchanged(out);clean(w);
    out.fill(0xa5);assert(!engine.multiply(scalar.data(),31,g.data(),64,out.data(),out.size(),w));unchanged(out);clean(w);
    assert(!engine.multiply(scalar.data(),32,g.data(),63,out.data(),out.size(),w));unchanged(out);clean(w);
    assert(!engine.multiply(scalar.data(),32,g.data(),64,out.data(),63,w));unchanged(out);clean(w);
    assert(!engine.validate(nullptr,64,w));clean(w);
    API missing=tracked;missing.multiply=nullptr;Engine incomplete(missing);assert(!incomplete.validate(g.data(),64,w));clean(w);
    // Output may alias the caller's point; publication happens only after success.
    auto alias=point;auto expected=decode<64>(P256Fixtures::multiply[3].result);
    assert(engine.multiply(scalar.data(),32,alias.data(),64,alias.data(),64,w) && alias==expected);clean(w);
    { // Independent OpenSSL/cryptography: 7 * (3*G + 2*G) = 35*G.
      auto peerScalar=decode<32>("0000000000000000000000000000000000000000000000000000000000000003");
      auto ownRandom=decode<32>("0000000000000000000000000000000000000000000000000000000000000007");
      auto peerPoint=decode<64>(P256Fixtures::multiply[1].result);
      const auto expected=decode<32>("d58d4a589ed27d168ffa3ad7326c48ca94e8e1fe92af9700a12d389033bb291a");
      auto run=[&](){return AthSecurity::saeGroup19SharedSecret(engine,ownRandom.data(),32,peerScalar.data(),32,g.data(),64,peerPoint.data(),64,out.data(),out.size(),w);};
      calls=failAt=0;out.fill(0xa5);assert(run());assert(!memcmp(out.data(),expected.data(),32));clean(w);
      for(size_t i=32;i<out.size();++i)assert(out[i]==0xa5);
      const unsigned total=calls;
      for(unsigned n=1;n<=total;++n){calls=0;failAt=n;out.fill(0xa5);assert(!run());unchanged(out);clean(w);}
      failAt=0;
      peerPoint=decode<64>("5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c78cb9bf2b6670082c8b4f931e59b5d1327d54fcac7b047c265864ed85d82afcd");out.fill(0xa5);
      assert(!run());unchanged(out);clean(w); // 3*G + (-3*G) is infinity.
      peerPoint=decode<64>(P256Fixtures::multiply[1].result);
      for(auto text:{P256Fixtures::order,P256Fixtures::aboveOrder}){
        peerScalar=decode<32>(text);out.fill(0xa5);assert(!run());unchanged(out);clean(w);
      }
      peerScalar.fill(0);peerScalar[31]=3;ownRandom.fill(0);out.fill(0xa5);
      assert(!run());unchanged(out);clean(w);
      ownRandom[31]=7;peerScalar.fill(0);out.fill(0xa5);
      assert(!run());unchanged(out);clean(w);
      failAt=0;peerScalar.fill(0);peerScalar[31]=1;out.fill(0xa5);
      assert(!run());unchanged(out);clean(w);
    }
    { auto a=decode<32>("0000000000000000000000000000000000000000000000000000000000000002"),b=decode<32>("0000000000000000000000000000000000000000000000000000000000000003");out.fill(0xa5);
      assert(AthSecurity::saeGroup19CommitScalar(a.data(),b.data(),32,out.data(),out.size())==true);
      const auto expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000005");assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);
    }
    { auto a=decode<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"),b=decode<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550");out.fill(0xa5);
      assert(AthSecurity::saeGroup19CommitScalar(a.data(),b.data(),32,out.data(),out.size())==true);
      const auto expected=decode<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f");assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);
    }
    { auto a=decode<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f"),b=decode<32>("0000000000000000000000000000000000000000000000000000000000000003");out.fill(0xa5);
      assert(AthSecurity::saeGroup19CommitScalar(a.data(),b.data(),32,out.data(),out.size())==false);
      unchanged(out);
    }
    { auto a=decode<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f"),b=decode<32>("0000000000000000000000000000000000000000000000000000000000000002");out.fill(0xa5);
      assert(AthSecurity::saeGroup19CommitScalar(a.data(),b.data(),32,out.data(),out.size())==false);
      unchanged(out);
    }
    { auto a=decode<32>("0000000000000000000000000000000000000000000000000000000000000002"),b=decode<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550");out.fill(0xa5);
      assert(AthSecurity::saeGroup19CommitScalar(a.data(),b.data(),32,out.data(),out.size())==false);
      unchanged(out);
    }
    { auto a=decode<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"),b=decode<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f");out.fill(0xa5);
      assert(AthSecurity::saeGroup19CommitScalar(a.data(),b.data(),32,out.data(),out.size())==true);
      const auto expected=decode<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e");assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);
    }
    { auto a=decode<32>("8000000000000000000000000000000000000000000000000000000000000000"),b=decode<32>("8000000000000000000000000000000000000000000000000000000000000000");out.fill(0xa5);
      assert(AthSecurity::saeGroup19CommitScalar(a.data(),b.data(),32,out.data(),out.size())==true);
      const auto expected=decode<32>("00000000ffffffff00000000000000004319055258e8617b0c46353d039cdaaf");assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);
    }
    { auto a=decode<32>("0000000000000000000000000000000000000000000000000000000000000001"),b=decode<32>("0000000000000000000000000000000000000000000000000000000000000005");out.fill(0xa5);
      assert(AthSecurity::saeGroup19CommitScalar(a.data(),b.data(),32,out.data(),out.size())==false);
      unchanged(out);
    }
    { auto a=decode<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),b=decode<32>("0000000000000000000000000000000000000000000000000000000000000005");out.fill(0xa5);
      assert(AthSecurity::saeGroup19CommitScalar(a.data(),b.data(),32,out.data(),out.size())==false);
      unchanged(out);
    }
    { auto ownRandom=decode<32>("0000000000000000000000000000000000000000000000000000000000000007"),mask=decode<32>("0000000000000000000000000000000000000000000000000000000000000003");
      auto peerRandom=decode<32>("000000000000000000000000000000000000000000000000000000000000000b"),peerMask=decode<32>("0000000000000000000000000000000000000000000000000000000000000005");
      std::array<uint8_t,96> own{},peer{};std::array<uint8_t,32> x{},y{};
      auto run=[&](){return AthSecurity::saeGroup19Commit(engine,ownRandom.data(),mask.data(),32,g.data(),64,own.data(),96,w);};
      calls=failAt=0;assert(run());clean(w);const unsigned total=calls;
      assert(own[31]==10);const auto negative=decode<64>("5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c78cb9bf2b6670082c8b4f931e59b5d1327d54fcac7b047c265864ed85d82afcd");assert(!memcmp(own.data()+32,negative.data(),64));
      for(unsigned n=1;n<=total;++n){calls=0;failAt=n;own.fill(0xa5);assert(!run());for(auto c:own)assert(c==0xa5);clean(w);}
      failAt=0;assert(run());
      assert(AthSecurity::saeGroup19Commit(engine,peerRandom.data(),peerMask.data(),32,g.data(),64,peer.data(),96,w));
      assert(AthSecurity::saeGroup19SharedSecret(engine,ownRandom.data(),32,peer.data(),32,g.data(),64,peer.data()+32,64,x.data(),32,w));
      assert(AthSecurity::saeGroup19SharedSecret(engine,peerRandom.data(),32,own.data(),32,g.data(),64,own.data()+32,64,y.data(),32,w));
      const auto expected=decode<32>("5821b002dba277251a9d18eb72d5c720f4efe021b38029c017d871340893be7b");assert(x==y && x==expected);clean(w);
    }
    { const auto input=decode<48>("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");const auto expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000000");out.fill(0xa5);
      assert(AthSecurity::saeGroup19ReduceH2EValue(input.data(),48,out.data(),out.size()));assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);
      out.fill(0xa5);assert(!AthSecurity::saeGroup19ReduceH2EValue(input.data(),47,out.data(),out.size()));unchanged(out);
    }
    { const auto input=decode<48>("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001");const auto expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000001");out.fill(0xa5);
      assert(AthSecurity::saeGroup19ReduceH2EValue(input.data(),48,out.data(),out.size()));assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);
      out.fill(0xa5);assert(!AthSecurity::saeGroup19ReduceH2EValue(input.data(),47,out.data(),out.size()));unchanged(out);
    }
    { const auto input=decode<48>("00000000000000000000000000000000ffffffff00000001000000000000000000000000fffffffffffffffffffffffe");const auto expected=decode<32>("ffffffff00000001000000000000000000000000fffffffffffffffffffffffe");out.fill(0xa5);
      assert(AthSecurity::saeGroup19ReduceH2EValue(input.data(),48,out.data(),out.size()));assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);
      out.fill(0xa5);assert(!AthSecurity::saeGroup19ReduceH2EValue(input.data(),47,out.data(),out.size()));unchanged(out);
    }
    { const auto input=decode<48>("00000000000000000000000000000000ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");const auto expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000000");out.fill(0xa5);
      assert(AthSecurity::saeGroup19ReduceH2EValue(input.data(),48,out.data(),out.size()));assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);
      out.fill(0xa5);assert(!AthSecurity::saeGroup19ReduceH2EValue(input.data(),47,out.data(),out.size()));unchanged(out);
    }
    { const auto input=decode<48>("00000000000000000000000000000000ffffffff00000001000000000000000000000001000000000000000000000000");const auto expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000001");out.fill(0xa5);
      assert(AthSecurity::saeGroup19ReduceH2EValue(input.data(),48,out.data(),out.size()));assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);
      out.fill(0xa5);assert(!AthSecurity::saeGroup19ReduceH2EValue(input.data(),47,out.data(),out.size()));unchanged(out);
    }
    { const auto input=decode<48>("00000000000000000000000000000001fffffffe00000002000000000000000000000001fffffffffffffffffffffffe");const auto expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000000");out.fill(0xa5);
      assert(AthSecurity::saeGroup19ReduceH2EValue(input.data(),48,out.data(),out.size()));assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);
      out.fill(0xa5);assert(!AthSecurity::saeGroup19ReduceH2EValue(input.data(),47,out.data(),out.size()));unchanged(out);
    }
    { const auto input=decode<48>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");const auto expected=decode<32>("fffffffe00000001000000000000000200000002fffffffffffffffefffffffd");out.fill(0xa5);
      assert(AthSecurity::saeGroup19ReduceH2EValue(input.data(),48,out.data(),out.size()));assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);
      out.fill(0xa5);assert(!AthSecurity::saeGroup19ReduceH2EValue(input.data(),47,out.data(),out.size()));unchanged(out);
    }
    { const auto input=decode<48>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");const auto expected=decode<32>("18181817fffefdfd14131211100f0e0d0c0d0e0f282b2e3134373a3d40424446");out.fill(0xa5);
      assert(AthSecurity::saeGroup19ReduceH2EValue(input.data(),48,out.data(),out.size()));assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);
      out.fill(0xa5);assert(!AthSecurity::saeGroup19ReduceH2EValue(input.data(),47,out.data(),out.size()));unchanged(out);
    }
    { AthSecurity::P256FieldAPI api{};api.curve=curve;
      api.units=symbol<decltype(api.units)>(lib,"cczp_n");api.prime=symbol<decltype(api.prime)>(lib,"cczp_prime");
      actualFieldMultiply=symbol<decltype(actualFieldMultiply)>(lib,"cczp_mul");actualFieldInverse=symbol<decltype(actualFieldInverse)>(lib,"cczp_inv");
      api.multiply=fieldMultiply;api.inverse=fieldInverse;
      api.add=symbol<decltype(api.add)>(lib,"cczp_add");api.subtract=symbol<decltype(api.subtract)>(lib,"cczp_sub");
      AthSecurity::P256FieldCandidate field(api);AthSecurity::P256FieldWorkspace workspace;
      auto a=decode<32>("0000000000000000000000000000000000000000000000000000000000000002"),b=decode<32>("0000000000000000000000000000000000000000000000000000000000000003");
      const auto product=decode<32>("0000000000000000000000000000000000000000000000000000000000000006"),inverse=decode<32>("7fffffff80000000800000000000000000000000800000000000000000000000");
      {const auto input=decode<32>("0000000000000000000000000000000000000000000000000000000000000000");out.fill(0xa5);
       calls=failAt=0;assert(field.squareRoot(input.data(),32,out.data(),80,workspace)==true);
       const auto expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000000");assert(!memcmp(out.data(),expected.data(),32));
      }
      {const auto input=decode<32>("0000000000000000000000000000000000000000000000000000000000000001");out.fill(0xa5);
       calls=failAt=0;assert(field.squareRoot(input.data(),32,out.data(),80,workspace)==true);
       const auto expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000001");assert(!memcmp(out.data(),expected.data(),32));
      }
      {const auto input=decode<32>("0000000000000000000000000000000000000000000000000000000000000004");out.fill(0xa5);
       calls=failAt=0;assert(field.squareRoot(input.data(),32,out.data(),80,workspace)==true);
       const auto expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000002");assert(!memcmp(out.data(),expected.data(),32));
      }
      {const auto input=decode<32>("0000000000000000000000000000000000000000000000000000000000000009");out.fill(0xa5);
       calls=failAt=0;assert(field.squareRoot(input.data(),32,out.data(),80,workspace)==true);
       const auto expected=decode<32>("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc");assert(!memcmp(out.data(),expected.data(),32));
      }
      {const auto input=decode<32>("ffffffff00000001000000000000000000000000fffffffffffffffffffffffe");out.fill(0xa5);
       calls=failAt=0;assert(field.squareRoot(input.data(),32,out.data(),80,workspace)==false);
       unchanged(out);
      }
      {auto input=decode<32>("0000000000000000000000000000000000000000000000000000000000000004");
       calls=failAt=0;assert(field.squareRoot(input.data(),32,out.data(),80,workspace));const auto total=calls;
       for(unsigned n:{1u,total/2,total}){calls=0;failAt=n;out.fill(0xa5);
        assert(!field.squareRoot(input.data(),32,out.data(),80,workspace));unchanged(out);
        for(size_t j=0;j<sizeof(workspace);++j)assert(reinterpret_cast<const uint8_t *>(&workspace)[j]==0);
       }failAt=0;
      }
      {const auto nonsquare=decode<32>(P256Fixtures::prime);
       auto input=nonsquare;--input[31]; // p-1, a nonsquare since p = 3 mod 4.
       calls=failAt=0;out.fill(0xa5);
       assert(field.squareRootStatus(input.data(),32,out.data(),80,workspace)==AthSecurity::P256FieldResult::NotSquare);unchanged(out);
       assert(field.squareRootStatus(nonsquare.data(),32,out.data(),80,workspace)==AthSecurity::P256FieldResult::Error);unchanged(out);
       calls=0;failAt=3;
       assert(field.squareRootStatus(input.data(),32,out.data(),80,workspace)==AthSecurity::P256FieldResult::Error);unchanged(out);failAt=0;
      }
      {const auto a=decode<32>("0000000000000000000000000000000000000000000000000000000000000002"),b=decode<32>("0000000000000000000000000000000000000000000000000000000000000003");
       {const auto expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000005");out.fill(0xa5);assert(field.add(a.data(),b.data(),32,out.data(),80,workspace));assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);}
       {const auto expected=decode<32>("ffffffff00000001000000000000000000000000fffffffffffffffffffffffe");out.fill(0xa5);assert(field.subtract(a.data(),b.data(),32,out.data(),80,workspace));assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);}
      }
      {const auto a=decode<32>("ffffffff00000001000000000000000000000000fffffffffffffffffffffffe"),b=decode<32>("ffffffff00000001000000000000000000000000fffffffffffffffffffffffe");
       {const auto expected=decode<32>("ffffffff00000001000000000000000000000000fffffffffffffffffffffffd");out.fill(0xa5);assert(field.add(a.data(),b.data(),32,out.data(),80,workspace));assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);}
       {const auto expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000000");out.fill(0xa5);assert(field.subtract(a.data(),b.data(),32,out.data(),80,workspace));assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);}
      }
      {const auto a=decode<32>("0000000000000000000000000000000000000000000000000000000000000000"),b=decode<32>("0000000000000000000000000000000000000000000000000000000000000001");
       {const auto expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000001");out.fill(0xa5);assert(field.add(a.data(),b.data(),32,out.data(),80,workspace));assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);}
       {const auto expected=decode<32>("ffffffff00000001000000000000000000000000fffffffffffffffffffffffe");out.fill(0xa5);assert(field.subtract(a.data(),b.data(),32,out.data(),80,workspace));assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);}
      }
      {const auto a=decode<32>("0000000000000000000000000000000000000000000000000000000000000001"),b=decode<32>("0000000000000000000000000000000000000000000000000000000000000001");
       {const auto expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000002");out.fill(0xa5);assert(field.add(a.data(),b.data(),32,out.data(),80,workspace));assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);}
       {const auto expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000000");out.fill(0xa5);assert(field.subtract(a.data(),b.data(),32,out.data(),80,workspace));assert(!memcmp(out.data(),expected.data(),32));for(size_t j=32;j<80;++j)assert(out[j]==0xa5);}
      }
      {const auto u=decode<32>("0000000000000000000000000000000000000000000000000000000000000000");const auto expected=decode<64>("a528bd8696bdaf996c65b982d94959d3146fe6a020693090bdba13132375f2240e5fb73d16791ce358fb5adb2d33668a3b24099fd8d401f6685e0e994fb4d756");
       calls=failAt=0;out.fill(0xa5);assert(AthSecurity::saeGroup19SSWU(field,u.data(),32,out.data(),80,workspace));assert(!memcmp(out.data(),expected.data(),64));for(size_t j=64;j<80;++j)assert(out[j]==0xa5);
      }
      {const auto u=decode<32>("0000000000000000000000000000000000000000000000000000000000000001");const auto expected=decode<64>("db4698c8497def7b647653b93facc51d5cdd384d642795b77e596b889f6facc727e86f687ca94e26b655508b3bfec36e3e73a474c9f7914931f09c6e91d3fa5b");
       calls=failAt=0;out.fill(0xa5);assert(AthSecurity::saeGroup19SSWU(field,u.data(),32,out.data(),80,workspace));assert(!memcmp(out.data(),expected.data(),64));for(size_t j=64;j<80;++j)assert(out[j]==0xa5);
      }
      {const auto u=decode<32>("0000000000000000000000000000000000000000000000000000000000000002");const auto expected=decode<64>("eacdd18501ea13403e4f3b609bcbed7cde8dacbcc108e10accf23edeaff6789f999cbac0bc3d067557493edb9b22feb1623c7a64cb69255801ba634dbbe7955a");
       calls=failAt=0;out.fill(0xa5);assert(AthSecurity::saeGroup19SSWU(field,u.data(),32,out.data(),80,workspace));assert(!memcmp(out.data(),expected.data(),64));for(size_t j=64;j<80;++j)assert(out[j]==0xa5);
      }
      {const auto u=decode<32>("0000000000000000000000000000000000000000000000000000000000000003");const auto expected=decode<64>("d96e39d020f60a368176565aa752e4cb5dd09b4a3eb75ab0389b4500ed5baf94835cedb7afbe78818807b5b9accfd8b2d576d38542d1fc3cdc2e6a8ccba9e947");
       calls=failAt=0;out.fill(0xa5);assert(AthSecurity::saeGroup19SSWU(field,u.data(),32,out.data(),80,workspace));assert(!memcmp(out.data(),expected.data(),64));for(size_t j=64;j<80;++j)assert(out[j]==0xa5);
      }
      {const auto u=decode<32>("ffffffff00000001000000000000000000000000fffffffffffffffffffffffe");const auto expected=decode<64>("db4698c8497def7b647653b93facc51d5cdd384d642795b77e596b889f6facc7d81790968356b1da49aaaf74c4013c91c18c5b8c36086eb6ce0f63916e2c05a4");
       calls=failAt=0;out.fill(0xa5);assert(AthSecurity::saeGroup19SSWU(field,u.data(),32,out.data(),80,workspace));assert(!memcmp(out.data(),expected.data(),64));for(size_t j=64;j<80;++j)assert(out[j]==0xa5);
      }
      {auto u=decode<32>("0000000000000000000000000000000000000000000000000000000000000001");
       auto run=[&](){return AthSecurity::saeGroup19SSWU(field,u.data(),32,out.data(),80,workspace);};
       calls=failAt=0;assert(run());const auto total=calls;assert(engine.validate(out.data(),64,w));clean(w);
       for(unsigned n:{1u,total/2,total}){calls=0;failAt=n;out.fill(0xa5);assert(!run());unchanged(out);
        for(size_t j=0;j<sizeof(workspace);++j)assert(reinterpret_cast<const uint8_t *>(&workspace)[j]==0);
       }failAt=0;
       u=decode<32>(P256Fixtures::prime);out.fill(0xa5);assert(!run());unchanged(out);
      }
      {const uint8_t ssid[]="test-ssid",password[]="test-password",id[]="test-id";
       const auto expected=decode<64>("84347bb62237b0df47cae8e044af1c097d15f635dbed2ae56b6b1740189a73f5de793758cf3db5c47ef4e2636e730ab88551c914ebdb8e9ef4e3303b7c9d5c1b");
       auto run=[&](){return AthSecurity::saeGroup19H2EPT<H2ETestCrypto>(field,engine,ssid,9,password,13,id,7,out.data(),80,workspace,w);};
       calls=failAt=0;out.fill(0xa5);assert(run());assert(!memcmp(out.data(),expected.data(),64));
       const auto total=calls;assert(engine.validate(out.data(),64,w));clean(w);
       {const uint8_t a[]={2,1,2,3,4,5},b[]={2,6,7,8,9,10};uint8_t pwe[64]{};
        const auto expectedPWE=decode<64>("8e3a78633b49752947fa2ec5fe4f9ceb7d80763eb62ecbaa468a8b570618f660a4932a75da3118352dfa78c45ed3c039d020c8e1b9f32504a8e725e085b6930d");
        assert(AthSecurity::saeGroup19H2EPWE<H2ETestCrypto>(engine,out.data(),64,a,b,6,pwe,64,w));
        assert(!memcmp(pwe,expectedPWE.data(),64));assert(engine.validate(pwe,64,w));clean(w);
        AthSecurity::wipe(pwe,sizeof(pwe));
       }

       for(unsigned n:{1u,total/2,total}){calls=0;failAt=n;out.fill(0xa5);assert(!run());unchanged(out);clean(w);
        for(size_t j=0;j<sizeof(workspace);++j)assert(reinterpret_cast<const uint8_t *>(&workspace)[j]==0);
       }failAt=0;
      }
      {auto square=decode<32>("0000000000000000000000000000000000000000000000000000000000000004");
       auto nonsquare=decode<32>(P256Fixtures::prime);--nonsquare[31];
       calls=failAt=0;assert(field.squareRootStatus(square.data(),32,out.data(),80,workspace)==AthSecurity::P256FieldResult::Success);const auto squareCalls=calls;
       calls=0;assert(field.squareRootStatus(nonsquare.data(),32,out.data(),80,workspace)==AthSecurity::P256FieldResult::NotSquare);
       assert(calls==squareCalls); // Normal residue outcomes must not skip conversion/allocation.
      }
      for(bool invert:{false,true}){
        auto run=[&](){return invert?field.inverse(a.data(),32,out.data(),80,workspace):field.multiply(a.data(),32,b.data(),32,out.data(),80,workspace);};
        calls=failAt=0;out.fill(0xa5);assert(run());assert(!memcmp(out.data(),invert?inverse.data():product.data(),32));
        const unsigned total=calls;
        for(unsigned n=1;n<=total;++n){calls=0;failAt=n;out.fill(0xa5);assert(!run());unchanged(out);
          for(size_t j=0;j<sizeof(workspace);++j)assert(reinterpret_cast<const uint8_t *>(&workspace)[j]==0);}
        failAt=0;
      }
    }
    {const uint8_t a[]={2,1,2,3,4,5},b[]={2,6,7,8,9,10};
     const auto expected=decode<64>("a82d564ff856993a50bb2d8f9feeb823a273eac97f13f26216545dacf33a8dcd618c2bd6673173dabf5f2a2d5bf95905cf67fd4316deefb37ba0e318e3328de6");std::array<uint8_t,80> other{};
     auto run=[&](){return AthSecurity::saeGroup19H2EPWE<H2ETestCrypto>(engine,g.data(),64,a,b,6,out.data(),80,w);};
     calls=failAt=0;out.fill(0xa5);assert(run());assert(!memcmp(out.data(),expected.data(),64));const auto total=calls;
     assert(AthSecurity::saeGroup19H2EPWE<H2ETestCrypto>(engine,g.data(),64,b,a,6,other.data(),80,w));assert(!memcmp(other.data(),expected.data(),64));
     auto changed=std::array<uint8_t,6>{2,6,7,8,9,11};
     assert(AthSecurity::saeGroup19H2EPWE<H2ETestCrypto>(engine,g.data(),64,a,changed.data(),6,other.data(),80,w));assert(memcmp(other.data(),expected.data(),64));
     for(unsigned n=1;n<=total;++n){calls=0;failAt=n;out.fill(0xa5);assert(!run());unchanged(out);clean(w);}failAt=0;
    }
    {const auto input=decode<32>("0000000000000000000000000000000000000000000000000000000000000000"),expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000001");out.fill(0xa5);assert(AthSecurity::saeGroup19H2EScalar(input.data(),32,out.data(),80));assert(!memcmp(out.data(),expected.data(),32));}
    {const auto input=decode<32>("0000000000000000000000000000000000000000000000000000000000000001"),expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000002");out.fill(0xa5);assert(AthSecurity::saeGroup19H2EScalar(input.data(),32,out.data(),80));assert(!memcmp(out.data(),expected.data(),32));}
    {const auto input=decode<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f"),expected=decode<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550");out.fill(0xa5);assert(AthSecurity::saeGroup19H2EScalar(input.data(),32,out.data(),80));assert(!memcmp(out.data(),expected.data(),32));}
    {const auto input=decode<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"),expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000001");out.fill(0xa5);assert(AthSecurity::saeGroup19H2EScalar(input.data(),32,out.data(),80));assert(!memcmp(out.data(),expected.data(),32));}
    {const auto input=decode<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),expected=decode<32>("0000000000000000000000000000000000000000000000000000000000000002");out.fill(0xa5);assert(AthSecurity::saeGroup19H2EScalar(input.data(),32,out.data(),80));assert(!memcmp(out.data(),expected.data(),32));}
    {const auto input=decode<32>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),expected=decode<32>("00000000ffffffff00000000000000004319055258e8617b0c46353d039cdab0");out.fill(0xa5);assert(AthSecurity::saeGroup19H2EScalar(input.data(),32,out.data(),80));assert(!memcmp(out.data(),expected.data(),32));}
    printf("{\"userland_corecrypto_uuid\":\"%s\",\"multiplication_vectors\":12,\"add_subtract_vectors\":14,\"injected_failures\":%u,\"workspace_bytes\":%zu,\"kernel_runtime_verified\":false,\"sae_implemented\":false}\n",uuid().c_str(),faultChecks,sizeof(w));
    dlclose(lib);
}
