// Executes only in an ordinary user process. Does not load or call a kernel module.
#include "../../src/shared/Ath10kP256CoreCrypto.hpp"
#include "../../tests/p256_corecrypto_fixtures.hpp"
#include <dlfcn.h>
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
    printf("{\"userland_corecrypto_uuid\":\"%s\",\"multiplication_vectors\":12,\"add_subtract_vectors\":14,\"injected_failures\":%u,\"workspace_bytes\":%zu,\"kernel_runtime_verified\":false,\"sae_implemented\":false}\n",uuid().c_str(),faultChecks,sizeof(w));
    dlclose(lib);
}
