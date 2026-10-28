#include "mock_sae_worker.hpp"

struct Barrier {
    std::mutex mutex;std::condition_variable cv;bool entered=false,released=false;
    void pause(){std::unique_lock<std::mutex> guard(mutex);entered=true;cv.notify_all();assert(cv.wait_for(guard,5s,[&]{return released;}));}
    void wait(){std::unique_lock<std::mutex> guard(mutex);assert(cv.wait_for(guard,5s,[&]{return entered;}));}
    void resume(){std::lock_guard<std::mutex> guard(mutex);released=true;cv.notify_all();}
};
struct Job : Ath10kSAEWorkItem {
    std::atomic<unsigned> executed{0},discarded{0};std::atomic<bool> executing{false};
    unsigned char secret[64];Barrier *execution=nullptr,*retirement=nullptr;
    Job(){memset(secret,0xa5,sizeof(secret));}
    void execute() override {
        assert(!heldLocks && !ownerGate);executing=true;++executed;
        if(execution)execution->pause();executing=false;
    }
    void discard() override {
        assert(!heldLocks && !executing);++discarded;
        if(retirement)retirement->pause();memset(secret,0,sizeof(secret));
    }
};
static Ath10kSAEWorker *create(){auto p=new Ath10kSAEWorker;assert(p->init());return p;}
static void waitForSleep(unsigned count){std::unique_lock<std::mutex> guard(observation);assert(observed.wait_for(guard,5s,[&]{return sleeps>=count;}));}
static void clean(){assert(objects==0 && locks==0 && calls==0);}
int main(){
    for(bool lockFailure:{true,false}){
        failLock=lockFailure;failCall=!lockFailure;auto p=new Ath10kSAEWorker;assert(!p->init());p->release();clean();
    }
    { auto p=create();auto call=latest;auto a=new Job;auto b=new Job;
      assert(p->submit(a));assert(!p->submit(b));assert(!p->takeCompleted());
      run(call);assert(a->executed==1 && !a->discarded);assert(!p->submit(b));
      auto result=p->takeCompleted();assert(result==a && !p->takeCompleted());
      result->release();assert(a->references()==1);
      assert(p->submit(b));ownerGate=true;p->cancel();ownerGate=false;
      assert(b->discarded==1 && !b->executed && b->references()==1);
      p->shutdown();assert(!p->submit(b));p->shutdown();p->release();a->release();b->release();clean();
    }
    { // Independent consumers must not steal a completed owner's job.
      auto p=create();auto call=latest;auto a=new Job;auto b=new Job;
      unsigned ownerA=1,ownerB=2;
      assert(p->submit(a,&ownerA));assert(!p->takeCompletedFor(&ownerA));run(call);
      const auto refs=a->references();ownerGate=true;
      assert(!p->takeCompletedFor(nullptr) && !p->takeCompletedFor(&ownerB));ownerGate=false;
      assert(a->references()==refs && !a->discarded && !p->available() && !p->submit(b,&ownerB));
      auto result=p->takeCompletedFor(&ownerA);assert(result==a);result->release();
      assert(p->available() && !p->takeCompletedFor(&ownerA));
      assert(p->submit(b,&ownerB));run(call);assert(!p->takeCompletedFor(&ownerA));
      result=p->takeCompletedFor(&ownerB);assert(result==b);result->release();
      // Default-owner jobs are collected by their own retained identity.
      assert(p->submit(a));run(call);assert(!p->takeCompletedFor(&ownerA));
      result=p->takeCompletedFor(a);assert(result==a);result->release();
      p->shutdown();p->release();a->release();b->release();clean();
    }
    { // Simultaneous polling consumers transfer exactly one retained reference.
      auto p=create();auto a=new Job;unsigned ownerA=1,ownerB=2;assert(p->submit(a,&ownerA));run(latest);
      std::atomic<bool> go{false};Ath10kSAEWorkItem *result=nullptr;
      std::thread wrong([&]{while(!go)std::this_thread::yield();for(unsigned i=0;i<1000;++i)assert(!p->takeCompletedFor(&ownerB));});
      std::thread right([&]{while(!go)std::this_thread::yield();result=p->takeCompletedFor(&ownerA);});
      go=true;wrong.join();right.join();assert(result==a && !p->takeCompletedFor(&ownerA));result->release();
      p->shutdown();p->release();a->release();clean();
    }
    { // Cancel and same-slot reuse must retire the previous binding.
      auto p=create();auto a=new Job;auto b=new Job;unsigned ownerA=1,ownerB=2;
      assert(p->submit(a,&ownerA));run(latest);ownerGate=true;p->cancel();ownerGate=false;
      assert(a->discarded==1 && !p->takeCompletedFor(&ownerA));
      assert(p->submit(b,&ownerB));run(latest);assert(!p->takeCompletedFor(&ownerA));
      auto result=p->takeCompletedFor(&ownerB);assert(result==b);result->release();
      p->shutdown();p->release();a->release();b->release();clean();
    }
    { // Cancel returns false after dispatch but before callback; drain must wait.
      auto p=create();auto call=latest;auto a=new Job;assert(p->submit(a));claim(call);
      ownerGate=true;p->cancel();ownerGate=false;assert(!a->discarded && !p->takeCompleted());
      const auto count=sleeps.load();std::atomic<bool> stopped{false};
      std::thread stopper([&]{p->shutdown();stopped=true;});waitForSleep(count+1);assert(!stopped);
      invoke(call);finish(call);stopper.join();assert(stopped && !a->executed && a->discarded==1);
      p->release();a->release();clean();
    }
    { // Cancel while crypto executes: no concurrent wipe, no completion publication.
      auto p=create();auto call=latest;auto a=new Job;Barrier computing;a->execution=&computing;
      assert(p->submit(a));std::thread runner([&]{run(call);});computing.wait();
      ownerGate=true;p->cancel();ownerGate=false;
      assert(a->executing && !a->discarded && !p->takeCompleted());
      const auto count=sleeps.load();std::atomic<bool> stopped{false};
      std::thread stopper([&]{p->shutdown();stopped=true;});waitForSleep(count+1);assert(!stopped);
      computing.resume();runner.join();stopper.join();assert(a->discarded==1 && a->executed==1 && a->references()==1);
      for(auto v:a->secret)assert(v==0);p->release();a->release();clean();
    }
    { // A completed result cancelled under a gate is disposed outside bookkeeping.
      auto p=create();auto a=new Job;assert(p->submit(a));run(latest);p->cancel();
      assert(a->discarded==1 && !p->takeCompleted());assert(p->submit(a));run(latest);
      auto result=p->takeCompleted();assert(result==a);result->release();p->shutdown();p->release();a->release();clean();
    }
    { // Drain includes external retirement preempted after detaching its result.
      auto p=create();auto a=new Job;Barrier retiring;a->retirement=&retiring;
      assert(p->submit(a));run(latest);
      std::thread canceller([&]{p->cancel();});retiring.wait();assert(!p->submit(a));
      const auto count=sleeps.load();std::atomic<bool> stopped{false};
      std::thread stopper([&]{p->shutdown();stopped=true;});waitForSleep(count+1);assert(!stopped);
      retiring.resume();canceller.join();stopper.join();assert(a->discarded==1);p->release();a->release();clean();
    }
    { // Callback retain survives loss of the last external queue reference.
      auto p=create();auto call=latest;auto a=new Job;assert(p->submit(a));p->release();
      run(call);assert(a->executed==1 && a->discarded==1 && a->references()==1);a->release();clean();
    }
    { // Requeue in the ONCE kernel-return gap, then cancel its reschedule.
      auto p=create();auto call=latest;auto a=new Job;auto b=new Job;
      assert(p->submit(a));claim(call);invoke(call);
      auto result=p->takeCompleted();assert(result==a);result->release();
      assert(p->submit(b));p->cancel();assert(b->discarded==1 && !b->executed);
      p->shutdown();finish(call);p->release();a->release();b->release();clean();
    }
}
