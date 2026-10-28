// Included inside Ath10kPCIDevice, only in the Sequoia build.
public:
    IO80211WorkQueue *getWorkQueue() const override;
    bool createWorkQueue() override {return getWorkQueue()!=nullptr;}
    bool isCommandProhibited(int) override {return false;}
    SInt32 handleCardSpecific(IO80211SkywalkInterface *,unsigned long command,void *,bool set) override {
        // WCL performs the actual operation; this controller hook must not veto it.
        setProperty("Ath10kNativeCardCommand",UInt64(command),64);
        setProperty("Ath10kNativeCardCommandIsSet",set);
        return kIOReturnSuccess;
    }
    bool requiresExplicitMBufRelease() override {return false;}
    bool flowIdSupported() override {return false;}
    CCLogStream *getLogger() const override {return _nativeLogger;}
    CommonFaultReporter *getFaultReporterFromDriver() override {return _nativeFault;}
    bool getLogPipes(CCPipe **,CCPipe **,CCPipe **) override;
    IOReturn getDRIVER_VERSION(IO80211SkywalkInterface *,apple80211_version_data *) override;
    IOReturn getHARDWARE_VERSION(IO80211SkywalkInterface *,apple80211_version_data *) override;
    IOReturn getCARD_CAPABILITIES(IO80211SkywalkInterface *,apple80211_capability_data *) override;
    IOReturn getPOWER(IO80211SkywalkInterface *,apple80211_power_data *) override;
    IOReturn setPOWER(IO80211SkywalkInterface *,apple80211_power_data *) override;
    IOReturn getCOUNTRY_CODE(IO80211SkywalkInterface *,apple80211_country_code_data *) override;
    IOReturn setCOUNTRY_CODE(IO80211SkywalkInterface *,apple80211_country_code_data *) override;
    IOReturn setGET_DEBUG_INFO(IO80211SkywalkInterface *,apple80211_debug_command *) override {return kIOReturnUnsupported;}
    IONetworkInterface *createInterface() override;
    IOReturn nativeRequest(AthNativeOp,void *);
    static IOReturn nativeAction(OSObject *,void *,void *,void *,void *);
    IOReturn nativeRequestGated(AthNativeOp,void *);
    IOReturn nativeCurrentAPInfo(AthNativeOp,void *);
    IOReturn nativeLinkStateUpdate(void *);
    IOReturn nativeLinkMetrics(AthNativeOp,void *);
    IOReturn nativePHYCapabilities(AthNativeOp,void *);
    bool prepareNativeInterface();
    bool prepareNativeLogs();
    void nativeStartupPhase(const char *);
    void releaseNativeInterface();
    void stopNativeRequests();
    void nativeInterfaceWillStop(Ath10kNativeInterface *);
    void prepareNativeInterfaceTermination(Ath10kNativeInterface *);
    static IOReturn nativeInterfaceStopAction(OSObject *,void *,void *,void *,void *);
    void discardNativeSecurity();
    bool nativePMFPairwiseAcknowledged(const UInt8 *);
    bool nativePMFPortReady();
    static IOReturn nativeStopAction(OSObject *,void *,void *,void *,void *);
    void releaseNativeLogs();
    void serviceNative(UInt64);
    bool nativePMFTransportReady();
    void serviceNativePMF(UInt64);
    static bool nativePMFManagement(void *,const UInt8 *,UInt32,UInt32,UInt32,UInt32);
    void serviceNativeNotifications(UInt64);
    void requestNativeService();
    static void nativeServiceThread(thread_call_param_t,thread_call_param_t);
    static IOReturn nativeServiceWCLAction(OSObject *,void *,void *,void *,void *);
    static IOReturn nativeServiceRadioAction(OSObject *,void *,void *,void *,void *);
    thread_call_t _nativeServiceCall=nullptr;
    IOLock *_nativeServiceLock=nullptr;
    bool _nativeServiceQueued=false,_nativeServiceRunning=false,_nativeServiceStopping=false;
    bool _nativeServicePending=false;
    IOReturn _nativePostError=kIOReturnSuccess;
    UInt64 _nativePostFailures=0;
    const char *serviceNativeMAC(UInt64);
    const char *nativeSelectBSS(UInt64);
    bool _nativeMACActive=false,_nativeMACWaiting=false,_nativeMACValid=false;
    bool _nativeMACSubmitted=false;
    UInt32 _nativeMACStep=0,_nativeMACNext=0,_nativeMACGeneration=0;
    UInt64 _nativeMACSince=0;
    UInt8 _nativeMACCurrent[6]{},_nativeMACRequested[6]{};
    Ath10k::WMIEchoState _nativeMACEcho{};
    IOReturn _nativeMACResult=kIOReturnNotReady;
private:
    friend class Ath10kNativeInterface;
    friend class Ath10kBSDInterface;
    class NativeSecurity;
    IO80211WorkQueue *_nativeWorkQueue=nullptr;
    NativeSecurity *_nativeSecurity=nullptr;
    Ath10kNativeInterface *_nativeInterface=nullptr;
    IOCommandGate *_nativeGate=nullptr;
    IOCommandGate *_nativeBSDGate=nullptr;
    CCPipe *_nativePipes[3]{};
    bool _nativePipesStarted[3]{};
    CCLogStream *_nativeLogger=nullptr;
    CCStream *_nativeFaultStream=nullptr;
    CCFaultReporter *_nativeCoreFault=nullptr;
    IO80211FaultReporter *_nativeFault=nullptr;
    bool _nativeRadioOn=true,_nativeScanPending=false,_nativeJoinPending=false;
    bool _nativeAssocSent=false,_nativeBeaconSent=false,_nativeWasUp=false;
    bool _nativeJoinBSSSent=false,_nativeLinkUpSent=false,_nativeDeauthSent=false,_nativeJoinFailed=false;
    UInt8 _nativeLastBSSID[6]{};
    UInt32 _nativeScanResultIndex=0,_nativeScanResultsEmitted=0;
    bool _nativeScanStreamed=false;
    bool _nativeAttached=false,_nativeControllerAttached=false,_nativeStarted=false,_nativeStopping=false;
    UInt32 _nativeReportedBeacon=0;
    int _nativeReportedQuality=-2;
    bool _nativeReadyPublished=false,_nativeReadyRequested=false,_nativeAbortRequested=false,_nativeReadyResetSent=false;
    UInt64 _nativeJoinDeadline=0;
    AirportWCL::JoinRequest _nativeJoin{};
    AirportWCL::ScanRequest _nativeScan{};
    UInt8 _nativeBSSMessage[1600]{};
    UInt32 _nativeBSSBytes=0;
    UInt32 _nativeScanDwellMs=120;
