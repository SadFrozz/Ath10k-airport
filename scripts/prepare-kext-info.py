import sys,plistlib,pathlib
p=pathlib.Path('Ath10kMac.kext/Contents/Info.plist'); d=plistlib.loads(p.read_bytes())
if sys.argv[1]=='1':
 d['OSBundleLibraries'].update({'com.apple.iokit.IO80211Family':'1200.13.1','com.apple.iokit.IOSkywalkFamily':'1.0','com.apple.driver.corecapture':'1.0.0','com.apple.kec.corecrypto':'1.0'})
 d['IOKitPersonalities']={'Lunnen-QCA9377':d['IOKitPersonalities']['QCA9377']}
 d['IOKitPersonalities']['Lunnen-QCA9377'].update({'IOMatchCategory':'WiFiDriver','IONetworkRootType':'airport','Ath10kNativeExperimental':True,'Ath10kStationDFS':True,'IOPCISecondaryMatch':'0x2b511a3b'})
pathlib.Path(sys.argv[2]).write_bytes(plistlib.dumps(d,sort_keys=False))
