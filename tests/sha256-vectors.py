"""Independent public fixtures: hashlib KDF + cryptography CMAC/AES wrap."""
import hashlib,hmac,struct,sys
from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms
pmk=hashlib.pbkdf2_hmac('sha1',b'password',b'IEEE',4096,32)
sta=bytes.fromhex('020102030405');ap=bytes.fromhex('02060708090a')
snonce=bytes(range(32));anonce=bytes(range(32,64))
context=min(sta,ap)+max(sta,ap)+min(snonce,anonce)+max(snonce,anonce)
ptk=b''.join(hmac.digest(pmk,struct.pack('<H',i)+b'Pairwise key expansion'+context+struct.pack('<H',384),'sha256') for i in (1,2))[:48]
rsn=bytes.fromhex('30140100000fac040100000fac040100000fac068000')
station=rsn[:-2]+b'\0\0';gtk=bytes(range(80,96));newgtk=bytes(range(96,112))
def mic(key,data):
 c=CMAC(algorithms.AES(key));c.update(data);return c.finalize()
def packet(info,replay,nonce,data=b'',sign=False,reply=False):
 p=bytearray(99+len(data));p[0]=2;p[1]=3;p[2:4]=struct.pack('>H',len(p)-4);p[4]=2
 p[5:7]=struct.pack('>H',info);p[7:9]=struct.pack('>H',0 if reply else 16);p[9:17]=struct.pack('>Q',replay);p[17:49]=nonce;p[97:99]=struct.pack('>H',len(data));p[99:]=data
 if sign:p[81:97]=mic(ptk[:16],bytes(p))
 return (ap+sta if reply else sta+ap)+b'\x88\x8e'+p
plain=rsn+bytes.fromhex('dd16000fac010100')+gtk+b'\xdd\x00'
m1=packet(0x8b,1,anonce);m2=packet(0x10b,1,snonce,station,True,True)
m3=packet(0x13cb,2,anonce,aes_key_wrap(ptk[16:32],plain),True)
m4=packet(0x30b,2,bytes(32),b'',True,True)
groupPlain=bytes.fromhex('dd16000fac010200')+newgtk
# RFC3394 plaintext must be a multiple of eight; the KDE is 24 bytes.
group=packet(0x1383,3,bytes(32),aes_key_wrap(ptk[16:32],groupPlain),True)
groupAck=packet(0x303,3,bytes(32),b'',True,True)
originalPTK=ptk
nextNonce=bytes(range(64,96))
nextContext=min(sta,ap)+max(sta,ap)+min(snonce,nextNonce)+max(snonce,nextNonce)
nextPTK=b''.join(hmac.digest(pmk,struct.pack('<H',i)+b'Pairwise key expansion'+nextContext+struct.pack('<H',384),'sha256') for i in (1,2))[:48]
ptk=nextPTK
rekey1=packet(0x8b,5,nextNonce)
rekey2=packet(0x10b,5,snonce,station,True,True)
rekeyPlain=rsn+bytes.fromhex('dd16000fac010200')+newgtk+b'\xdd\x00'
rekey3=packet(0x13cb,6,nextNonce,aes_key_wrap(ptk[16:32],rekeyPlain),True)
rekey4=packet(0x30b,6,bytes(32),b'',True,True)
ptk=originalPTK
with open(sys.argv[1],'w') as out:
 for name,data in dict(pmk=pmk,sta=sta,ap=ap,snonce=snonce,rsn=rsn,gtk=gtk,newgtk=newgtk,ptk=ptk,m1=m1,m2=m2,m3=m3,m4=m4,group=group,groupAck=groupAck,nextPTK=nextPTK,rekey1=rekey1,rekey2=rekey2,rekey3=rekey3,rekey4=rekey4).items():
  out.write('static const uint8_t s_'+name+'[]={'+','.join(str(x) for x in data)+'};\n')
