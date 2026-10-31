#!/usr/bin/env python3
"""Synthetic AKM-8, --owe AKM-18 or --eap-sha256 AKM-5 fixtures with independent crypto.

Regeneration requires cryptography; tests consume the checked-in public fixture.
No real credentials or packets are read. Output is written only to stdout.
"""
import sys
OWE = "--owe" in sys.argv
EAP_SHA256 = "--eap-sha256" in sys.argv
assert not (OWE and EAP_SHA256)
import hashlib
import hmac
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

PMK = bytes.fromhex('82b9391b7d38228fdb913b2d587547380bfc1310fb5c63b9b8e1baa2d568d715')
STA, AP = bytes.fromhex('020102030405'), bytes.fromhex('02060708090a')
SN, AN, NEXT_AN = bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96))
RSN = bytes.fromhex('301a0100000fac040100000fac040100000fac08c0000000000fac06')
if OWE:
    RSN = RSN[:19] + bytes([18]) + RSN[20:]
if EAP_SHA256:
    RSN = RSN[:19] + bytes([5]) + RSN[20:]
PMKID = bytes(16)
STATION_RSN = RSN[:1] + bytes([42]) + RSN[2:22] + b'\x01\x00' + PMKID + RSN[24:]

if OWE or EAP_SHA256:
    STATION_RSN = RSN

def ptk(an, master=PMK):
    context = min(STA, AP) + max(STA, AP) + min(SN, an) + max(SN, an)
    return b''.join(hmac.digest(master, i.to_bytes(2, 'little') + b'Pairwise key expansion' +
                                context + (384).to_bytes(2, 'little'), hashlib.sha256)
                    for i in (1, 2))[:48]


PTK, NEXT_PTK = ptk(AN), ptk(NEXT_AN)
GTK, GTK2, GTK3 = bytes(range(80, 96)), bytes(range(112, 128)), bytes(range(144, 160))
IGTK, IGTK2, IGTK3 = bytes(range(160, 176)), bytes(range(176, 192)), bytes(range(192, 208))


def gtk(key, index=1):
    return b'\xdd\x16\x00\x0f\xac\x01' + bytes([index, 0]) + key


def igtk(key, index=4, ipn=1):
    return b'\xdd\x1c\x00\x0f\xac\x09' + index.to_bytes(2, 'little') + ipn.to_bytes(6, 'little') + key


def wrap(data, key=PTK):
    if len(data) % 8:
        data += b'\xdd' + bytes((-len(data) - 1) % 8)
    return aes_key_wrap(key[16:32], data)


def frame(info, replay, nonce=bytes(32), data=b'', key=PTK, station=False, length=16):
    if EAP_SHA256:
        info = (info & ~7) | 3
    p = bytearray(99 + len(data))
    p[:2] = b'\x02\x03'
    p[2:4] = (len(p) - 4).to_bytes(2, 'big')
    p[4] = 2
    p[5:7], p[7:9], p[9:17] = info.to_bytes(2, 'big'), length.to_bytes(2, 'big'), replay.to_bytes(8, 'big')
    p[17:49] = nonce
    p[97:99], p[99:] = len(data).to_bytes(2, 'big'), data
    if info & 0x100:
        if OWE:
            p[81:97] = hmac.digest(key[:16], bytes(p), hashlib.sha256)[:16]
        else:
            tag = cmac.CMAC(algorithms.AES(key[:16])); tag.update(bytes(p)); p[81:97] = tag.finalize()
    return (AP + STA if station else STA + AP) + b'\x88\x8e' + p


def m3(data, replay=2, key=PTK, nonce=AN):
    return frame(0x13c8, replay, nonce, wrap(data, key), key)


vectors = dict(pmk=PMK, sta=STA, ap=AP, snonce=SN, anonce=AN, pmkid=PMKID, rsn=RSN,
               station_rsn=STATION_RSN, ptk=PTK, next_ptk=NEXT_PTK,
               gtk=GTK, next_gtk=GTK2, third_gtk=GTK3, igtk=IGTK, next_igtk=IGTK2, third_igtk=IGTK3)
vectors.update(m1=frame(0x88, 1, AN), m2=frame(0x108, 1, SN, STATION_RSN, station=True, length=0),
               m3=m3(RSN + gtk(GTK) + igtk(IGTK)),
               m3_retry=m3(RSN + gtk(GTK) + igtk(IGTK), replay=3),
               m4=frame(0x308, 2, station=True, length=0),
               m4_retry=frame(0x308, 3, station=True, length=0))
transition = bytearray(RSN[:14] + b'\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x08' + RSN[20:])
if OWE or EAP_SHA256:
    transition[23] = 18 if OWE else 5
transition[1], transition[24] = len(transition) - 2, 0x80
default_management = bytearray(RSN[:22]); default_management[1] = 20
vectors.update(transition_rsn=bytes(transition), transition_m3=m3(bytes(transition) + gtk(GTK) + igtk(IGTK)),
               default_management_rsn=bytes(default_management),
               default_management_m3=m3(bytes(default_management) + gtk(GTK) + igtk(IGTK)),
               m2_withoutid=frame(0x108, 1, SN, RSN, station=True, length=0))
vectors.update(mgmt_only=frame(0x1380, 4, data=wrap(igtk(IGTK2, 5, 1))),
               mgmt_ack=frame(0x300, 4, station=True, length=0),
               group_both=frame(0x1380, 5, data=wrap(gtk(GTK2) + igtk(IGTK3, 4, 2))),
               group_ack=frame(0x300, 5, station=True, length=0),
               group_same=frame(0x1380, 6, data=wrap(gtk(GTK2) + igtk(IGTK3, 4, 0))),
               group_gtk_only=frame(0x1380, 7, data=wrap(gtk(GTK3) + igtk(IGTK3, 4, 0))),
               group_moved_igtk=frame(0x1380, 8, data=wrap(igtk(IGTK3, 5, 0))))
vectors.update(rekey1=frame(0x88, 10, NEXT_AN),
               rekey2=frame(0x108, 10, SN, STATION_RSN, NEXT_PTK, station=True, length=0),
               rekey3=m3(RSN, 11, NEXT_PTK, NEXT_AN),
               rekey3_withkeys=m3(RSN + gtk(GTK3) + igtk(IGTK3, 4, 0), 11, NEXT_PTK, NEXT_AN),
               rekey4=frame(0x308, 11, key=NEXT_PTK, station=True, length=0))
if EAP_SHA256 or OWE:
    policy = bytes([0xdd, 5, 0x50, 0x6f, 0x9a, 0x20, 4 if EAP_SHA256 else 8])
    vectors.update(policy_m3=m3(RSN + gtk(GTK) + igtk(IGTK) + policy),
                   policy_duplicate=m3(RSN + gtk(GTK) + igtk(IGTK) + policy + policy))
if EAP_SHA256:
    new_master = bytes(range(224, 256))
    new_ptk = ptk(NEXT_AN, new_master)
    vectors.update(reauth_pmk=new_master, reauth_ptk=new_ptk,
                   reauth2=frame(0x108, 10, SN, STATION_RSN, new_ptk, station=True, length=0),
                   reauth3=m3(RSN, 11, new_ptk, NEXT_AN),
                   reauth4=frame(0x308, 11, key=new_ptk, station=True, length=0))
vectors.update(missing_igtk=m3(RSN + gtk(GTK)), duplicate_igtk=m3(RSN + gtk(GTK) + igtk(IGTK) * 2),
               bad_igtk_id=m3(RSN + gtk(GTK) + igtk(IGTK, 6)),
               bad_padding=m3(RSN + gtk(GTK) + igtk(IGTK) + b'\xdd\x00\x01'),
               changed_rsn=m3(RSN[:20] + b'\x80\x00' + RSN[22:] + gtk(GTK) + igtk(IGTK)))
badwrap = bytearray(wrap(RSN + gtk(GTK) + igtk(IGTK))); badwrap[-1] ^= 1
vectors['bad_wrap'] = frame(0x13c8, 2, AN, bytes(badwrap))
print('// Generated by tools/sae/generate-eapol-vectors.py' + (' --owe' if OWE else ' --eap-sha256' if EAP_SHA256 else '') + '; synthetic public fixtures.')
for name, value in vectors.items():
    print('static const uint8_t w_' + name + '[]={' + ','.join(str(b) for b in value) + '};')
