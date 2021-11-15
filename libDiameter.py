#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - Nov 2012
# Version 0.3.1, Last change on Nov 17, 2012
# This software is distributed under the terms of BSD license.    
##################################################################
# Copyright (c) 2020, Mostafa  Elyasi <mostafa.elyasi@gmail.com>
# Code hanged to use in python3
# All functions needed to build/decode diameter messages


import xml.dom.minidom as minidom
import struct
import codecs
import socket
import sys
import logging
import time
import string

# Diameter Header fields

DIAMETER_FLAG_MANDATORY = 0x40
DIAMETER_FLAG_VENDOR    = 0x80

DIAMETER_HDR_REQUEST    = 0x80
DIAMETER_HDR_PROXIABLE  = 0x40
DIAMETER_HDR_ERROR      = 0x20
DIAMETER_HDR_RETRANSMIT = 0x10

# Include common routines for all modules
ERROR = -1
 

#migrate to python3 encode
class CodecPipeline(object):
    def __init__(self, *names, **kwds):
        self.default_errors = self._bind_kwds(**kwds)
        encoders = []
        decoders = []
        self.codecs = names
        for name in names:
            info = self._lookup_codec(name)
            encoders.append(info.encode)
            decoders.append(info.decode)
        self.encoders = encoders
        decoders.reverse()
        self.decoders = decoders

    def _bind_kwds(self, errors=None):
        if errors is None:
            errors = "strict"
        return errors

    def _lookup_codec(self, name):
        try:
            return codecs.lookup(name)
        except LookupError:
            return codecs.lookup(name + "_codec")

    def __repr__(self):
        names = self.codecs
        errors = self.default_errors
        if not names:
            return "{}(errors={!r})".format(type(self).__name__, errors)
        return "{}({}, errors={!r})".format(type(self).__name__,
                                            ", ".join(map(repr, names)),
                                            errors)

    def encode(self, input, errors=None):
        """Apply all encoding operations in the pipeline"""
        if errors is None:
            errors = self.default_errors
        result = input
        for encode in self.encoders:
            result, __ = encode(result, errors)
        return result

    def decode(self, input, errors=None):
        """Apply all decoding operations in the pipeline"""
        if errors is None:
            errors = self.default_errors
        result = input
        for decode in self.decoders:
            result,__ = decode(result, errors)
        return result



class AVPItem:
    def __init__(self):
        self.code=0
        self.name=""
        self.vendor=0
        self.type=""
        self.mandatory=""
        
class HDRItem:
    def __init__(self):
        self.ver=0
        self.flags=0
        self.len=0
        self.cmd=0
        self.appId=0
        self.HobByHop=0
        self.EndToEnd=0
        self.msg=""
    

utf8encoder=codecs.getencoder("utf_8")
utf8decoder=codecs.getdecoder("utf_8")


# Load simplified dictionary from <file>
def LoadDictionary(file):
    global dict_avps
    global dict_vendors
    global dict_commands
    global asString
    global asUTF8
    global asU32
    global asI32
    global asU64
    global asI64
    global asF32
    global asF64
    global asIPAddress
    global asIP
    global asTime
    doc = minidom.parse(file)
    node = doc.documentElement
    dict_avps = doc.getElementsByTagName("avp")
    dict_vendors = doc.getElementsByTagName("vendor")
    dict_commands=doc.getElementsByTagName("command")
    asString=["OctetString"]
    asUTF8=["UTF8String"]
    asI32=["Integer32"]
    asU32=["Unsigned32"]
    asF32=["Float32"]
    asI64=["Integer64"]
    asU64=["Unsigned64"]
    asF64=["Float64"]
    asIPAddress=["IPAddress"]
    asIP=["IP"]    
    asTime=["Time"]    
    dict_typedefs=doc.getElementsByTagName("typedef")
    for td in dict_typedefs:
        tName=td.getAttribute("name")
        tType=td.getAttribute("type")
        if tType in asString:
           asString.append(tName)
        if tType in asUTF8:
           asUTF8.append(tName)
        if tType in asU32:
           asU32.append(tName)
        if tType in asI32:
           asI32.append(tName)
        if tType in asI64:
           asI64.append(tName)    
        if tType in asU64:
           asU64.append(tName)           
        if tType in asF32:
           asF32.append(tName)           
        if tType in asF64:
           asF64.append(tName)           
        if tType in asIPAddress:
           asIPAddress.append(tName)
        if tType in asIP:
           asIP.append(tName)           
        if tType in asTime:
           asTime.append(tName)   
        
def dictAVPname2code(A,avpname,avpvalue):
    global dict_avps
    dbg="Searching dictionary for N",avpname,"V",avpvalue
    logging.debug(dbg)
    for avp in dict_avps:
        A.name = avp.getAttribute("name")
        A.code = avp.getAttribute("code")
        A.mandatory=avp.getAttribute("mandatory")
        A.type = avp.getAttribute("type")
        vId = avp.getAttribute("vendor-id")
        if avpname==A.name:
           if vId=="":
                A.vendor=0
           else:
                A.vendor=dictVENDORid2code(vId)
           return
    dbg="Searching dictionary failed for N",avpname,"V",avpvalue
    bailOut(dbg)

def dictAVPcode2name(A,avpcode,vendorcode):
    global dict_avps
    dbg="Searching dictionary for ","C",avpcode,"V",vendorcode
    logging.debug(dbg)
    A.vendor=dictVENDORcode2id(int(vendorcode))
    for avp in dict_avps:
        A.name = avp.getAttribute("name")
        A.type = avp.getAttribute("type")
        A.code = int(avp.getAttribute("code"))
        A.mandatory=avp.getAttribute("mandatory")
        vId = avp.getAttribute("vendor-id")
        if int(avpcode)==A.code:
            if vId=="":
               vId="None"
            if vId==A.vendor:
               return 
    logging.info("Unsuccessful search")
    A.code=avpcode
    A.name="Unknown Attr-"+str(A.code)+" (Vendor:"+A.vendor+")"
    A.type="OctetString"
    return 


def dictVENDORcode2id(code):
    global dict_vendors
    dbg="Searching Vendor dictionary for C",code
    logging.debug(dbg)
    for vendor in dict_vendors:
        vCode=vendor.getAttribute("code")
        vId=vendor.getAttribute("vendor-id")
        if code==int(vCode):
            return vId
    dbg="Searching Vendor dictionary failed for C",code
    bailOut(dbg)


def dictVENDORid2code(vendor_id):
    global dict_vendors
    dbg="Searching Vendor dictionary for V",vendor_id
    logging.debug(dbg)
    for vendor in dict_vendors:
        Code=vendor.getAttribute("code")
        vId=vendor.getAttribute("vendor-id")
        if vendor_id==vId:
            return int(Code)
    dbg="Searching Vendor dictionary failed for V",vendor_id
    bailOut(dbg)


def dictCOMMANDname2code(name):
    global dict_commands
    for command in dict_commands:
         cName=command.getAttribute("name")
         cCode=command.getAttribute("code")
         if cName==name:
            return int(cCode)
    dbg="Searching CMD dictionary failed for N",name
    bailOut(dbg)


def dictCOMMANDcode2name(flags,code):
    global dict_commands
    cmd=ERROR
    for command in dict_commands:
         cName=command.getAttribute("name")
         cCode=command.getAttribute("code")
         if code==int(cCode):
            cmd=cName
    if cmd==ERROR:
        return cmd
    if flags&DIAMETER_HDR_REQUEST==DIAMETER_HDR_REQUEST:
        dbg=cmd+" Request"
    else:
        dbg=cmd+" Answer"
    return dbg


def inet_pton(address_family, ip_string): 
    cp = CodecPipeline("hex")
    if address_family == socket.AF_INET:
        return socket.inet_aton(ip_string)
    elif address_family == socket.AF_INET6:
        JOKER = "*"
        while "::" in ip_string:
            ip_string = ip_string.replace("::", ":" + JOKER + ":")
        joker_pos = None
        # The last part of an IPv6 address can be an IPv4 address
        ipv4_addr = None
        if "." in ip_string:
            ipv4_addr = ip_string.split(":")[-1]
        result = ""
        parts = ip_string.split(":")
        for part in parts:
            if part == JOKER:
                if joker_pos is None:
                   joker_pos = len(result)
                else:
                   bailOut("Illegal syntax for IP address")
            elif part == ipv4_addr:
                result += socket.inet_aton(ipv4_addr)
            else:
                try:
                    result += cp.decode(part.rjust(4, "0"))
                except TypeError:
                    bailOut("Illegal syntax for IP address")
        if JOKER in ip_string:
            result = (result[:joker_pos] + "\x00" * (16 - len(result))
                      + result[joker_pos:])
        if len(result) != 16:
            bailOut("Illegal syntax for IP address")
        return result
    else:
        bailOut("Address family not supported")

def inet_ntop(address_family, packed_ip): 
    if address_family == socket.AF_INET:
        return socket.inet_ntoa(packed_ip)
    elif address_family == socket.AF_INET6:
        if len(packed_ip) != 16:
            bailOut("Illegal syntax for IP address")
        parts = []
        for left in [0, 2, 4, 6, 8, 10, 12, 14]:
            try:
                value = struct.unpack("!H", packed_ip[left:left+2])[0]
                hexstr = hex(value)[2:]
            except TypeError:
                bailOut("Illegal syntax for IP address")
            parts.append(hexstr.lstrip("0").lower())
        result = ":".join(parts)
        while ":::" in result:
            result = result.replace(":::", "::")
        if result.endswith(":") and not result.endswith("::"):
            result = result + "0"
        if result.startswith(":") and not result.startswith("::"):
            result = "0" + result
        return result
    else:
        bailOut("Address family not supported yet")

def pack_address(address):
    if address.find('.')!=ERROR:
        raw = inet_pton(socket.AF_INET,address);
        d=struct.pack('!h4s',1,raw)
        return d
    if address.find(':')!=ERROR:
        raw = inet_pton(socket.AF_INET6,address);
        d=struct.pack('!h16s',2,raw)
        return d
    dbg='Malformed IP'
    bailOut(dbg)


def decode_Integer32(data):
    cp = CodecPipeline("hex")
    ret=struct.unpack("!I",cp.decode(data))[0]
    return int(ret)

def decode_Integer64(data):
    cp = CodecPipeline("hex")
    ret=struct.unpack("!Q",cp.decode(data))[0]
    return int(ret)
  
def decode_Unsigned32(data):
    cp = CodecPipeline("hex")
    ret=struct.unpack("!I",cp.decode(data))[0]
    return int(ret)
  
def decode_Unsigned64(data):
    cp = CodecPipeline("hex")
    ret=struct.unpack("!Q",cp.decode(data))[0]
    return int(ret)

def decode_Float32(data):
    cp = CodecPipeline("hex")
    ret=struct.unpack("!f",cp.decode(data))[0]
    return ret

def decode_Float64(data):
    cp = CodecPipeline("hex")
    ret=struct.unpack("!d",cp.decode(data))[0]
    return ret
    
def decode_Address(data):
    cp = CodecPipeline("hex")
    if len(data)<=16:
        data=data[4:12]
        ret=inet_ntop(socket.AF_INET,cp.decode(data))
    else:
        data=data[4:36]    
        ret=inet_ntop(socket.AF_INET6,cp.decode(data))
    return ret

def decode_IP(data):
    cp = CodecPipeline("hex")
    if len(data)<=16:
        ret=inet_ntop(socket.AF_INET,cp.decode(data))
    else:
        ret=inet_ntop(socket.AF_INET6,cp.decode(data))
    return ret
    
def decode_OctetString(data,dlen):
    cp = CodecPipeline("hex")
    fs="!"+str(dlen-8)+"s"
    dbg="Deconding String with format:",fs
    logging.debug(dbg)
    ret=struct.unpack(fs,cp.decode(data)[0:dlen-8])[0]
    return ret

def decode_UTF8String(data,dlen):
    cp = CodecPipeline("hex")
    fs="!"+str(dlen-8)+"s"
    dbg="Decoding UTF8 format:",fs
    logging.debug(dbg)
    ret=struct.unpack(fs,cp.decode(data)[0:dlen-8])[0]
    utf8=utf8decoder(ret)
    return utf8[0]

def decode_Grouped(data):
    dbg="Decoding Grouped:"
    ret=[]
    for gmsg in splitMsgAVPs(data):
        ret.append(decodeAVP(gmsg))
    return ret

def decode_Time(data):
    cp = CodecPipeline("hex")
    seconds_between_1900_and_1970 = ((70*365)+17)*86400
    ret=struct.unpack("!I",cp.decode(data))[0]
    return int(ret)-seconds_between_1900_and_1970
    
def bailOut(msg):
    logging.error(msg)
    sys.exit(1)
    
def chop_msg(msg,size):
    return (msg[0:size],msg[size:])
    
def encode_finish(A,flags,pktlen,data):
    ret=data
    if A.vendor!=0:
       ret=("%08X" % int(A.vendor)).encode() + ret
       flags|=DIAMETER_FLAG_VENDOR
       pktlen+=4
    dbg="Packing","C:",A.code,"F:",flags,"V:",A.vendor,"L:",pktlen,"D:",ret
    logging.debug(dbg)
    x = ("%08X"%int(A.code)).encode()
    y = ("%02X"%int(flags)).encode()
    z = ("%06X"%int(pktlen)).encode()
    ret= x+y+z+ret
    return ret
    
def encode_OctetString(A,flags,data):
    fs="!"+str(len(data))+"s"
    dbg="Encoding String format:",fs
    logging.debug(dbg)
    if isinstance(data, str):
        ret=struct.pack(fs,data.encode())
    else:
        ret=struct.pack(fs,data)
    cp = CodecPipeline("hex")
    ret = cp.encode(ret)
    pktlen=8+len(ret)/2
    return encode_finish(A,flags,pktlen,ret)

def encode_UTF8String(A,flags,data):
    utf8data=utf8encoder(data)[0]
    fs="!"+str(len(utf8data))+"s"
    dbg="Encoding UTF8",utf8data,"L",len(utf8data),"F",fs
    logging.debug(dbg)
    ret=struct.pack(fs,utf8data)
    cp = CodecPipeline("hex")
    ret = cp.encode(ret)
    pktlen=8+len(ret)/2
    return encode_finish(A,flags,pktlen,ret)
    
def encode_Integer32(A,flags,data):
    r=struct.pack("!I",data)
    cp = CodecPipeline("hex")
    ret = cp.encode(r)
    pktlen=12
    return encode_finish(A,flags,pktlen,ret)

def encode_Unsigned32(A,flags,data):
    r=struct.pack("!I",int(data))
    cp = CodecPipeline("hex")
    ret = cp.encode(r)
    pktlen=12
    return encode_finish(A,flags,pktlen,ret)

def encode_Float32(A,flags,data):
    ret=struct.pack("!f",data)
    cp = CodecPipeline("hex")
    ret = cp.encode(ret)
    pktlen=12
    return encode_finish(A,flags,pktlen,ret)
    
def encode_Integer64(A,flags,data):
    ret=struct.pack("!Q",data)
    cp = CodecPipeline("hex")
    ret = cp.encode(ret)
    pktlen=16
    return encode_finish(A,flags,pktlen,ret)

def encode_Unsigned64(A,flags,data):
    ret=struct.pack("!Q",data)
    cp = CodecPipeline("hex")
    ret = cp.encode(ret)
    pktlen=16
    return encode_finish(A,flags,pktlen,ret)

def encode_Float64(A,flags,data):
    ret=struct.pack("!d",data)
    cp = CodecPipeline("hex")
    ret = cp.encode(ret)
    pktlen=16
    return encode_finish(A,flags,pktlen,ret)

def encode_Address(A,flags,data):
    ret=pack_address(data)
    cp = CodecPipeline("hex")
    ret = cp.encode(ret)
    pktlen=8+len(ret)/2
    return encode_finish(A,flags,pktlen,ret)
    
def encode_IP(A,flags,data):
    ret=pack_address(data)
    cp = CodecPipeline("hex")
    ret = cp.encode(ret)[4:]
#   ret=pack_address(data).encode("hex")[4:]
    pktlen=8+len(ret)/2
    return encode_finish(A,flags,pktlen,ret)    

def encode_Enumerated(A,flags,data):
    global dict_avps
    if isinstance(data,str):
        for avp in dict_avps:
            Name = avp.getAttribute("name")
            if Name==A.name:
                for e in avp.getElementsByTagName("enum"):
                    if data==e.getAttribute("name"):
                        return encode_Integer32(A,flags,int(e.getAttribute("code")))
                dbg="Enum name=",data,"not found for AVP",A.name
                bailOut(dbg)
    else:
        return encode_Integer32(A,flags,data)
    
def encode_Time(A,flags,data):
    seconds_between_1900_and_1970 = ((70*365)+17)*86400 
    r=struct.pack("!I",int(data)+seconds_between_1900_and_1970)
    cp = CodecPipeline("hex")
    ret = cp.encode(r)    
#    ret=r.encode("hex")
    pktlen=12
    return encode_finish(A,flags,pktlen,ret)


def checkMandatory(mandatory):
    flags=0
    if mandatory=="must":
        flags|=DIAMETER_FLAG_MANDATORY
    return flags
    
def do_encode(A,flags,data):
    if A.type in asUTF8:
        return encode_UTF8String(A,flags,data)
    if A.type in asI32:
        return encode_Integer32(A,flags,data)
    if A.type in asU32:
        return encode_Unsigned32(A,flags,data)
    if A.type in asI64:
        return encode_Integer64(A,flags,data)
    if A.type in asU64:
        return encode_Unsigned64(A,flags,data)
    if A.type in asF32:
        return encode_Float32(A,flags,data)
    if A.type in asF64:
        return encode_Float64(A,flags,data)
    if A.type in asIPAddress:
        return encode_Address(A,flags,data)
    if A.type in asIP:
        return encode_IP(A,flags,data)        
    if A.type in asTime:
        return encode_Time(A,flags,data)
    if A.type=="Enumerated":
        return encode_Enumerated(A,flags,data)
    # default is OctetString  
    return encode_OctetString(A,flags,data) 

def getAVPDef(AVP_Name,AVP_Value):
    A=AVPItem()
    dictAVPname2code(A,AVP_Name,AVP_Value)
    if A.name=="":
       logging.error("AVP with that name not found")
       return ""
    if A.code==0:
       logging.error("AVP Code not found")
       return ""
    if A.type=="":
       logging.error("AVP type not defined")
       return ""
    if A.vendor<0:
       logging.error("Vendor ID does not match")
       return ""
    else:
        data=AVP_Value
    dbg="AVP dictionary def","N",A.name,"C",A.code,"M",A.mandatory,"T",A.type,"V",A.vendor,"D",data
    logging.debug(dbg)
    flags=checkMandatory(A.mandatory)
    return do_encode(A,flags,data)

def encodeAVP(AVP_Name,AVP_Value):
    cp = CodecPipeline("hex")
    if type(AVP_Value).__name__=='list':
        p=''.encode()
        for x in AVP_Value:
            while len(x)/2<calc_padding(len(x)/2):
                x=x+'00'.encode()
            p=p+x
        xp = cp.decode(p)
        msg=getAVPDef(AVP_Name,xp)
    else:
        msg=getAVPDef(AVP_Name,AVP_Value)
    dbg="AVP",AVP_Name,AVP_Value,"Encoded as:",msg
    logging.info(dbg)
    return msg

def calc_padding(msg_len):
    return (int(msg_len)+3)&~3 

def decodeAVP(msg):
    cp = CodecPipeline("hex")
    (scode,msg)=chop_msg(msg,8)
    (sflag,msg)=chop_msg(msg,2)
    (slen,msg)=chop_msg(msg,6)
    dbg="Decoding ","C",scode,"F",sflag,"L",slen,"D",msg
    logging.debug(dbg)
    mcode=struct.unpack("!I",cp.decode(scode))[0]
    mflags=ord(cp.decode(sflag))
    data_len=struct.unpack("!I","\00".encode()+cp.decode(slen))[0]
    mvid=0
    if mflags & DIAMETER_FLAG_VENDOR:
        (svid,msg)=chop_msg(msg,8)
        mvid=struct.unpack("!I",cp.decode(svid))[0]
        data_len-=4
    A=AVPItem()
    dictAVPcode2name(A,mcode,mvid)
    dbg="Read","N",A.name,"T",A.type,"C",A.code,"F",mflags,"L",data_len,"V",A.vendor,mvid,"D",msg
    logging.debug(dbg)
    ret=""
    decoded=False
    if A.type in asI32:
        logging.debug("Decoding Integer32")
        ret= decode_Integer32(msg)
        decoded=True
    if A.type in asI64:
        decoded=True
        logging.debug("Decoding Integer64")
        ret= decode_Integer64(msg)
    if A.type in asU32:
        decoded=True
        logging.debug("Decoding Unsigned32")
        ret= decode_Unsigned32(msg)
    if A.type in asU64:
        decoded=True
        logging.debug("Decoding Unsigned64")
        ret= decode_Unsigned64(msg)
    if A.type in asF32:
        decoded=True
        logging.debug("Decoding Float32")
        ret= decode_Float32(msg)
    if A.type in asF64:
        decoded=True
        logging.debug("Decoding Float64")
        ret= decode_Float64(msg)        
    if A.type in asUTF8:
        decoded=True
        logging.debug("Decoding UTF8String")
        ret= decode_UTF8String(msg,data_len)
    if A.type in asIPAddress:
        decoded=True
        logging.debug("Decoding IPAddress")
        ret= decode_Address(msg)
    if A.type in asIP:
        decoded=True
        logging.debug("Decoding IP")
        ret= decode_IP(msg)        
    if A.type in asTime:
        decoded=True
        logging.debug("Decoding Time")
        ret= decode_Time(msg)
    if A.type=="Grouped":
        decoded=True
        logging.debug("Decoding Grouped")
        ret= decode_Grouped(msg)
    if not decoded:
      logging.debug("Decoding OctetString")
      ret= decode_OctetString(msg,data_len)
    dbg="Decoded as",A.name,ret
    logging.info(dbg)
    return (A.name,ret)

def findAVP(what,list):
    for avp in list:
        if isinstance(avp,tuple):
           (Name,Value)=avp
        else:
           (Name,Value)=decodeAVP(avp)
        if Name==what:
           return Value
    return ERROR
    

def joinAVPs(avps):
    data="".encode()
    for avp in avps:
        while len(avp)/2<calc_padding(len(avp)/2):
            avp=avp+"00".encode()
        data=data+avp
    return data

def setFlags(H,flag):
    H.flags|=flag
    return

def createReq(H,avps):
    H.flags|=DIAMETER_HDR_REQUEST
    return createRes(H,avps)

def createRes(H,avps):
    data=joinAVPs(avps)
    H.len=len(data)/2+20
    ret="01"+"%06X" % int(H.len)+"%02X"%int(H.flags) + "%06X"%int(H.cmd)
    x = ("%08X"%int(H.appId)).encode()
    y = ("%08X"%int(H.HopByHop)).encode()
    z = ("%08X"%int(H.EndToEnd)).encode()
    ret=ret.encode()+ x+ y+ z+data
    dbg="Header fields","L",H.len,"F",H.flags,"C",H.cmd,"A",H.appId,"H",H.HopByHop,"E",H.EndToEnd
    logging.debug(dbg)
    dbg="Diameter hdr+data",ret
    logging.debug(dbg)
    return ret

def initializeHops(H):
    try:
        initializeHops.Hop_by_Hop+=1
        initializeHops.End_to_End+=1
    except:
        initializeHops.Hop_by_Hop=int(time.time())
        initializeHops.End_to_End=(initializeHops.Hop_by_Hop%32768)*32768
    H.HopByHop=initializeHops.Hop_by_Hop
    H.EndToEnd=initializeHops.End_to_End
    return 
    
def stripHdr(H,msg):
    dbg="Incoming Diameter msg",msg
    logging.info(dbg)
    if len(msg)==0:
        return ERROR
    (sver,msg)=chop_msg(msg,2)
    (slen,msg)=chop_msg(msg,6)
    (sflag,msg)=chop_msg(msg,2)
    (scode,msg)=chop_msg(msg,6)
    (sapp,msg)=chop_msg(msg,8)
    (shbh,msg)=chop_msg(msg,8)
    (sete,msg)=chop_msg(msg,8)
    dbg="Split hdr","V",sver,"L",slen,"F",sflag,"C",scode,"A",sapp,"H",shbh,"E",sete,"D",msg
    logging.debug(dbg)
    cp = CodecPipeline("hex")
    
    H.ver=ord(cp.decode(sver))
    H.flags=ord(cp.decode(sflag))
    H.len=struct.unpack("!I","\00".encode()+cp.decode(slen))[0]
    H.cmd=struct.unpack("!I","\00".encode()+cp.decode(scode))[0]
    H.appId=struct.unpack("!I",cp.decode(sapp))[0]
    H.HopByHop=struct.unpack("!I",cp.decode(shbh))[0]
    H.EndToEnd=struct.unpack("!I",cp.decode(sete))[0]
    dbg="Read","V",H.ver,"L",H.len,"F",H.flags,"C",H.cmd,"A",H.appId,"H",H.HopByHop,"E",H.EndToEnd
    logging.debug(dbg)
    dbg=dictCOMMANDcode2name(H.flags,H.cmd)
    logging.info(dbg)
    H.msg=msg
    return 

def splitMsgAVPs(msg):
    cp = CodecPipeline("hex")
    ret=[]
    dbg="Incoming avps",msg
    logging.debug(dbg)
    while len(msg)!=0:
      slen="00".encode()+msg[10:16]
      mlen=struct.unpack("!I",cp.decode(slen))[0]
      plen=calc_padding(mlen)
      (avp,msg)=chop_msg(msg,2*plen)
      dbg="Single AVP","L",mlen,plen,"D",avp
      logging.info(dbg)
      ret.append(avp)
    return ret

def Connect(host,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock
    

def getCurrentDateTime():
    t=time.localtime()
    return t.tm_year,t.tm_mon,t.tm_mday,t.tm_hour,t.tm_min,t.tm_sec

def epoch2date(sec):
    t=time.localtime(sec)
    return t.tm_year,t.tm_mon,t.tm_mday,t.tm_hour,t.tm_min,t.tm_sec

def date2epoch(tYear,tMon,tDate,tHr,tMin,tSec):  
    t=time.strptime("{0} {1} {2} {3} {4} {5}".format(tYear,tMon,tDate,tHr,tMin,tSec),"%Y %m %d %H %M %S")
    return time.mktime(t)    


