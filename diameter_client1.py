#!/usr/bin/python

##################################################################
# Copyright (c) 2021, Mostafa Elyasi <mostafa.elyasi@gmail.com>
# January 2020
# Version 0.1, Last change on January 20, 2020   
# This software is distributed under the terms of BSD license.    
##################################################################
# Client for diameter accounting
# Each time granted 30seconds for call
# Python version: 3
# Request types : 1-init 2-update 3-terminate 4-event

from libDiameter import *
import datetime
import time
import sys


import codecs
class CodecPipeline(object):
    """Chains multiple codecs into a single encode/decode operation"""
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



def create_CCR():
    # Let's build Request
    now=datetime.datetime.now()
    Event_Time=time.time()
    REQ_avps=[]    
    REQ_avps.append(encodeAVP("Session-Id", SID))
    REQ_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    REQ_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    REQ_avps.append(encodeAVP("Destination-Realm", DEST_REALM))
    REQ_avps.append(encodeAVP("Destination-Host", DEST_HOST))
    REQ_avps.append(encodeAVP("Auth-Application-Id",4))
    REQ_avps.append(encodeAVP("Service-Context-Id", SCID))
    REQ_avps.append(encodeAVP("Service-Information",[encodeAVP("IMS-Information",[encodeAVP("Calling-Party-Address",Calling_Num),encodeAVP("Called-Party-Address",Called_Num) ]),encodeAVP("PS-Information",[encodeAVP("3GPP-MS-TimeZone","4000")])] ))
    REQ_avps.append(encodeAVP("CC-Request-Type", Req_Type)) 
    REQ_avps.append(encodeAVP("CC-Request-Number", 0))
    REQ_avps.append(encodeAVP("Event-Timestamp",Event_Time))
    REQ_avps.append(encodeAVP("Subscription-Id",[encodeAVP("Subscription-Id-Type",0 ),encodeAVP("Subscription-Id-Data",Calling_Num) ]))
    REQ_avps.append(encodeAVP("Multiple-Services-Indicator", 1))
    REQ_avps.append(encodeAVP("Multiple-Services-Credit-Control",[encodeAVP("Used-Service-Unit",[encodeAVP("CC-Time",ucctime)]),encodeAVP("Requested-Service-Unit",[encodeAVP("CC-Time",rcctime) ]),encodeAVP("Service-Identifier", 1000),encodeAVP("Rating-Group", 100)]))
    REQ_avps.append(encodeAVP("Requested-Action",0))
    REQ=HDRItem()
    REQ.cmd=dictCOMMANDname2code("Credit-Control")
    initializeHops(REQ)
    msg=createReq(REQ,REQ_avps)
    return msg


def create_Session_Id():
    print("Start to generate SID")
    now=datetime.datetime.now()
    ret=ORIGIN_HOST+";"
    ret=ret+str(now.year)[2:4]+"%02d"%now.month+"%02d"%now.day
    ret=ret+"%02d"%now.hour+"%02d"%now.minute+";"
    ret=ret+"%02d"%now.second+str(now.microsecond)+";"
    ret=ret+IDENTITY[2:16]
    return ret


def create_Disconnect():
    now=datetime.datetime.now()
    Event_Time=time.time()
    STR_avps=[]
    STR_avps.append(encodeAVP("Session-Id", SID))
    STR_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    STR_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    STR_avps.append(encodeAVP("Destination-Realm", DEST_REALM))
    STR_avps.append(encodeAVP("Destination-Host", DEST_HOST))
    STR_avps.append(encodeAVP("Auth-Application-Id", APPLICATION_ID))
    STR_avps.append(encodeAVP("Service-Context-Id", SCID))
    STR_avps.append(encodeAVP("Service-Information",[encodeAVP("IMS-Information",[encodeAVP("Calling-Party-Address",Calling_Num),encodeAVP("Called-Party-Address",Called_Num) ]),encodeAVP("PS-Information",[encodeAVP("3GPP-MS-TimeZone","4000")])] ))
    STR_avps.append(encodeAVP("CC-Request-Type", Req_Type))
    STR_avps.append(encodeAVP("CC-Request-Number",Req_Num))
    STR_avps.append(encodeAVP("Event-Timestamp",Event_Time))
    STR_avps.append(encodeAVP("Subscription-Id",[encodeAVP("Subscription-Id-Type",0 ),encodeAVP("Subscription-Id-Data",Calling_Num) ]))
    STR_avps.append(encodeAVP("Multiple-Services-Indicator", 1))
    STR_avps.append(encodeAVP("Multiple-Services-Credit-Control",[encodeAVP("Used-Service-Unit",[encodeAVP("CC-Time",ucctime)]),encodeAVP("Requested-Service-Unit",[encodeAVP("CC-Time",rcctime) ]),encodeAVP("Service-Identifier", 1000),encodeAVP("Rating-Group", 100)]))
    STR_avps.append(encodeAVP("Termination-Cause", 1))
    STR=HDRItem()
    STR.cmd=dictCOMMANDname2code("Credit-Control")
    STR.appId=APPLICATION_ID
    initializeHops(STR)
    msg=createReq(STR,STR_avps)
    print("Finish Disconnet")
    return msg


if __name__ == '__main__':
    Called_Num  = "4545454"
    Calling_Num = "4545455"
    HOST="x.x.x.x" # Host IP address or hostname
    PORT=3868
    ORIGIN_HOST="y.y.y.y" # Origin IP address or hostname
    ORIGIN_REALM="realm.y.y.y.y"
    LoadDictionary("dictDiameter.xml")
    DEST_REALM="realm.domain.com"
    DEST_HOST="x.x.x.x"
    SCID = Calling_Num + "@3gpp.org"
    now=datetime.datetime.now()
    Event_Time=time.time()
    ORIGIN_ID=str(now.microsecond)
    IDENTITY="4545455"
    APPLICATION_ID=4 #16777250
    MSG_SIZE=4096
    # Create unique session ID
    SID=create_Session_Id()
    # Connect to server     
    Conn=Connect(HOST,PORT)
    print("Successfuly connected")
    ###########################################################
    # 1- initiation
    rcctime=60
    ucctime=0
    Req_Type = 1
    msg=create_CCR()
    logging.debug("+"*30)

    cp = CodecPipeline("hex")
    x = cp.decode(msg)    

    Conn.send(x)
    print("data sent and try to receive first result")
    received = Conn.recv(MSG_SIZE)
    CEA=HDRItem()
    y = cp.encode(received)
    stripHdr(CEA,y)
    Capabilities_avps=splitMsgAVPs(CEA.msg)
    granted = findAVP("Multiple-Services-Credit-Control",Capabilities_avps)
    print(granted)
    ###########################################################
    # 2- Update
    remaining_balance = findAVP("Remaining-Balance",Capabilities_avps)[0][1][0][1]
    print("Remaining Balance:"+str(remaining_balance))
    Req_Type = 2
    ckeck_conn = True
    remained_time = True
    x = 2
    y = 0
    if granted[0][1] < 4013 and granted[0][1] > 4009:
        ckeck_conn = False
        print(" User Not allowed to call")
        remained_time = False
    else:
        rcctime = granted[1][1][0][1]
    while ckeck_conn:
        if y >= x or granted[1][1][0][1] <10:
            remained_time = False
            break
        msg=create_CCR()
        logging.debug("+"*30)
        Conn.send(cp.decode(msg))
        received = Conn.recv(MSG_SIZE)
        CEA=HDRItem()
        stripHdr(CEA,cp.encode(received))
        Capabilities_avps=splitMsgAVPs(CEA.msg)
        granted = findAVP("Multiple-Services-Credit-Control",Capabilities_avps)
        if granted and granted[0][1] < 4013 and granted[0][1] > 4009:
            remained_time = False
            print("Credit limit exceeded")
            break
        gcct = "\nServer result code is:"+str(granted[0][1])+" with "+str(y)+" minutes used and "+str(granted[1][1][0][1])+" second granted. \n"
        print(gcct)
        DEST_HOST=findAVP("Origin-Host",Capabilities_avps)
        DEST_REALM=findAVP("Origin-Realm",Capabilities_avps)
        ucctime = rcctime
        if (remaining_balance - y*60) < 30:
            rcctime = remaining_balance - y*60
            ucctime = rcctime
            remained_time = False
        else:
            rcctime = granted[1][1][0][1]
        ntime = rcctime #- 2
        y = y + 1
        time.sleep(ntime)
        #Check connection state here
    ###########################################################
    # Last update
    remaining_time = 46
    if remained_time:
        print("release remaining time"+str(remaining_time))
        ucctime = (60 - remaining_time)/2
        rcctime = 0
        msg=create_CCR()
        logging.debug("+"*30)
        Conn.send(cp.decode(msg))
        received = Conn.recv(MSG_SIZE)
    ###########################################################
    # 3- Disconnect
    Req_Type = 3    
    Req_Num  = 3
    msg=create_Disconnect()
    logging.debug("-"*30)
    Conn.send(cp.decode(msg))
    received = Conn.recv(MSG_SIZE)
    DIS=HDRItem()
    stripHdr(DIS,cp.encode(received))
    Capabilities_avps=splitMsgAVPs(DIS.msg)
    print(findAVP("Result-Code",Capabilities_avps))
    ###########################################################
    # Close Connection
    Conn.close()

