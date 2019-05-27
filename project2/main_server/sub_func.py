# multichain-util create chaindemo
# multichaind chaindemo -daemon
# multichain-cli chaindemo create stream DATA true
# multichain-cli chaindemo create stream PUBKEY true
# multichain-cli chaindemo create stream REQUEST true

import os
import sys
import subprocess
import json
import binascii 
import socket 
import string 
import Crypto
import ast
import copy
import time 
import shutil
import pyAesCrypt
import codecs
import hashlib
import numpy as np
from Savoir import Savoir
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random

BLOCKSIZE = 65536
hasher = hashlib.sha1()
kilobytes = 1024
megabytes = kilobytes * 1000
chunksize = int(10 * megabytes) 
MAX_SIZE_ALLOW = 200*megabytes
readsize = 1024    
#CRPATH = Path(__file__).resolve().parent.__str__()
CRPATH = '/home/thanhtrang/Documents/project_multichain_demo/'
PATH_CURRENT_FILE = os.path.join(CRPATH,'data')
FILE_LIST_USERS_INFO = os.path.join(CRPATH,'userinfo.json') 
RSAKEYLENGTH = 1024
CRYPT_BUFFER_SIZE = 64 * 1024
MAX_DATA_PER_ITEM = 1048576
NUM_ITEMS_PER_GET_FROM_STREAM = 100
KEY_REQUEST_CERT = 'REQUEST_CERT' 
KEY_REQUEST_SER = 'REQUEST_SER' 
KEY_CERT_PROVIDER = 'CERT_PROVIDER'
KEY_SER_PROVIDER = 'SER_PROVIDER'
KEY_STORJ_INFO = 'STORJ_INFO'
STREAM_DATA = 'DATA' # noi de dang file
STREAM_REQUEST = 'REQUEST' # noi de dang cac require 
STREAM_PUBKEY = 'PUBKEY' # noi dang cac publish key
chain_name = 'chaindemo' # ten chain
rpchost = 'localhost'   # 
ip_address = '10.10.221.103'  # ip connect cua server tao ra chain_name
port_connect = '6491'          # port connect cua server tao ra chain_name 
str_rpc_default_host = 'default-rpc-port'
#####################################
if not os.path.exists(PATH_CURRENT_FILE): # tao path dir data de luu tru file tam thoi                  
        os.mkdir(PATH_CURRENT_FILE)         
#####################################   


# user -> sp1: yeu cau cap chung chi
# User_info:  
# SP_info: 
# return: 
# def request_Cert(User_info,SP_info, type_of_Cert)
# def provide_Cert(User_info,type_of_Cert):
# def up_Cert_to_Cloud(User_info,Cert_path,cloud_info)
# def request_Ser(User_info,SP_info,type_of_Cert,link_to_Cert,cloud_info)
# def get_Cert_from_Cloud(User_info,path,cloud_info)
# def get_PubKey(SP_info)
# def ver_Cert(Cert,Key,info)
# def accept_or_deny(User_info)
#####################################
def getAPI(): 
    if (os.path.isfile(os.path.expanduser('~/.multichain/'+chain_name+'/params.dat'))) == False:
        with subprocess.Popen(['multichaind',chain_name+'@'+ip_address+':'+port_connect]) as p:
            try:
                p.wait(timeout=10) 
            except:
                p.kill()
                p.wait() 
    rpc_info = {}
    with open(os.path.expanduser('~/.multichain/'+chain_name+'/multichain.conf')) as f:
        for line in f:
            line = line.rstrip('\n')
            (key,val) = line.split('=')
            rpc_info[key] = val  

    with open(os.path.expanduser('~/.multichain/'+chain_name+'/params.dat')) as f:
        for line in f:
            line = line.rstrip('\n')
            if(str_rpc_default_host in line):
                tline = line.split(' ')
                rpc_info[tline[0]] = tline[2]

    #print(rpc_info)
    rpcuser = rpc_info['rpcuser']
    rpcpasswd = rpc_info['rpcpassword']
    rpcport = rpc_info['default-rpc-port']
    api = Savoir(rpcuser, rpcpasswd, rpchost, rpcport, chain_name)
    try :
        api.help()
    except:#kiem tra node da chay chua
        subprocess.call(['multichaind',chain_name,'-daemon'])
    return api
api = getAPI()

#####################################

def getStreamName():
    a = api.liststreams()
    name_stream = list(t['name'] for t in a)
    #print(name_stream)
    api.subscribe(name_stream)
    return name_stream
#####################################
getStreamName()
def getMyaddress():    
    return api.getaddresses()[0]
#####################################
def checkPermission():
    list_pe = api.listpermissions()
    for p in list_pe:
        if getMyaddress() in p['address']:
            return True
    return False
#####################################
def send_address_for_granting_permission(ip_address,port_connect):
    BUFFER_SIZE = 1024 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip_address, int(port_connect)-1))
    s.send(bytes(getMyaddress(), "utf-8"))
    data = 0
    data = data + int.from_bytes(s.recv(BUFFER_SIZE),"big")
    s.close()
    #print(data)
    #print(int.from_bytes(data,"big"))
    return data
######################################
def getStorjKeyAndBucket():
    tx = api.liststreamkeyitems(STREAM_DATA,KEY_STORJ_INFO,False,NUM_ITEMS_PER_GET_FROM_STREAM)
    tx.reverse()
    for t in tx:
        if set(getMyaddress()).issubset(t['keys']):
            return t['data']['json']
######################################
def getListCertProviders():
    list_addr = api.liststreamkeyitems(STREAM_PUBKEY,KEY_CERT_PROVIDER,False,NUM_ITEMS_PER_GET_FROM_STREAM)
    list_addr.reverse()
    a = []
    for ad in list_addr:
        b = {}
        b['publisher'] = ad['publishers'][0]
        b['info'] = ad['keys']
        if any(e['info'] == b['info']  for e in a):
            continue
        b['pubkey'] = bytes.fromhex(ad['data']).decode('utf-8')
        a.append(b)

    return a
#########################################
def getListSerProviders():
    list_addr = api.liststreamkeyitems(STREAM_PUBKEY,KEY_SER_PROVIDER,False,NUM_ITEMS_PER_GET_FROM_STREAM)
    list_addr.reverse()
    a = []
    for ad in list_addr:
        b = {}
        b['publisher'] = ad['publishers'][0]
        b['info'] = ad['keys']
        if any(e['info'] == b['info']  for e in a):
            continue
        b['pubkey'] = bytes.fromhex(ad['data']).decode('utf-8')
        a.append(b)

    return a
#########################################
#########################################
# SP_info = ['HCMUS','IT']
def getCPPubKey(CP_info):
    l = getListCertProviders()
    for i in l:
        if(all(elem in i['info']  for elem in CP_info)):
            return RSA.importKey(i['pubkey'])
#####################################
# SP_info = ['VNG']
def getSPPubKey(SP_info):
    l = getListSerProviders()
    for i in l:
        if(all(elem in i['info']  for elem in SP_info)):
            return RSA.importKey(i['pubkey'])
####################################
# User_info : encrypted 'ab123ab324df23afc2fc8...'
# key = 'REQUEST_CERT', 'HCMUS', 'IT' ...., 'checked','uploaded', 'link...'
# key = 'REQUEST_CERT', 'HCMUS', 'IT' ...., ,'checked','denied'
def checkReQuestCertStatus(CP_info,en_user_info,type_of_cert): 
    tx = api.liststreamkeyitems(STREAM_REQUEST,KEY_REQUEST_CERT,False,NUM_ITEMS_PER_GET_FROM_STREAM)
    tx.reverse()
    for t in tx:
        if set(CP_info).issubset(t['keys']):
            if en_user_info == t['data']['json']['user_info'] and type_of_cert == t['data']['json']['type_of_cert']: 
                if 'checked' in t['keys']:
                    if 'uploaded' in t['keys'] : 
                        return 1,t['txid'] # file dc dong y 
                    else:
                        return 2,t['txid'] # file bi tu choi  
                else:
                    return 0,t['txid']# file chua duoc check
    return -1, None # khong co file

#######################################
def checkReQuestSerStatus(SP_info,en_info_user,type_of_ser): 
    tx = api.liststreamkeyitems(STREAM_REQUEST,KEY_REQUEST_SER,False,NUM_ITEMS_PER_GET_FROM_STREAM)
    tx.reverse()
    for t in tx:
        if set(SP_info).issubset(t['keys']):
            if en_info_user == t['data']['json']['user_info'] and type_of_ser == t['data']['json']['type_of_ser']: 
                if 'checked' in t['keys']:
                    if 'uploaded' in t['keys'] : 
                        return 1,t['txid'] # file dc dong y 
                    else:
                        return 2,t['txid'] # file bi tu choi  
                else:
                    return 0,t['txid']# file chua duoc check
    return -1 # khong co file
#####################################
##############################
def genRsaKey():
    random_generator = Random.new().read
    RSAKEY = RSA.generate(RSAKEYLENGTH, random_generator) #generate pub and priv key
    f = open(os.path.join(CRPATH, 'my_rsa_public.pem'), 'wb')
    f.write(RSAKEY.publickey().exportKey('PEM'))
    f.close()
    f = open(os.path.join(CRPATH,'my_rsa_private.pem'), 'wb')
    f.write(RSAKEY.exportKey('PEM'))
    f.close()  
############################### 
def getMyPupKey():
    pubkeypath = os.path.join(CRPATH,'my_rsa_public.pem')
    #prikeypath = os.path.join(CRPATH,'my_rsa_private.pem')
    if not os.path.isfile(pubkeypath): 
        genRsaKey()
    fpub = open(pubkeypath, 'rb') 
    pub_key = (fpub.read()) 
    return pub_key
#####################################

####################################
def encrypt(message):
    f = open(os.path.join(CRPATH, 'my_rsa_public.pem'), 'rb')
    pub_key = RSA.importKey(f.read())
    #return tuple(bytes.fromhex(info['user']))
    #print((bytes.fromhex(info['user'])),)
    de_mess = pub_key.encrypt(message.encode('utf-8'),32)[0].hex()
    return de_mess
####################################
def decrypt(message):
    f = open(os.path.join(CRPATH, 'my_rsa_private.pem'), 'rb')
    pri_key = RSA.importKey(f.read())
    #return tuple(bytes.fromhex(info['user']))
    #print((bytes.fromhex(info['user'])),)
    de_mess = pri_key.decrypt((bytes.fromhex(message),)).decode("utf-8")
    return de_mess
####################################
####################################
# def sign(message):
#     digest = SHA256.new()
#     digest.update(message)

#     f = open(os.path.join(CRPATH, 'my_rsa_private.pem'), 'rb')
#     pri_key = RSA.importKey(f.read())
#     #return tuple(bytes.fromhex(info['user']))
#     #print((bytes.fromhex(info['user'])),)
#     #de_mess = pri_key.encrypt((bytes.fromhex(message),)).decode("utf-8")
#     signer = PKCS1_v1_5.new(pri_key)
#     sig = signer.sign(digest)

#     return sig
# ####################################
# #
# def verify(Cert,pubkey):
#     cert = Cert['cert']

#     digest = SHA256.new()
#     digest.update(cert.encode('utf-8'))

#     verifier = PKCS1_v1_5.new(pubkey)
#     verified = verifier.verify(digest,bytes.fromhex(Cert['signature']))
#     return verified

