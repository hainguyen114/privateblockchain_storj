# import os
# import sys
# from Savoir import Savoir
# import subprocess
# import json
# import binascii 
# import socket
# ## tao server ban dau de tao chain 
# # multichain-util create chaindemo
# # multichaind chaindemo -daemon
# # tao 3 stream de chuyen file
# #  multichain-cli chaindemo create stream requires true
# #  multichain-cli chaindemo create stream data true
# #  multichain-cli chaindemo create stream pubkey true
# MAX_DATA_PER_ITEM = 1048576
# KEY_UP = 'Uploadrequest' 
# STREAM_DATA = 'data' # noi de dang file
# STREAM_REQUEST = 'requires' # noi de dang cac require
# STREAM_pubkey = 'pubkey' # noi dang cac publish key
# chain_name = 'chaindemo' # ten chain
# rpchost = 'localhost'   # 
# ip_address = '10.10.98.75'  # ip connect cua server tao ra chain_name
# port_connect = '7739'          # port connect cua server tao ra chain_name 


# str_rpc_default_host = 'default-rpc-port'
# if (os.path.isfile(os.path.expanduser('~/.multichain/'+chain_name+'/params.dat'))) == False:
#     with subprocess.Popen(['multichaind',chain_name+'@'+ip_address+':'+port_connect]) as p:
#         try:
#             p.wait(timeout=2) 
#         except:
#             p.kill()
#             p.wait() 
# rpc_info = {}
# with open(os.path.expanduser('~/.multichain/'+chain_name+'/multichain.conf')) as f:
#     for line in f:
#         line = line.rstrip('\n')
#         (key,val) = line.split('=')
#         rpc_info[key] = val  

# with open(os.path.expanduser('~/.multichain/'+chain_name+'/params.dat')) as f:
#     for line in f:
#         line = line.rstrip('\n')
#         if(str_rpc_default_host in line):
#             tline = line.split(' ')
#             rpc_info[tline[0]] = tline[2]

# print(rpc_info)
# rpcuser = rpc_info['rpcuser']
# rpcpasswd = rpc_info['rpcpassword']
# rpcport = rpc_info['default-rpc-port']
# api = Savoir(rpcuser, rpcpasswd, rpchost, rpcport, chain_name)

# try :
#     api.help()
# except:#kiem tra node da chay chua
#     subprocess.call(['multichaind',chain_name,'-daemon'])

# a = api.liststreams()

# name_stream = list(t['name'] for t in a)
# print(name_stream)
# api.subscribe(name_stream)

# myaddress = api.getaddresses()[0]
# print(myaddress)
# #############################################################
# # can send dia chi cho server cap quyen
# # ten server ban dau tao chain : multichain-cli chain1 grant [dia chi] connect
# # truyen vao address va port cua server co quyen cap quyen connect cho
# # def send_address_for_granting_permission(ip_address,port_connect):
# #     BUFFER_SIZE = 1024 
# #     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# #     s.connect((ip_address, int(port_connect)))
# #     s.send(bytes(myaddress, "utf-8"))
# #     data = 0
# #     data = data + int.from_bytes(s.recv(BUFFER_SIZE),"big")
# #     s.close()
# #     #print(data)
# #     #print(int.from_bytes(data,"big"))
# #     return data
# # print(send_address_for_granting_permission(ip_address,port_connect))
# # api.listpermissions()
# #############################################################
# ## source code cua ben server tao node de nhan address message
# #import socket
# #import subprocess
# #import socket
# TCP_IP = '10.10.98.75'
# TCP_PORT = 7739
# BUFFER_SIZE = 1024  

# # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# # s.bind((TCP_IP, TCP_PORT))
# # a = s.listen(5)
# # print(a)
# # i = 5
# # while i>0:
# #     out = ''
# #     conn, addr = s.accept()
# #     print(' address:',addr)
# #     data = conn.recv(BUFFER_SIZE)
# #     if not data: 
# #         conn.send(bytes([0]))
# #         break
# #     out = out + data.decode('utf-8')
# #     print(out)
# #     conn.send(bytes([1]))  # echo
# #     i= i-1
# # conn.close()
# ######################################3

# def upfile(path, info):
#     with open(path,'rb') as f:
#         content = f.read().hex()
#         size = len(bytearray.fromhex(content))
#         #if(size >= MAX_DATA_PER_ITEM):
#         key = [KEY_UP] 
#         key.append(info)
#         tx = api.publish(STREAM_REQUEST,key,content,'offchain')
#         return tx 
#         #return key

# def get_data_transaction(type_of_tx,key):
#     out = []
#     if(type_of_tx == KEY_UP ):
#         tx = api.liststreamkeyitems(STREAM_REQUEST,type_of_tx)
#         for o in tx:
#             if(all(elem in o['keys']  for elem in key)):
#                 out.append(o['data'])
#     return out        
# def get_fulldata(data):
#     txout_data = api.gettxoutdata(data['txid'],data['vout'])
#     return txout_data

# def dow_file(path,info):
#     data = get_data_transaction(KEY_UP,info)
#     # gia su chi co 1 file  duy nhat co key
#     output = get_fulldata(data[0])
#     with open(path, 'wb') as f:
#         #for i in output:
#         f.write(bytearray.fromhex(output))

# filename = '/home/hainguyen/Documents/hai'
# upfile(filename,'hai')
# ##############################################################
# #  node b

# # new_path = '/home/hainguyen/Desktop/gh'
# # dow_file(new_path,'hai')
# # #  #############
# # #  up len storj
# # #  
# # ############################################################## 
# #subprocess.call(['multichain-cli',chain_name,'stop'])

import os
import sys
#from Savoir import Savoir
import subprocess
import json
import binascii 
import socket
import time
from threading import Thread
import threading
import requests
import yaml
import shutil

#--------------------------------------------------
#                    Documentation
#    https://storj.io/blog/2019/01/getting-started-with-the-storj-v3-test-network-storj-sdk/
    
#                    Prerequisites

#    Before configuring the storj-sim V3 testnet, you must have the following:
#     The latest release of Git (https://git-scm.com/downloads)
#     Go, at least version 1.11 (https://golang.org/doc/install)
#     The AWS CLI tool (https://docs.aws.amazon.com/cli/latest/userguide/installing.html)

class Server:
    def __init__(self, gateway_addr, gateway_access_key, gateway_secret_key):
        self._gateway_addr = gateway_addr
        self._gateway_access_key = gateway_access_key
        self._gateway_secret_key = gateway_secret_key

    def configure(self):
        # configure gateway access key
        command = ['aws', 'configure', 'set', 'aws_access_key_id', self._gateway_access_key] 
        subprocess.run(command)

        # configure gateway secret key
        command = ['aws', 'configure', 'set', 'aws_secret_access_key', self._gateway_secret_key] 
        subprocess.run(command)

    def run(self):
        # run storj process
        command = [storjsim_path, 'network', 'run'] 
        subprocess.run(command, stdout=subprocess.PIPE)
        while(True):
            if (threading.currentThread().isAlive() == False):
                break

    def list_buckets(self):
        # list current buckets
        command = ['aws', 's3', '--endpoint=http://' + self._gateway_addr, 'ls']
        buckets = subprocess.run(command, stdout=subprocess.PIPE)

        str = buckets.stdout.decode('utf-8')
        BUCKETS = []
        while(str != ''):
            info = {
                'date': '',
                'time': '',
                'name': ''
            }
            # get date
            index = str.find(' ')
            temp = slice(index)
            info['date'] = str[temp]
            str = str[index + 1:]

            # get time
            index = str.find(' ')
            temp = slice(index)
            info['time'] = str[temp]
            str = str[index + 1:]
            # get name
            index = str.find('\n')
            temp = slice(index)
            info['name'] = str[temp]
            str = str[index + 1:]

            BUCKETS.append(info)

        return BUCKETS

    def list_bucket_files(self, bucket_name):
        # list current files in bucket
        command = ['aws', 's3', '--endpoint=http://' + self._gateway_addr, 'ls', 's3://' + bucket_name]
        files = subprocess.run(command, stdout=subprocess.PIPE)

        str = files.stdout.decode('utf-8')
        FILES = []
        while(str != ''):
            info = {
                'date': '',
                'time': '',
                'size': '',
                'name': ''
            }
            # get date
            index = str.find(' ')
            temp = slice(index)
            info['date'] = str[temp]
            str = str[index + 1:]

            # get time
            index = str.find(' ')
            temp = slice(index)
            info['time'] = str[temp]
            str = str[index + 1:]

            # get size
            str = str.strip() + '\n'
            index = str.find(' ')
            temp = slice(index)
            info['size'] = str[temp]
            str = str[index + 1:]

            # get name
            index = str.find('\n')
            temp = slice(index)
            info['name'] = str[temp]
            str = str[index + 1:]

            FILES.append(info)

        return FILES

    def create_bucket(self, bucket_name):
        # create a bucket
        command = ['aws', 's3', '--endpoint=http://' + self._gateway_addr, 'mb', 's3://' + bucket_name] 
        subprocess.call(command)

    def upload(self, path, file_name, bucket_name):
        # upload the file from the path to the bucket
        command = ['aws', 's3', '--endpoint=http://' + self._gateway_addr, 'cp', path + '/' + file_name,'s3://' + bucket_name] 
        subprocess.run(command)

    def download(self, bucket_name, path, file_name):
        # download the file from the bucket to the path
        command = ['aws', 's3', '--endpoint=http://' + self._gateway_addr, 'cp','s3://' + bucket_name + '/' + file_name, path] 
        subprocess.run(command)

    def remove_bucket(self, bucket_name):
        # remove a bucket
        command = ['aws', 's3', '--endpoint=http://' + self._gateway_addr, 'rb', 's3://' + bucket_name] 
        subprocess.run(command)

    def remove_file(self, bucket_name, file_name):
        # remove a file
        command = ['aws', 's3', '--endpoint=http://' + self._gateway_addr, 'rm', 's3://' + bucket_name + '/' + file_name] 
        subprocess.run(command)

    def presign(self, bucket_name, file_name):
        # export a link
        command = ['aws', 's3', '--endpoint=http://' + self._gateway_addr, 'presign', 's3://' + bucket_name + '/' + file_name] 
        presign = subprocess.run(command, stdout=subprocess.PIPE)
        temp = presign.stdout.decode('utf-8')

        LINK = temp.strip()
        return LINK

#----------------------------------------------------
storjsim_path = '$HOME/go/bin/storj-sim'

# Get gateway address
def get_gateway_addr():
    command = [storjsim_path, 'network', 'env', 'GATEWAY_0_ADDR'] 
    gateway_addr = subprocess.run(command, stdout=subprocess.PIPE)
    temp = gateway_addr.stdout.decode('utf-8')

    GATEWAY_ADDR = temp.strip()
    return GATEWAY_ADDR

#Get gateway access key
def get_access_key():
    command = [storjsim_path, 'network', 'env', 'GATEWAY_0_ACCESS_KEY'] 
    gateway_access_key = subprocess.run(command, stdout=subprocess.PIPE)
    temp = gateway_access_key.stdout.decode('utf-8')

    GATEWAY_ACCESS_KEY = temp.strip()
    return GATEWAY_ACCESS_KEY

#Get gateway secret key
def get_secret_key():
    command = [storjsim_path, 'network', 'env', 'GATEWAY_0_SECRET_KEY']
    gateway_secret_key = subprocess.run(command, stdout=subprocess.PIPE)
    temp = gateway_secret_key.stdout.decode('utf-8')

    GATEWAY_SECRET_KEY = temp.strip()
    return GATEWAY_SECRET_KEY

if __name__ == "__main__":

    # GATEWAY_ADDR = get_gateway_addr()
    # GATEWAY_ACCESS_KEY = get_access_key()
    # GATEWAY_SECRET_KEY = get_secret_key()

    # _server = Server(GATEWAY_ADDR, GATEWAY_ACCESS_KEY, GATEWAY_SECRET_KEY)
    # t1 = threading.Thread(target=_server.run, args=())
    # t1.start()
    # _server.configure()
    # _server.create_bucket('demobucket1')
    data = os.path.isfile(os.path.expanduser('~/.local/share/storj/uplink/config.yaml'))
    print(data)