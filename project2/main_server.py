import subprocess
import socket
import os 
import sub.sub_func as fs
import sub.storj as st
from pathlib import Path
path = Path(__file__).resolve().parent.__str__()
print(path)
#TCP_IP = '192.168.100.24'
#TCP_PORT = 6304
BUFFER_SIZE = 1024  # Normally 1024, but we want fast response

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#s.bind((TCP_IP, TCP_PORT))
s.bind((fs.ip_address, int(fs.port_connect)-1))

a = s.listen(5)
print(a)
i = 1
server = st.StorjServer()
satellite_addr = "10.10.221.103:10000"

while i>0:
    out = ''
    conn, addr = s.accept()
    print(' address:',addr)
    data = conn.recv(BUFFER_SIZE)
    print(data)
    if not data: 
        conn.send(bytes([0]))
        break
    out = out + data.decode('utf-8')
    print(out)

    # accept quyền cho user
    subprocess.call(['multichain-cli','chaindemo','grant',out,'connect'])
    key = [fs.KEY_STORJ_INFO]
    key.append(out)
    content = {}

    # cấp key cho client
    content['access_key'] = server._gateway_access_key
    content['secret_key'] = server._gateway_secret_key
    content['api_key'] = server._gateway_api_key
    content['bucket_name'] = server.generate_bucket_name(out)

    # setup cli cho server
    client = st.StorjClient(satellite_addr, content['api_key'], content['access_key'], content['secret_key'])
    client.setup()

    # tự tạo 1 bucket 
    server.make_bucket(content['bucket_name'])

    tx = fs.api.publish(fs.STREAM_DATA,key,{'json':content})
    conn.send(bytes([1]))  # echo
    i= i-1
conn.close()
