import sub.sub_func as fs
import sub.create_pdf as cp

a = fs.checkPermission()
if(fs.checkPermission() == False):
    permission_check = fs.send_address_for_granting_permission(fs.ip_address,fs.port_connect)
    if permission_check == 0:
        print('Cannot grant permission in multichain streams')
        fs.sys.exit()


# de dang ki minh thanh 1 node B
# SP_info = ['BIDV']
def putMyPubKey(SP_info):
    key = [fs.KEY_SER_PROVIDER]  
    key.extend(SP_info)
    tx = fs.api.publish(fs.STREAM_PUBKEY,key,fs.getMyPupKey().hex())
    return tx 
# user_info: decrypted {'user':,'pass':}
def checkUser(User_info,type_of_ser):
    return True
    
####################################
def exportSer(User_info,type_of_Ser):
    return "this is Ser: " + (type_of_Ser)
####################################
def checkReQuestCertStatus(SP_info,en_user_info,type_of_cert): 
    tx = fs.api.liststreamkeyitems(fs.STREAM_REQUEST,fs.KEY_REQUEST_SER,False,fs.NUM_ITEMS_PER_GET_FROM_STREAM)
    tx.reverse()
    for t in tx:
        if set(SP_info).issubset(t['keys']):
            if en_user_info == t['data']['json']['user_info'] and type_of_cert == t['data']['json']['type_of_ser']: 
                if 'checked' in t['keys']:
                    if 'accepted' in t['keys'] : 
                        return 1,t['txid'] # file dc dong y 
                    else:
                        return 2,t['txid'] # file bi tu choi  
                else:
                    return 0,t['txid']# file chua duoc check
    return -1, None # khong co file
#####################################

def listRequestSer(SP_info): 
    tx = fs.api.liststreamkeyitems(fs.STREAM_REQUEST,fs.KEY_REQUEST_SER,False,fs.NUM_ITEMS_PER_GET_FROM_STREAM)
    tx.reverse()
    list_txs = []
    for t in tx:
        if set(SP_info).issubset(t['keys']):
            if checkReQuestCertStatus(SP_info,t['data']['json']['user_info'],t['data']['json']['type_of_ser'])[0] == 0:
                list_txs.append(t)
    return list_txs
#####################################

#####################################
def CheckUserAndCert(txid,acc_Storj):
    t = fs.api.getstreamitem(fs.STREAM_REQUEST,txid)
    de_user_info = fs.json.loads(fs.decrypt(t['data']['json']['user_info']))
    type_of_ser = t['data']['json']['type_of_ser']
    cert_file = fs.decrypt(t['data']['json']['name_file'])
    cert_bucket = fs.decrypt(t['data']['json']['bucket_name'])
    #acc_Storj.download('sj://'+cert_bucket+'/'+cert_file, fs.CRPATH)
    CP_info = t['data']['json']['CP_info']
    print(cert_file,CP_info)
    check_cert = cp.verifyPDF(cert_file,fs.getCPPubKey(CP_info))
    return checkUser(de_user_info,type_of_ser),check_cert
########################################
def AcceptOrDenyRequest(txid,acc_Storj):
    t = fs.api.getstreamitem(fs.STREAM_REQUEST,txid)
    new_content = fs.copy.copy(t['data'])
    new_key = fs.copy.copy(t['keys'])
    new_key.append('checked')
    if CheckUserAndCert(txid,acc_Storj) == (True,True):
        new_key.append('accepted')
    else:
        new_key.append('denied')
    tx = fs.api.publish(fs.STREAM_REQUEST,new_key,new_content)
    return tx




SP_info  = ['BIDV']
listSP = fs.getListSerProviders() 
if not any(SP_info == i['info'][1:] for i in  listSP):
    putMyPubKey(SP_info) 
    print("up key")
#

#--stoji
#keyStorj = fs.getStorjKeyAndBucket()
keyStorj = {}
keyStorj['bucket_name'] = 'asd'
#acc_Storj = st.StorjClient(st.satellite_addr, keyStorj['api_key'],keyStorj['access_key'], keyStorj['secret_key'])
acc_Storj = 0
#
####################



try:
    while True:
        fs.sys.stdout.write(".")
        fs.sys.stdout.flush()
        fs.time.sleep(3)

                
        l = listRequestSer(SP_info)
        #########################
                
        for t in l:
            if checkReQuestCertStatus(SP_info,t['data']['json']['user_info'],t['data']['json']['type_of_ser'])[0] == 0 :
                print('-txid : {}'.format(t['txid']))
                name_file = t['data']['json']['name_file']
                bucket_name = t['data']['json']['bucket_name']
                de_user_info = fs.json.loads(fs.decrypt(t['data']['json']['user_info']))
                de_name_file = fs.decrypt(name_file)
                de_bucket_name = fs.decrypt(bucket_name) 
                check = CheckUserAndCert(t['txid'],acc_Storj)
                print('   check user: {}, check cert: {}'.format(check[0],check[1]))
                print('   name: {}'.format(de_user_info['user']))
                print('   cert: name:{} bucket:{}'.format(de_name_file,de_bucket_name))
                print('   ser_request: {}'.format(t['data']['json']['type_of_ser']))
                AcceptOrDenyRequest(t['txid'],acc_Storj)


except KeyboardInterrupt:
    print('---__Exit!__---')


#print('choose')

#fs.api.liststreamkeyitems(fs.STREAM_REQUEST,fs.KEY_REQUEST_SER,False,fs.NUM_ITEMS_PER_GET_FROM_STREAM)

# txid = '303dafc4bfcfc01edd15a23126c2ac7e0e35da6e8e6a34d71276db6fddcd233d'
# AcceptOrDenyRequest(txid)


