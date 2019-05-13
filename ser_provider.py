import sub_func as fs

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
def checkReQuestCertStatus(SP_info): 
    tx = fs.api.liststreamkeyitems(fs.STREAM_REQUEST,fs.KEY_REQUEST_SER,False,fs.NUM_ITEMS_PER_GET_FROM_STREAM)
    tx.reverse()
    for t in tx:
        if set(SP_info).issubset(t['keys']):
            #if en_user_info == t['data']['json']['user_info'] and en_type_of_cert == t['data']['json']['type_of_cert']: 
            if 'checked' in t['keys']:
                if 'uploaded' in t['keys'] : 
                    return 1,t['txid'] # file dc dong y 
                else:
                    return 2,t['txid'] # file bi tu choi  
            else:
                return 0,t['txid']# file chua duoc check
    return -1, None # khong co file
#####################################

def AccepOrDenyRequest(SP_info, txid):
    t = fs.api.getstreamitem(fs.STREAM_REQUEST,txid)
    return 0 #


