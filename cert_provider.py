import sub_func as fs

a = fs.checkPermission()
if(fs.checkPermission() == False):
    permission_check = fs.send_address_for_granting_permission(fs.ip_address,fs.port_connect)
    if permission_check == 0:
        print('Cannot grant permission in multichain streams')
        fs.sys.exit()


# de dang ki minh thanh 1 node B
# CP_info = ['HCMUS','IT']
def putMyPubKey(CP_info):
    key = [fs.KEY_CERT_PROVIDER]  
    key.extend(CP_info)
    tx = fs.api.publish(fs.STREAM_PUBKEY,key,fs.getMyPupKey().hex())
    return tx 
# user_info: decrypted {'user':,'pass':}
def checkUser(User_info,type_of_cert):
    return True
    
####################################

####################################
def exportCert(User_info,type_of_Cert):
    Cert = {}
    Cert['cert'] = type_of_Cert + User_info['user']
    Cert['signature'] = fs.sign(Cert['cert'].encode('utf-8')).hex() 
    return Cert

####################################
def AccepOrDenyRequest(CP_info):
    tx = fs.api.liststreamkeyitems(fs.STREAM_REQUEST,fs.KEY_REQUEST_CERT,False,fs.NUM_ITEMS_PER_GET_FROM_STREAM)
    tx.reverse()
    for t in tx:
        if set(CP_info).issubset(t['keys']):
            type_of_cert = t['data']['json']['type_of_cert']
            en_user_info = t['data']['json']['user_info']
            status_check = fs.checkReQuestCertStatus(CP_info,en_user_info,type_of_cert)

            status = status_check[0]
            #t_txid = status_check[1]
            if status == 0:
                de_user_info = fs.json.loads(fs.decrypt(en_user_info))
                check = checkUser(de_user_info,type_of_cert)
                key = [fs.KEY_REQUEST_CERT]
                key.extend(CP_info) 
                key.append('checked')
                content = fs.copy.copy(t['data']['json'])
                if check == True:
                    link_to_Cert = exportCert(de_user_info,type_of_cert)
                    key.append('uploaded')
                    content['link_to_cert'] = link_to_Cert
                    tx = fs.api.publish(fs.STREAM_REQUEST,key,{'json':content})
                    print('1 upload:',tx)
                    #return tx
                else:
                    key.append('denied')
                    tx = fs.api.publish(fs.STREAM_REQUEST,key,{'json':content})
                    print('1 denied: ',tx)
                    #return tx
    return 0 #


