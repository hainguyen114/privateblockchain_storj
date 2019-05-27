import sub.sub_func as fs
import sub.create_pdf as cp
import sub.storj as st

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
def put_newRSAKey(CP_info):
    global key_id
    key = [fs.KEY_CERT_PROVIDER]  
    key.extend(CP_info)
    pubkeypath = fs.os.path.join(fs.CRPATH,'my_rsa_public.pem')
    if fs.os.path.isfile(pubkeypath):
        content_old_pub = open(pubkeypath, 'rb').read()
        old_pub_key = fs.RSA.importKey(content_old_pub)
    prikeypath = fs.os.path.join(fs.CRPATH,'my_rsa_private.pem')
    fs.genRsaKey()
    if fs.os.path.isfile(pubkeypath):
        content_pub = open(pubkeypath, 'rb').read()
        content_pri = open(prikeypath, 'rb').read()
        pub_key = fs.RSA.importKey(content_pub)
        pri_key = fs.RSA.importKey(content_pri)
        fs.create_old_key_cert(pri_key,old_pub_key,key_id,CP_info)
        tx = fs.api.publish(fs.STREAM_PUBKEY,key,pub_key.exportKey('PEM').hex())
        key_id +=1
        return tx

def checkUser(User_info,type_of_cert):
    print(User_info)
    print(type_of_cert)
    return True
    
####################################

####################################
def exportCert(User_info,type_of_Cert,bucket_name,acc_Storj):
    content = 'this is {}: name {}'.format(type_of_Cert,User_info['user'])
    file_name = '{}_{}'.format(User_info['user'],type_of_Cert)+'.pdf'
    cp.createWithText(content,fs.os.path.join(fs.CRPATH,file_name))

    f = open(fs.os.path.join(fs.CRPATH,'my_rsa_private.pem'), 'rb')
    prikey = fs.RSA.importKey(f.read())

    cp.exportPDFwithSig(fs.os.path.join(fs.CRPATH,file_name),prikey)
    #
    newfile = file_name.replace('.pdf','_signed.pdf')

    # up qua multichain
    fs.upfile(fs.os.path.join(fs.CRPATH,newfile),[newfile])


    # up qua storj
    #check = acc_Storj.upload(fs.CRPATH, newfile,bucket_name)
    #print(check) 
    return newfile

####################################
def AccepOrDenyRequest(CP_info,bucket_name,acc_Storj):
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
                    link_to_Cert = exportCert(de_user_info,type_of_cert,bucket_name,acc_Storj)
                    key.append('uploaded')
                    content['file_name'] = link_to_Cert
                    content['bucket_name'] = bucket_name
                    tx = fs.api.publish(fs.STREAM_REQUEST,key,{'json':content})
                    print('1 upload:',tx)
                    #return tx
                else:
                    key.append('denied')
                    tx = fs.api.publish(fs.STREAM_REQUEST,key,{'json':content})
                    print('1 denied: ',tx)
                    #return tx
    return 0 #



####################
key_id = fs.getRSAKeyId()
# dk thanh 1 CP va put pubkey len chain
CP_info  = ['HCMUS','IT']
listCP = fs.getListCertProviders() 
if not any(CP_info == i['info'][1:] for i in  listCP):
    #putMyPubKey(CP_info) 
    print("up key")


cp.createWithText('this is','/home/thanhtrang/trang.pdf')
f = open(fs.os.path.join(fs.CRPATH,'my_rsa_private.pem'), 'rb')
prikey = fs.RSA.importKey(f.read())
cp.exportPDFwithSig('/home/thanhtrang/trang.pdf',prikey)


rc_pub_key = fs.getCPPubKey(CP_info)
cp.verifyPDF('/home/thanhtrang/trang_signed.pdf',rc_pub_key)

put_newRSAKey(CP_info)

rc_pub_key = fs.getCPPubKey(CP_info)
cp.verifyPDF('/home/thanhtrang/trang_signed.pdf',rc_pub_key)

fs.getRSAKeyId()
old_pubkey = fs.get_old_pubkey(fs.getCPPubKey(CP_info),5,CP_info)[1]
cp.verifyPDF('/home/thanhtrang/trang_signed.pdf',old_pubkey)


#--stoji
#keyStorj = fs.getStorjKeyAndBucket() 
#acc_Storj = st.StorjClient(st.satellite_addr, keyStorj['api_key'],keyStorj['access_key'], keyStorj['secret_key'])
#acc_Storj.setup()

keyStorj= {}
keyStorj['bucket_name'] =0
acc_Storj = 0
## client.download('sj://demobucket/Do_an2.pdf', '/home/hainguyen/Desktop')

## acc_Storj.upload('/home/thanhtrang', 'l.zip', keyStorj['bucket_name'])
## acc_Storj = 0
#########################



try:
    while True:
        fs.sys.stdout.write(".")
        fs.sys.stdout.flush()
        fs.time.sleep(3)
        AccepOrDenyRequest(CP_info,keyStorj['bucket_name'],acc_Storj)
except KeyboardInterrupt:
    print('---__Exit!__---')
