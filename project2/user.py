import sub.sub_func as fs
import sub.create_pdf as cp

import sub.storj as st
# import imp
# imp.reload(fs)
a = fs.checkPermission()
if(fs.checkPermission() == False):
    permission_check = fs.send_address_for_granting_permission(fs.ip_address,fs.port_connect)
    if permission_check == 0:
        print('Cannot grant permission in multichain streams')
        fs.sys.exit()
fs.getStreamName()
####################################################
# User_info = {'user':'NguyenThiA','pass':'1234'}
# CP_info = ['HCMUS','IT']
# type_of_Cert = 'degree'
#              = 'semester_grade_chart'
def request_Cert(User_info,CP_info, type_of_Cert):
    key = [fs.KEY_REQUEST_CERT]
    key.extend(CP_info)
    CP_pubkey = fs.getCPPubKey(CP_info)
    en_info_user = CP_pubkey.encrypt(User_info.__str__().replace("\'", "\"").encode('utf-8'),32)[0].hex()
    content = {}
    content['user_info'] = en_info_user
    content['type_of_cert'] = type_of_Cert
    tx = fs.api.publish(fs.STREAM_REQUEST,key,{'json':content})
    return tx 
########################################################
def getLinkCert(User_info,CP_info,type_of_Cert):
    CP_pubkey = fs.getCPPubKey(CP_info)
    en_info_user = CP_pubkey.encrypt(User_info.__str__().replace("\'", "\"").encode('utf-8'),32)[0].hex()
    status = fs.checkReQuestCertStatus(CP_info,en_info_user,type_of_Cert)
    if status[0] == 1:
        t = fs.api.getstreamitem(fs.STREAM_REQUEST,status[1])
        return t['data']['json']['file_name'],t['data']['json']['bucket_name']
    return False

# User_info = {'name':'trang'} -> json
# SP_info = ['BIDV']
# type_of_Ser = 'applyjob'
# link -> ?
def request_Ser(User_info,SP_info,CP_info,type_of_Ser,name_file,bucket_name):
    key = [fs.KEY_REQUEST_SER]
    key.extend(SP_info)
    SP_pubkey = fs.getSPPubKey(SP_info)
    en_info_user = SP_pubkey.encrypt(User_info.__str__().replace("\'", "\"").encode('utf-8'),32)[0].hex()
    en_name_file = SP_pubkey.encrypt(name_file.encode('utf-8'),32)[0].hex()
    en_bucket_name = SP_pubkey.encrypt(bucket_name.encode('utf-8'),32)[0].hex()
    content = en_info_user
    content = {}
    content['user_info'] = en_info_user
    content['name_file'] = en_name_file
    content['bucket_name'] = en_bucket_name
    content['type_of_ser'] = type_of_Ser
    content['CP_info'] = CP_info
    tx = fs.api.publish(fs.STREAM_REQUEST,key,{'json':content})
    return tx 
###################################

User_CP_info = {'user':'NguyenThiG','pass':'1234'} 
CP_info = ['HCMUS','IT']
SP_info = ['BIDV']
type_of_Ser = 'applyjob'
type_of_Cert = 'degree'
fs.getListCertProviders()
request_Cert(User_CP_info,CP_info, type_of_Cert)

CP_pubkey = fs.getCPPubKey(CP_info)
en_info_user = CP_pubkey.encrypt(User_CP_info.__str__().replace("\'", "\"").encode('utf-8'),32)[0].hex()
fs.checkReQuestCertStatus(CP_info,en_info_user,type_of_Cert)

link_Cert = getLinkCert(User_CP_info,CP_info,type_of_Cert)  

#################################
User_SP_info = {'user':'NguyenThiA'} 
request_Ser(User_SP_info,SP_info,CP_info,type_of_Ser,link_Cert[0],link_Cert[1])
###############################

cp.verifyPDF(link_Cert[0],CP_pubkey)
a = fs.getStorjKeyAndBucket()

fs.down_file('/home/thanhtrang/o.pdf',['NguyenThiG_degree.pdf'])


keyStorj = fs.getStorjKeyAndBucket() 
acc_Storj = st.StorjClient(st.satellite_addr, keyStorj['api_key'],keyStorj['access_key'], keyStorj['secret_key'])
acc_Storj.setup()
acc_Storj.download('sj://'+keyStorj['bucket_name']+'/'+link_Cert[0], '/home/thanhtrang')

cp.verifyPDF('/home/thanhtrang/'+ link_Cert[0],fs.getCPPubKey(CP_info))

##########################################################################
fs.upfile(fs.os.path.join(fs.CRPATH, 'my_rsa_public.pem'),['public'])
fs.down_file('/home/thanhtrang/pubkey1.pem',['public'])
fs.genRsaKey()
import sub.sign_ver as sv 
content = open('/home/thanhtrang/pubkey1.pem', 'rb').read()

f = open(fs.os.path.join(fs.CRPATH,'my_rsa_private.pem'), 'rb')
prikey = fs.RSA.importKey(f.read())
signature = sv.b64encode(sv.sign(content, prikey, "SHA-512"))
with open('/home/thanhtrang/key_sig.pem', "wb") as myfile:
    myfile.write(content)
    myfile.write(signature)


pubkey = CP_pubkey
if fs.os.path.isfile('/home/thanhtrang/key_sig.pem'):
        data = open('/home/thanhtrang/key_sig.pem', 'rb').read()
        #print(data)
        eOF = b'-----END PUBLIC KEY-----' 
        pos = data.find(eOF)+len(eOF)
        signature = data[pos:] 
        content = data[:pos] 
        #print(signature)
        #print(content)
        print(sv.verify(content, signature, pubkey))
        print(content)
old_pubkey = fs.RSA.importKey(content)
old_pubkey
# f = open(fs.os.path.join(fs.CRPATH,'my_rsa_private.pem'), 'rb')
# prikey = fs.RSA.importKey(f.read())
# f = open(fs.os.path.join(fs.CRPATH,'my_rsa_public.pem'), 'rb')
# pubkey = fs.RSA.importKey(f.read())
# pubkey == CP_pubkey

# prikey.decrypt(pubkey.encrypt('kkk'.encode('utf-8'),32))

# cp.createWithText('aaa','a.pdf')
# cp.exportPDFwithSig("/home/thanhtrang/Documents/project_multichain_demo/project/a.pdf",prikey)

# import sub.sign_ver as sv

# if fs.os.path.isfile(file_in):

# data = open('NguyenThiG_degree_signed.pdf', 'rb').read()
# data = open('a_signed.pdf', 'rb').read()
#     #print(data)
# eOF = b'%%EOF\n' 
# pos = data.find(eOF)+len(eOF)
# signature = data[pos:] 
# content = data[:pos] 
#     #print(signature)
#     #print(content)
# sv.verify(content, signature, CP_pubkey)
