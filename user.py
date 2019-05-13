import sub_func as fs

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
        return t['data']['json']['link_to_cert']
    return False

# User_info = {'name':'trang'} -> json
# SP_info = ['BIDV']
# type_of_Ser = 'applyjob'
# link -> ?
def request_Ser(User_info,SP_info,CP_info,type_of_Ser,link_Cert):
    key = [fs.KEY_REQUEST_SER]
    key.extend(SP_info)
    SP_pubkey = fs.getSPPubKey(SP_info)
    en_info_user = SP_pubkey.encrypt(User_info.__str__().replace("\'", "\"").encode('utf-8'),32)[0].hex()
    en_link_cert = SP_pubkey.encrypt(link_Cert.__str__().encode('utf-8'),32)[0].hex()
    content = en_info_user
    content = {}
    content['user_info'] = en_info_user
    content['link_cert'] = en_link_cert
    content['type_of_ser'] = type_of_Ser
    content['CP_info'] = CP_info
    tx = fs.api.publish(fs.STREAM_REQUEST,key,{'json':content})
    return tx 
########################################

User_info = {'name':'trang'} 
SP_info = ['BIDV']
type_of_Ser = 'applyjob'
SP_pubkey = fs.getSPPubKey(SP_info)
en_info_user = SP_pubkey.encrypt(User_info.__str__().replace("\'", "\"").encode('utf-8'),32)[0].hex()
status = fs.checkReQuestSerStatus(SP_info,en_info_user,type_of_Sert)
