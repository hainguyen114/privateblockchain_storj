from fpdf import FPDF
import sub.sign_ver as sv 
import sub.sub_func as fs

def createWithText(message,name_file):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt= message, ln=1, align="C")
    if('.pdf' not in name_file):
        name_file += '.pdf'
    pdf.output(name_file)

def exportPDFwithSig(file_in,prikey):
    #keysize = sf.RSAKEYLENGTH
    content = open(file_in, 'rb').read()
    signature = sv.b64encode(sv.sign(content, prikey, "SHA-512"))
    with open(file_in.replace(".pdf","_signed.pdf"), "wb") as myfile:
        myfile.write(content)
        myfile.write(signature)

def verifyPDF(file_in,pubkey):
    if fs.os.path.isfile(file_in):
        data = open(file_in, 'rb').read()
        #print(data)
        eOF = b'%%EOF\n' 
        pos = data.find(eOF)+len(eOF)
        signature = data[pos:] 
        content = data[:pos] 
        #print(signature)
        #print(content)
        return sv.verify(content, signature, pubkey)
    return False
# message = 'trnaag'
# createWithText(message,'f.pdf')

# file_in = 'f.pdf'
# pubkey = fs.getSPPubKey(['BIDV'])
# f = open('my_rsa_private.pem', 'rb')
# prikey = fs.RSA.importKey(f.read())


# exportPDFwithSig('f.pdf',prikey)

# (pubkey, prikey) = sv.newkeys(1024)
# content = open(file_in, 'rb').read()
# signature =sv.b64encode(sv.sign(content, prikey, "SHA-512"))
# sv.verify(content, sv.b64decode(signature), pubkey)

# file_in = 'f_signed.pdf'


# data = open(file_in, 'rb').read()
# eOF = b'%%EOF\n'
# pos = data.find(eOF)+len(eOF)
# signature = data[pos:] 
# content = data[:pos]

# verifyPDF(file_in,pubkey)
