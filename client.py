''' Copyright 2013 Michael Gallagher
    mikesligo (at) gmail (dot) com
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.'''

from smtplib import SMTPHeloError, SMTPAuthenticationError, SMTPException, SMTP
from M2Crypto import RSA, X509, ASN1, Rand, EVP, m2
import imaplib
import getpass
import sys
import os
import email
import time
import base64

MBSTRING_FLAG = 0x1000
MBSTRING_ASC  = MBSTRING_FLAG | 1
MBSTRING_BMP  = MBSTRING_FLAG | 2

class MailManager():

    def __init__(self, username, password):
        self.username = username
        self.password = password
        print "** Connecting to SMTP servers **"
        self.serverConn = SMTP("smtp.gmail.com:587")
        self.serverConn.starttls()
        self.login_smtp()

    def login_smtp(self):
        self.login("smtp")

    def login_imap(self):
        self.login("imap")

    def login(self, protocol=None):
        if protocol is None:
            print "Protocol not selected"
            exit(1)
        try:
            print "Logging in... ",
            if protocol == "smtp":
                self.serverConn.login(self.username,self.password)
            elif protocol == "imap":
                self.imap.login(self.username,self.password)
        except SMTPHeloError:
            print "SMTPHeloError:"
            raise
        except SMTPAuthenticationError:
            print "Username/Password incorrect"
            sys.exit(1)
        except SMTPException:
            print "SMTPException"
            raise
        except:
            raise
        print "successful."

    def send_mail(self,address,data):
        message = 'Subject: %s\n\n%s' % ("Testing code", data)
        self.serverConn.sendmail(self.username,address,message)

    def fetch_mail(self):
        print "** Connecting to IMAP servers **"
        self.imap = imaplib.IMAP4_SSL('imap.gmail.com')
        self.login_imap()
        latest = self.get_latest_email()
        return latest

    def get_latest_email(self):
        self.imap.select("inbox")
        result, data = self.imap.uid('search', None, "ALL") # search and return uids instead
        latest_email_uid = data[0].split()[-1]
        result, data = self.imap.uid('fetch', latest_email_uid, '(RFC822)')
        raw_email = data[0][1]
        return raw_email

    def get_body(self,raw_email):
        return email.message_from_string(raw_email).get_payload()

    def quit(self):
        self.serverConn.quit()

class EncryptionManager():

    def __init__(self, key_loc=None, cert_loc=None):
        if key_loc is not None:
            self.import_key(key_loc)
        if cert_loc is not None:
            self.import_cert(cert_loc)

    def generate_cert(self, loc):
        self.generate_pkey(loc)
        self.create_x509_request()
        self.create_x509_cert()

    def generate_pkey(self, loc):
        if loc is None:
            Rand.rand_seed(os.urandom(1024))
            self.private = RSA.gen_key (1024, 65537, lambda: None)
        else:
            self.import_key(loc)
        self.pkey = EVP.PKey()  
        self.pkey.assign_rsa(self.private)

    def create_x509_request(self):
        self.X509Request = X509.Request()
        X509Name = X509.X509_Name()
        X509Name.add_entry_by_txt (field='C', type=MBSTRING_ASC, entry='Ireland', len=-1, loc=-1, set=0 ) # country name
        X509Name.add_entry_by_txt (field='SP', type=MBSTRING_ASC, entry='Dublin', len=-1, loc=-1, set=0 ) # state of province name
        X509Name.add_entry_by_txt (field='L', type=MBSTRING_ASC, entry='Dublin', len=-1, loc=-1, set=0 ) # locality name
        X509Name.add_entry_by_txt (field='O', type=MBSTRING_ASC, entry='TFA', len=-1, loc=-1, set=0 ) # organization name
        X509Name.add_entry_by_txt (field='OU', type=MBSTRING_ASC, entry='DevOps', len=-1, loc=-1, set=0 ) # organizational unit name
        X509Name.add_entry_by_txt (field='CN', type=MBSTRING_ASC, entry='Certificate client',len=-1, loc=-1, set=0)    # common name
        X509Name.add_entry_by_txt (field='Email',type=MBSTRING_ASC, entry='mikesligo@gmail.com',len=-1, loc=-1, set=0)    # pkcs9 email address
        self.X509Request.set_subject_name(X509Name)
        self.X509Request.set_pubkey( pkey=self.pkey )
        self.X509Request.sign(pkey=self.pkey, md='sha1')
        #print self.X509Request.as_text()

    def create_x509_cert(self):
        self.X509Certificate = X509.X509() 
        self.X509Certificate.set_version(0)

        # Time settings
        cur_time = ASN1.ASN1_UTCTIME()
        cur_time.set_time(int(time.time()))
        self.X509Certificate.set_not_before(cur_time)

        # Expire certs in 1 day.
        expire_time = ASN1.ASN1_UTCTIME()
        expire_time.set_time(int(time.time()) + 60 * 60 * 24)
        self.X509Certificate.set_not_after(expire_time)

        self.X509Certificate.set_pubkey(pkey=self.pkey)
        X509Name = self.X509Request.get_subject()

        self.X509Certificate.set_subject_name(X509Name)
        X509Name.add_entry_by_txt (field='C', type=MBSTRING_ASC, entry='Ireland', len=-1, loc=-1, set=0 ) # country name
        X509Name.add_entry_by_txt (field='SP', type=MBSTRING_ASC, entry='Dublin', len=-1, loc=-1, set=0 ) # state of province name
        X509Name.add_entry_by_txt (field='L', type=MBSTRING_ASC, entry='Dublin', len=-1, loc=-1, set=0 ) # locality name
        X509Name.add_entry_by_txt (field='O', type=MBSTRING_ASC, entry='TFA', len=-1, loc=-1, set=0 ) # organization name
        X509Name.add_entry_by_txt (field='OU', type=MBSTRING_ASC, entry='DevOps', len=-1, loc=-1, set=0 ) # organizational unit name
        X509Name.add_entry_by_txt(field='CN', type=MBSTRING_ASC, entry='Certificate Authority',len=-1, loc=-1, set=0)    # common name
        X509Name.add_entry_by_txt(field='Email',type=MBSTRING_ASC, entry='mikesligo@gmail.com',len=-1, loc=-1, set=0)    # pkcs9 email address
        X509Name = X509.X509_Name(m2.x509_name_new())
        self.X509Certificate.set_issuer_name(X509Name)
        
        self.X509Certificate.sign(pkey=self.pkey, md='sha1')
        self.X509Certificate.save_pem("cert.pem")
        #print self.X509Certificate.as_text ()

    def import_key(self, loc):
        self.private = RSA.load_key(loc)

    def import_cert(self,loc):
        self.X509Certificate = X509.load_cert(loc)

    def encrypt_data(self, data):
        pubkey = self.X509Certificate.get_pubkey().get_rsa()
        ciphertext = pubkey.public_encrypt(data, RSA.pkcs1_oaep_padding)
        encoded = base64.b64encode(ciphertext)
        return encoded

    def decrypt_data(self, encoded):
        #privkey = self.X509Certificate.get_pubkey().as_pem(None)
        cipher = RSA.load_key("key.asc")
        decoded = base64.b64decode(encoded)
        try:
            plaintext = cipher.private_decrypt(decoded, RSA.pkcs1_oaep_padding)
        except:
            print "Error: Incorrect private key"
            return ""
        return plaintext

    def sign_data(self,data):
        pass

class TestManager():

    def test_all(self):
        secure = EncryptionManager(key_loc="key.asc")
        #self.test_certificate_handling(secure)
        self.test_mail_encryption(secure)

    def test_certificate_handling(self, secure):
        print "Generating certificate..."
        secure.generate_cert("key.asc")
        print "Importing certificate..."
        secure.import_cert("cert.pem")

    def test_mail_encryption(self,secure):
        print "Logging in as mikesligo@gmail.com"
        password = getpass.getpass(prompt="Enter password: ")
        mail = MailManager("mikesligo@gmail.com",password)
        print "Getting mail..."
        data = "lolol"
        mail.send_mail("mikesligo@gmail.com",secure.encrypt_data(data))
        body = mail.get_body(mail.fetch_mail())
        print "Decrypting...",
        decrypted = secure.decrypt_data(body)
        if decrypted == data:
            print "successful\nDecrypted data matches original"
        else:
            print "failed\nEncrypted data does not match original"
        print "Received: " + decrypted
        mail.quit()

if __name__ == '__main__':
    print
    tester = TestManager()
    tester.test_all()
