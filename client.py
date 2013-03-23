import smtplib
from smtplib import SMTPHeloError, SMTPAuthenticationError, SMTPException
import imaplib
import getpass
import sys, os
import email
import M2Crypto
import time

MBSTRING_FLAG = 0x1000
MBSTRING_ASC  = MBSTRING_FLAG | 1
MBSTRING_BMP  = MBSTRING_FLAG | 2

class MailManager():

    def __init__(self, username, password):
        self.username = username
        self.password = password
        print "** Connecting to SMTP servers **"
        self.serverConn = smtplib.SMTP("smtp.gmail.com:587")
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
        self.serverConn.sendmail(self.username,address,data)

    def fetch_mail(self):
        print "** Connecting to IMAP servers **"
        self.imap = imaplib.IMAP4_SSL('imap.gmail.com')
        self.login_imap()
        latest = self.get_latest_email()
        print latest

    def get_latest_email(self):
        self.imap.select("inbox")
        result, data = self.imap.uid('search', None, "ALL") # search and return uids instead
        latest_email_uid = data[0].split()[-1]
        result, data = self.imap.uid('fetch', latest_email_uid, '(RFC822)')
        raw_email = data[0][1]
        return raw_email

    def quit(self):
        self.serverConn.quit()

class EncryptionManager():

    def generate_cert(self, loc):
        self.generate_pkey(loc)
        self.create_x509_request()
        self.create_x509_cert()

    def generate_pkey(self, loc):
        if loc is None:
            M2Crypto.Rand.rand_seed(os.urandom(1024))
            self.private = M2Crypto.RSA.gen_key (1024, 65537, lambda: None)
        else:
            self.import_key(loc)
        self.pkey = M2Crypto.EVP.PKey()  
        self.pkey.assign_rsa(self.private)

    def create_x509_request(self):
        self.X509Request = M2Crypto.X509.Request()
        X509Name = M2Crypto.X509.X509_Name()
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
        self.X509Certificate = M2Crypto.X509.X509() 
        self.X509Certificate.set_version(0)

        # Time settings
        cur_time = M2Crypto.ASN1.ASN1_UTCTIME()
        cur_time.set_time(int(time.time()))
        self.X509Certificate.set_not_before(cur_time)

        # Expire certs in 1 day.
        expire_time = M2Crypto.ASN1.ASN1_UTCTIME()
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
        X509Name = M2Crypto.X509.X509_Name(M2Crypto.m2.x509_name_new())
        self.X509Certificate.set_issuer_name(X509Name)
        
        self.X509Certificate.sign(pkey=self.pkey, md='sha1')
        self.X509Certificate.save_pem("cert.pem")
        #print self.X509Certificate.as_text ()

    def import_key(self, loc):
        self.private = M2Crypto.RSA.load_key(loc)

    def import_cert(self,loc):
        self.X509Certificate = M2Crypto.X509.load_cert(loc)

    def encrypt_data(self, data):
        pubkey = self.X509Certificate.get_pubkey()
        print pubkey.as_pem(None)


if __name__ == '__main__':
    print
    #print "Logging in as mikesligo@gmail.com"
    #password = getpass.getpass(prompt="Enter password: ")
    #mail = MailManager("mikesligo@gmail.com",password)
    #mail.send_mail("mikesligo@gmail.com","lol")
    #mail.fetch_mail()
    #mail.quit()
    secure = EncryptionManager()
    #secure.generate_cert("key.asc")
    secure.import_cert("cert.pem")
    secure.encrypt_data(None)
