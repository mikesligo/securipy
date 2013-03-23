import smtplib
from smtplib import SMTPHeloError, SMTPAuthenticationError, SMTPException
import imaplib
import getpass
import sys
import email

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


if __name__ == '__main__':
    print
    print "Logging in as mikesligo@gmail.com"
    password = getpass.getpass(prompt="Enter password: ")
    manager = MailManager("mikesligo@gmail.com",password)
    #manager.send_mail("mikesligo@gmail.com","lol")
    manager.fetch_mail()
    manager.quit()
