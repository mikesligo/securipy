import smtplib
from smtplib import SMTPHeloError, SMTPAuthenticationError, SMTPException
import imaplib
import getpass

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
        except SMTPHeloError as err:
            print "SMTPHeloError:"
            print err
        except SMTPAuthenticationError as err:
            print "Username/Password incorrect"
        except SMTPException as err:
            print "SMTPException"
            print err
        except:
            raise
        print "successful."

    def send_data(self,data,address):
        self.serverConn.sendmail(self.sender,address,data)

    def fetch_mail(self):
        print "** Connecting to IMAP servers **"
        self.imap = imaplib.IMAP4_SSL('imap.gmail.com')
        self.login_imap()
        print self.imap.list()

    def quit(self):
        self.serverConn.quit()


if __name__ == '__main__':
    print
    print "Logging in as mikesligo@gmail.com"
    password = getpass.getpass(prompt="Enter password: ")
    manager = MailManager("mikesligo@gmail.com",password)
    manager.fetch_mail()
    manager.quit()
