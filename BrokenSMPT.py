import argparse
from smtplib import SMTP, SMTPRecipientsRefused, SMTPSenderRefused, SMTPResponseException
from email.mime.multipart import MIMEMultipart

RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"
WHITE = "\033[0;37m"

def spoof(target,ports):

    TestedPorts = []
    if ("ports"=="*"):
        TestedPorts = ['25','465','587','2525']
        ports = "25, 465, 587 and 2525"
    else:
        TestedPorts = list(ports.split(","))

    testuser = "testuser@mail.ca"
    message = MIMEMultipart()
    message["From"] = testuser
    message["To"] = testuser
    message["Subject"] = "test"
  
    text = message.as_string()

    print("{}[!] Looking For Email Spooffing Vulnerability on port {}..... [!]\n\033[94m".format(WHITE,ports))
    for port in TestedPorts: 
        print("{}  Testing Email Spoofing on port {}.....\n\033[94m".format(WHITE,port))
        try:
            SMTP(target,port).sendmail(testuser,testuser,text)
            print("{}  The SMTP Server Targeted : {} is potentialy vulnerable to mail spoofing. Authentification don't seem to be required on port {} \033[0;37m \n".format(GREEN,target,port))
        except (SMTPRecipientsRefused, SMTPSenderRefused, SMTPResponseException):
            print("{}  Recipient error encountered. The SMTP Server Targeted : {} don't seem to be vunlerable to mail spoofing on port {} \033[0;37m \n ".format(BLUE,target,port))
        except ConnectionRefusedError:
            print("{}   Connection refused by host {}. It don't seem to be vunlerable to mail spoofing on port {} \033[0;37m \n".format(BLUE,target,port))
        except Exception:
            print("{}   Exception Occured on host {}. It don't seem to be vunlerable to mail spoofing on port {} \033[0;37m \n".format(BLUE,target,port))
        except KeyboardInterrupt:
            print("    [CTRL+C] Stopping...")
            exit()

def userenum (target,ports): 
    TestedPorts = []
    if (ports=="*"):
        TestedPorts = ['25','465','587','2525']
        ports = "25, 465, 587 and 2525"
    else:
        TestedPorts = list(ports.split(","))
    
    print("{}[!] Looking For user enumeration vulnerability on port {}..... [!]\n\033[94m".format(WHITE,ports))
    
    for port in TestedPorts: 
        print("{}  Testing user enumeration on port {}.....\n\033[94m".format(WHITE,port))
        try:
            # VRFY
            # 250 Requested mail action okay, completed
            # 251 User not local; will forward to <forward-path>
            # 252 Cannot VRFY user, but will accept message and attempt delivery
            # 550 Requested action not taken: mailbox unavailable
            # 551 User not local; please try <forward-path>
            # 553 Requested action not taken: mailbox name not allowed
            # 500 Syntax error, command unrecognised
            # 501 Syntax error in parameters or arguments
            # 502 Command not implemented
            # 504 Command parameter not implemented
            # 421 <domain> Service not available, closing transmission channel
            # 550 Requested action not taken: mailbox unavailable
            verify = SMTP(target, port).verify("")
            if verify[0] in [250, 252]:
                print("{}  The SMTP Server Targeted : {} is potentialy vulnerable to user enumeration on port {}. VRFY query responded status : {}  \033[0;37m \n".format(GREEN,target,port,verify[0]))
            else:
                print("{}  The SMTP Server Targeted : {} don't seem to be vulberable to user enumeration on port {}. VRFY query responded statys : {}  \033[0;37m \n".format(BLUE,target,port,verify[0]))
        except Exception:
            print("{}   Exception Occured on host {}. It don't seem to be vunlerable to user enumeration on port {}. \033[0;37m \n".format(BLUE,target,port))
        except KeyboardInterrupt:
            print("    [CTRL+C] Stopping...")
            exit()
        
    
    
if __name__ == "__main__": 
    print("""
    \n
     ____            _                 _____ __  __ _______ _____    ___  
    |  _ \          | |               / ____|  \/  |__   __|  __ \  |__ \ 
    | |_) |_ __ ___ | | _____ _ __   | (___ | \  / |  | |  | |__) |    ) |
    |  _ <| '__/ _ \| |/ / _ \ '_ \   \___ \| |\/| |  | |  |  ___/    / / 
    | |_) | | | (_) |   <  __/ | | |  ____) | |  | |  | |  | |       |_|  
    |____/|_|  \___/|_|\_\___|_| |_| |_____/|_|  |_|  |_|  |_|       (_)                                                                 
    \n                              By Mr.Lew1s
    \n
    """)

    parser = argparse.ArgumentParser(description="SMTP common vulnerability check")
    parser.add_argument('--targets','-t', help="SMTP target server address or file containing SMTP servers list", required=True)
    parser.add_argument('--port','-p', help="SMTP Targert port or list of port SMTP servers list. Use * for all SMTP Ports.", required=True)
    args = parser.parse_args()
    
    target = args.targets
    port = args.port

    spoof(target,port)
    userenum(target,port)
