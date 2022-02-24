
#攻撃元のIPアドレスを検出し、その国籍を調べ出力する。


from distutils.log import error
from nis import match
import re

from numpy import mat

def read_txt(fileName):
    with open(fileName, 'r') as f:
        text = f.readlines()
        f.close()
        return text

def check_ip(text_list):

    for i in range(len(text_list)):
        text = text_list[i]
        match = re.search(r'([0-9]+\.){3}[0-9]+',text)
        print(match)

def time(text_list):

    for i in range(len(text_list)):
        text = text_list[i]
        match = re.search(r'[A-z]+ [0-9]+ ([0-9]+\:){2}[0-9]+',text)
        print(match)

def sshd(text_list):

    for i in range(len(text_list)):
        text = text_list[i]
        match = re.search(r'[A-z]+\[[0-9]+\]',text)
        print(match)        

def regular(text):

    #状態の種類:

    recDis_pattern = "Received disconnect" #受信を切断 dis_patternとセット recDis_pattern→dis_patternを返す。
    dis_pattern = "Disconnected" #接続の切断 recDis_patternとセット
    verDif_pattern = "Did not receive identification string" #sshdのバージョンの違い
    invUsr_pattern = "Invalid user" #ユーザー名が違う
    acpKey_pattern = "Accepted publickey" #公開鍵によってログインできたユーザー
    pamUnix_patten = "pam_unix" #定期実行のプログラム
    connectionClosed_pattern = "Connection closed" #
    badprotocolVer_pattern = "Bad protocol version"
    dising_pattern = "Disconnecting"
    protmjVer_pattern  = "Protocol major versions"
    unabNego_pattern = "Unable to negotiate"
    login_pattern = "systemd-logind"
    error_pattern = "error"
    connectionReset_pattern = "Connection reset"

    recDis_result = re.search(recDis_pattern,text)
    dis_result = re.search(dis_pattern,text)
    verDif_result = re.search(verDif_pattern,text)
    invUsr_result = re.search(invUsr_pattern,text)
    acpKey_result = re.search(acpKey_pattern,text)
    pamUnix_result = re.search(pamUnix_patten,text)
    connectionClosed_result = re.search(connectionClosed_pattern,text)
    badprotocolVer_result = re.search(badprotocolVer_pattern,text)
    dising_result = re.search(dising_pattern,text)
    protmjVer_result = re.search(protmjVer_pattern,text)
    unabNego_result = re.search(unabNego_pattern,text)
    login_result = re.search(login_pattern,text)
    error_result = re.search(error_pattern,text)
    connectionReset_result = re.search(connectionReset_pattern,text) 

    if recDis_result:
        return recDis_result

    if dis_result:
        return dis_result
    
    if verDif_result:
        return verDif_result
    
    if invUsr_result:
        return invUsr_result

    if acpKey_result:
        return acpKey_result

    if pamUnix_result:
        return pamUnix_result

    if connectionClosed_result:
        return connectionClosed_result

    if badprotocolVer_result:
        return badprotocolVer_result

    if dising_result:
        return dising_result

    if protmjVer_result:
        return protmjVer_result

    if unabNego_result:
        return unabNego_result

    if login_result:
        return login_result

    if error_result:
        return error_result

    if connectionReset_result:
        return connectionReset_result


if __name__ == "__main__":
    
    file_name = "auth.log"

    text_list = read_txt(file_name)
    len_text_list = len(text_list)

    #check_ip(text_list)
    sshd(text_list)
    '''
    for i in range(len(text_list)):
        text = text_list[i]
        judege = regular(text)
        if judege == None:
            break
        print(i+1,judege)
    '''