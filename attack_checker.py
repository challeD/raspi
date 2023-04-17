
#攻撃元のIPアドレスを検出し、その国籍を調べ出力する。
#sshdだけ取り出す。

#問題点:取り出した一つのsshdIDが合ってるか不明。
#       sshdが重なっていてNoneと返した場合があるのか不明or次の(同じ)sshdIDから取ってくるようにしたい。 
#       auth.log消してしまった・・・。
#       sshdリストはどこかのドキュメントから引っ張ってこればいいのでは

import re
import csv
import collections

def make_csv(filename):
    header = ['IP','num']
    with open(filename, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        f.close()

def add_csv(filename,ip,num):
    body = [ip,num]
    with open(filename, 'a') as f:
        writer = csv.writer(f)
        writer.writerow(body)

def read_txt(fileName):
    with open(fileName, 'r') as f:
        text = f.readlines()
        f.close()
        return text

def check_ip(text):

    match = re.search(r'([0-9]+\.){3}[0-9]+',text)
    
    if match:
        return match.group()

def check_time(text):

    match = re.search(r'[A-z]+ [0-9]+ ([0-9]+\:){2}[0-9]+',text)

    if match:
        return match.group()

def check_sshdId(text):

    match = re.search(r'sshd\[[0-9]+\]',text)

    if match:
        return match.group()

def check_login(text):

    match = re.search(r'systemd-logind\[[0-9]+\]',text)
    
    if match:
        return match.group()

def regular(text):

    #状態を追記しないと判定しないところがダメ。
    #状態の種類:

    recDis_pattern = "Received disconnect" #受信を切断 dis_patternとセット recDis_pattern→dis_patternを返す。
    dis_pattern = "Disconnected" #接続の切断 recDis_patternとセット
    verDif_pattern = "Did not receive identification string" #sshdのバージョンの違い
    invUsr_pattern = "Invalid user" #ユーザー名が違う
    acpKey_pattern = "Accepted publickey" #公開鍵によってログインできたユーザー
    pamUnix_patten = "pam_unix" #定期実行のプログラム
    connectionClosed_pattern = "Connection closed"
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
    
    log_file = "auth.log"
    file_name = "IP.csv"
    sshdlog = ""

    ip_list = []
    text_list = read_txt(log_file)
    len_text_list = len(text_list)

    for i in range(len_text_list):
        
        text = text_list[i]

        sshd = check_sshdId(text)

        #割り込み処理の対応sshd[1]→[2]→[1]の改善。
        #重なりのないsshdの検知。
        #現時点では何もしないif-passを入れている。(何かに使えるかも？)

        if sshd == None:
            
            #sshd以外,cronなどを検知したい時に使う。
            
            pass

        elif sshd != sshdlog:

            #ここで検知。
            #現時点ではipのNoneがあるが、実はIP検知可能かもしれない。

            #print(text)

            sshdlog = sshd

            ip = check_ip(text)

            if ip == None:
                pass

            else:
                
                ip_list.append(ip)

                pass
        
        else:

            #重なったものはpass

            pass
        

    c = collections.Counter(ip_list)
    c = c.most_common()

    make_csv(file_name)
    
    for j in range(len(c)):
        add_csv(file_name,c[j][0],c[j][1])


