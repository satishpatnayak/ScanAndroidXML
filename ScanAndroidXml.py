#!/usr/bin/python3
import re
import requests
import sys
import os
from os import path

# Usage python lime.py <apkfile>
# fireBaseTest method will check for firebase url in /res/values/strings.xml
def fireBaseTest(filename, stringsFile):
	#Get Firebase URL 
	firebaseURL=""
	#writeResults(filename,"</br>[Info] --- Checking for firebase URLs")
	# for Strings.xml file 
	stringsFile=pwd+"\\"+filename+stringsFile
	writePassResults(filename,"<br> <br><b>Firebase Checks</b> ")
	try:
		#writeResults(filename,"</br>[Info]---Strings.xml file Location:"+ stringsFile)
		with open(stringsFile, errors='ignore') as f:
			f1=f.read()
			searchObj=re.findall(r'https://.*.firebaseio.com', f1)
			i=len(searchObj)
			if(i !=0):
				while i > 0:
				#print(i)
					i=i-1
					firebaseURL=searchObj[i]
					#writeResults(filename,"</br>[Info] --- Firebase URL found " + firebaseURL)
					firebaseURL=firebaseURL+"/.json"
					#writeResults(filename,"</br>[Info] --- Accessing "+ firebaseURL)
					req=requests.get(firebaseURL)
					if req.status_code == 200:
						writeResults(filename,"<p style=\"color:red;\">[Vulnerability] --- Firebase <a href='"+firebaseURL+"'>"+firebaseURL+"</a> is publicly accessible </p>" )
						writeResults(filename,"</br><button type='button' onclick='alert(JSON.stringify("+req.text+"))'> Show Response from " + firebaseURL+"</button> <br>Strings.xml file Location:"+ stringsFile)
					else:
						writePassResults(filename,"<br>[Info] --- Not Vulnerable. Strings.xml file Location:"+ stringsFile+"<br> Response from <a href='"+firebaseURL+"'>" + firebaseURL +"</a> </br>"+ req.text)
			else:
				writePassResults(filename,"</br>[Info] --- App doesn't have firebase URLs")
	except IOError:
		writeResults(filename,"</br> Strings.xml not accessible")
						
def network_security_config_Test(filename,nscFile):
	#writeResults(filename,"</br>[Info] --- Network security config check is in progress")
	stringsFile=pwd+"\\"+filename+nscFile
	writePassResults(filename,"<br> <br><b>Network Security Config Checks</b>")
	try:
		with open(stringsFile, errors='ignore') as f:
			#writeResults(filename,"</br>network_security_config.xml file Location:"+ stringsFile)
			fData=f.read()
		# Search for <certificates src="user"/>
			searchObj=re.search(r'<certificates.*src.*user.*>', fData, re.M|re.I)
			if searchObj:
				writeResults(filename,"<p style=\"color:red;\">[Vulnerability] --- Misconfigured network_security_config.xml. \n Found  "+searchObj.group()+" in network_security_config.xml which leads to MITM in Android devices API24 or above.</br>Found &lt;certificates src=\"user\" /&gt; in network_security_config.xml</p>network_security_config.xml file Location:"+ stringsFile)
			else:
				writePassResults(filename,"</br>[Info] --- Not found &lt;certificates src=\"user\" /&gt; in network_security_config.xml </br>network_security_config.xml file Location:"+ stringsFile)
		# Search for <certificates src="@raw/*"/>
			searchObj=re.search(r'<certificates.*src.*raw.*>', fData, re.M|re.I)
			if searchObj:
				writeResults(filename,"<p style=\"color:red;\">[Vulnerability] --- Misconfigured network_security_config.xml. \n Found  "+searchObj.group()+" in network_security_config.xml which leads to MITM in Android devices API24 or above.</br>Found &lt;certificates src=\"@raw/*\"/&gt; in network_security_config.xml</p>network_security_config.xml file Location:"+ stringsFile)
			else:
				writePassResults(filename,"</br>[Info] --- Not found &lt;certificates src=\"@raw/*\"/&gt; in network_security_config.xml</br>network_security_config.xml file Location:"+ stringsFile)
		# Search for ClearTextTraffic
			searchObj=re.search(r'<domain-config.*cleartextTrafficPermitted.*true.*>', fData, re.M|re.I)
			if searchObj:
				writeResults(filename,"<p style=\"color:red;\">[Vulnerability] --- Misconfigured network_security_config.xml. \n Found  "+searchObj.group()+" in network_security_config.xml which leads to MITM in Android devices API24 or above</p> </br>network_security_config.xml file Location:"+ stringsFile)
			else:
				writePassResults(filename,"</br>[Info] --- Not found &lt;domain-config cleartextTrafficPermitted=\"true\"&gt;  in network_security_config.xml</br>network_security_config.xml file Location:"+ stringsFile)
	except IOError:
		writePassResults(filename,"</br>App doesn't have network_security_config.xml")
	
def getDeepLinks():
	writePassResults(filename,"</br></br> <b> Custom URL Check</b>")
	# for AndroidManifest.xml file 
	f1=pwd+"\\"+filename+"\\"+manifestFile
	writePassResults(filename,"</br>[Info]---AndroidManifest.xml file Location: "+ f1)
	with open(f1, errors='ignore') as f:
		f2=f.read()
		i= f2.count("<data android:scheme")	
		searchObj1=re.findall(r'<data android:host=(.*)', f2)
		j=len(searchObj1)
		if(j !=0):
			while j > 0:
				j=j-1
				scheme1=re.search(r'android:scheme="(.*)"', searchObj1[j], re.M|re.I)
				if scheme1:
					writePassResults(filename,"</br>scheme: "+ scheme1.group(1))
					host1=searchObj1[j].replace(scheme1.group(),"")
					host2=re.search(r'"(.*)"', host1, re.M | re.I)
					if host2:
						writePassResults(filename,"</br>host: " + host2.group(1)+"</br>Deeplink: " + scheme1.group(1) + "://"+ host2.group(1))
					else:
						writePassResults(filename,"</br>No host found</br>Deeplink: "+ scheme1.group(1) + "://")
				else:
					host3=searchObj1[j].replace('"','')
					host4=host3.replace('/>','')
					writePassResults(filename,"</br>no scheme found</br>host: " + host4 +"</br>Deeplink: " + "://" + host4)
		else:
			writePassResults(filename,"</br>NO host")
		searchObj=re.findall(r'<data android:scheme=(.*)' , f2)
		i=len(searchObj)
		if(i !=0):
			while i > 0:
				i=i-1
				host=re.search(r'android:host="(.*)"' , searchObj[i], re.M|re.I)
				if host:
					writePassResults(filename,"</br>host: " + host.group(1))
					scheme1=searchObj[i].replace(host.group(),"")
					scheme=re.search(r'"(.*)"' , scheme1, re.M|re.I)
					if scheme:				
						writePassResults(filename,"</br>scheme: " + scheme.group(1)+"</br>Deeplink: " + scheme.group(1)+"://"+host.group(1))
						scheme=scheme1.replace(scheme.group(),"")
					else:
						writePassResults(filename,"</br>No Scheme found</br>Deeplink: "+ "://"+ host.group(1))
				else:
					scheme=searchObj[i].replace('"','')
					scheme=scheme.replace('/>','')
					writePassResults(filename,"</br>no host found</br>scheme: " + scheme +"</br>Deeplink: " + scheme + "://")
		else:
			writePassResults(filename,"</br>No more schemes")			
			
def isDebuggableOrBackup():
	f1=pwd+"\\"+filename+"\\"+manifestFile
	with open(f1, errors='ignore') as f:
		f2=f.read()
		searchObj=re.search(r'android:debuggable="true"' , f2, re.M|re.I)
		if searchObj:
			writeResults(filename,"<p style=\"color:red;\">[Vulnerability] ---Android debuggable. \n Found android:debuggable=true in AndroidManifest.xml file</p>")
		else:
			writePassResults(filename,"</br></br><b>android:debuggable Check </b> <br>[Info] --- android:debuggable not found")
		searchObj1=re.search(r'android:allowBackup="true"' , f2, re.M|re.I)
		searchObj2=re.search(r'android:allowBackup="false"' , f2, re.M|re.I)
		if searchObj1:
			writeResults(filename,"<p style=\"color:red;\">[Vulnerability] --- Android backup vulnerability. \n Found android:allowBackup=true in AndroidManifest.xml file</p>")
		elif searchObj2:	
			writePassResults(filename,"</br></br><b>android:allowBackup Check </b></br>[Info] --- android:allowBackup=\"false\" found")
		else:
			writeResults(filename,"<p style=\"color:red;\">[Vulnerability] --- Android backup vulnerability . \n Not found android:allowbackup=true, default value is true, in AndroidManifest.xml file</p>")
			
def writeResults(filename,msg):
	f=open(resultsHtml,"a")
	f.write(msg)
	f.close()
	
def writePassResults(filename,msg):
	f=open(resultsHtmlTemp,"a")
	f.write(msg)
	f.close()
	
apkfile = sys.argv[-1]
# Get file extension .apk 
filename, file_extension = os.path.splitext(apkfile)
pwd=os.getcwd()
stringsFile="\\res\\values\\strings.xml"
nscFile="\\res\\xml\\network_security_config.xml"
manifestFile="AndroidManifest.xml"
resultsHtml=filename+".html"
resultsHtmlTemp=filename+"Temp.html"
head="<!DOCTYPE html><html><head><style>table {  font-family: arial, sans-serif;  border-collapse: collapse;  width: 100%;}	td, th {	border: 1px solid #dddddd;	text-align: left;	padding: 8px;	}	tr:nth-child(even) {	background-color: #dddddd;	}	</style>	</head>	<body>"
endhtml="</body> </html>"
writeResults(filename, head +"<h3>This tool analyze Android app to find vulnerabilities in AndroidManifest.xml, network_security_config.xml and Firebase URLs from strings.xml </br>This tool also shows Deeplinks used in Android app </br>Developed by Satish Patnayak <a href='https://twitter.com/satish_patnayak'>satish_patnayak</a> </br> </br>Analysis results of <u>"+apkfile+"</u></h3>")
if file_extension == ".apk":
	#Decompile APK file 
	print("Please wait while I am analyzing Android app" + apkfile)
	if path.exists(resultsHtml):
		os.remove(resultsHtml)
		writeResults(filename, head +"<h3>This tool analyzes Android app to find vulnerabilities in AndroidManifest.xml, network_security_config.xml and Firebase URLs from strings.xml </br>This tool also shows Deeplinks used in Android app </br>Developed by Satish Patnayak <a href='https://twitter.com/satish_patnayak'>satish_patnayak</a> </br> </br>Analysis results of <u>"+apkfile+"</u></h3>")	
	os.system('java -jar apktool.jar d -q "' + apkfile +'"')
	isDebuggableOrBackup()
	network_security_config_Test(filename, nscFile)
	fireBaseTest(filename, stringsFile)
	getDeepLinks()
	try:
		f11=open(resultsHtmlTemp, "r")
		writeResults(filename, "</br><h3>Pass cases</h3>"+f11.read() + endhtml)
		f11.close()
		os.remove(resultsHtmlTemp)
	except IOError:
		writeResults(filename,endhtml)
	print("Results are printed in "+pwd+"\\"+resultsHtml)
# if file extension is not .apk
else:
	writeResults(filename,"</br>Please use apk file only")