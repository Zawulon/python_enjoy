import datetime
a = datetime.datetime.now()
dictionary = {}
f = open(r'nmap-os-db_import_fingerprint.txt')

for line in f.readlines():
	if line[0:1] == 'F':
		sep = line.index('|')
		dictionary[line[sep+1:].rstrip()] = line[0:sep]
f.close()
b = datetime.datetime.now()
#print dictionary['SEQ(SP=B-15%GCD=A000|14000|1E000|28000|32000%ISR=AB-B5%TI=I%II=I%SS=S%TS=U),OPS(O1=|M584%O2=|M584%O3=|M584%O4=|M584%O5=|M584%O6=|M584)                                       ,WIN(W1=0|5B40%W2=0|5B40%W3=0|5B40%W4=0|5B40%W5=0|5B40%W6=0|5B40),ECN(R=Y%DF=N%T=FE%TG=FF%W=0|5B40%O=|M584%CC=N|Y%Q=),T1(R=Y%DF=N%T=FE%TG=FF%S=O|Z%A=S+%F=AR|AS%RD=0%Q=),T2(R=N)                                       ,T3(R=Y%DF=N%T=FE%TG=FF%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)                                                        ,T4(R=Y%DF=N%T=FE%TG=FF%W=0%S=A%A=Z%F=R%O=%RD=0%Q=),T5(R=Y%DF=N%T=FE%TG=FF%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=),T6(R=Y%DF=N%T=FE%TG=FF%W=0%S=A%A=Z%F=R%O=%RD=0%Q=),T7(R=Y%DF=N%T=FE%TG=FF%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=),U1(DF=N%T=FE%TG=FF%IPL=38%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=D624%RUD=G),IE(DFI=N%T=FE%TG=FF%CD=S)']
#print dictionary['SEQ(SP=8B-95%GCD=1-6%ISR=91-9B%TI=I%II=RI%SS=O%TS=1)                       ,OPS(O1=M5A4NW0NNT11%O2=M5A4NW0NNT11%O3=M5A4NW0NNT11%O4=M5A4NW0NNT11%O5=M5A4NW0NNT11%O6=M5A4NNT11),WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)            ,ECN(R=Y%DF=N%T=19-23%TG=20%W=2000%O=M5A4NW0%CC=N)  ,T1(R=Y%DF=N%T=19-23%TG=20%S=O%A=S+%F=AS%RD=0)     ,T2(R=N)                                       ,T3(R=Y%DF=N%T=19-23%TG=20%W=2000%S=O%A=S+%F=AS%O=M5A4NW0NNT11NNLLLLLLLLLL|M5A4NW0NNT11W27W27NNLLLL%RD=0)    ,T4(R=N)                                           ,T5(R=Y%DF=N%T=19-23%TG=20%W=0%S=Z%A=S+%F=AR%RD=0)   ,T6(R=N)                                           ,T7(R=N)                                            ,U1(DF=N%T=19-23%TG=20%IPL=38%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G),IE(DFI=S%T=19-23%TG=20%CD=S)']

#print dictionary['SEQ(SP=C7%GCD=1%ISR=CD%TI=Z%CI=Z%TS=A)                                     ,OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11)     ,WIN(W1=16A0%W2=16A0%W3=16A0%W4=16A0%W5=16A0%W6=16A0)            ,ECN(R=Y%DF=Y%TG=40%W=16D0%O=M5B4NNSNW7%CC=N%Q=)    ,T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)          ,T2(R=Y%DF=Y%TG=40%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=),T3(R=Y%DF=Y%TG=40%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)                                                              ,T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)     ,T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)     ,T6(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)     ,T7(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)    ,U1(R=N)                                                             ,IE(R=N)']
c = datetime.datetime.now()
createdict = b - a
findindict = c - b
print createdict.microseconds
print findindict.microseconds

fo = open('102.done','w')
f = open(r'102')
for line in f.readlines():
    columns = line.split('\t')
    ip_column = columns[0]
    timestamp_column = columns[1]
    fingerprint_column = columns[2].rstrip()
    omitSCAN = fingerprint_column.index(',')
    
    keylook = fingerprint_column[omitSCAN+1:]
#    print dictionary[keylook]    
    if keylook in dictionary:
       resline = ip_column + ',' + timestamp_column + ',' + fingerprint_column + ',MACH:' + keylook
    else: 
       resline = ip_column + ',' + timestamp_column + ',' + fingerprint_column + ',-----'
    fo.writelines(resline)    
    
f.close()
fo.close()
raw_input("")