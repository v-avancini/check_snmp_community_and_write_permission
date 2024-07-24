from pysnmp.hlapi import *
import ipaddress
import time

def check_write_snmp(ip, community):
    snmp_engine = SnmpEngine()
    community_data = CommunityData(community, mpModel=0)
    #print (str(ip))
    transport_target = UdpTransportTarget((str(ip), 161), timeout=0.1, retries=1)
    object_identity = ObjectIdentity('1.3.6.1.2.1.1.5.0') #OID sysName
    original_value = None

    try:
        #Obter valor atual na OID
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(snmp_engine, community_data, transport_target, ContextData(), ObjectType(object_identity)))

        if errorIndication:
            #print "Erro ao tentar ler o valor atual via SNMP: ", errorIndication
            return False
        elif errorStatus:
            #print "Erro de status ao tentar ler o valor atual: ", errorStatus.prettyPrint()
            return False
        else:
            original_value = varBinds[0][1]

        #Escreve novo valor temporario
        new_value = 'Teste de Escrita'
        errorIndication, errorStatus, errorIndex, varBinds = next(
            setCmd(snmp_engine, community_data, transport_target, ContextData(), ObjectType(object_identity, new_value)))

        if errorIndication:
            #print "Erro ao tentar escrever via SNMP: ", errorIndication
            return False
        elif errorStatus:
            #print "Erro de status ao tentar escrever: ", errorStatus.prettyPrint()
            return False
        else:
           print original_value, ip

        #Reverte escrita para o valor original
        errorIndication, errorStatus, errorIndex, varBinds = next(
            setCmd(snmp_engine, community_data, transport_target, ContextData(), ObjectType(object_identity, original_value)))

        if errorIndication:
            #print "Erro ao tentar reverter o valor via SNMP: ", errorIndication
            return False
        elif errorStatus:
            #print "Erro de status ao tentar reverter o valor: ", errorStatus.prettyPrint()
            return False

        return True
    except Exception as e:
         #print "Excecao ao tentar verificar permissao de escrita SNMP: ", str(e)
         return False

ip_sw = '172.16.170.28'
community_snmp = 'public'
subrede = '172.16.170.0/24'
inicio_tempo = time.time()

#check_write_snmp(ip_sw, community_snmp)

rede = ipaddress.ip_network(unicode(subrede, 'utf-8'))
for ip in rede:
    if check_write_snmp(ip, community_snmp):
        print "SNMP public com permissao de escrita"
    else:
        print ip,"Nao possui SNMP public com permissao de escrita"

fim_tempo = time.time()
tempo_execucao_segundos = fim_tempo - inicio_tempo
tempo_execucao_minutos = int(tempo_execucao_segundos / 60.0)
print "-----------------------------------"
print "Tempo de execucao: {} minutos".format(tempo_execucao_minutos),"     |"
print "-----------------------------------"
