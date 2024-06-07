import scapy.all as scapy
from socket import *
import time
import sys 

def query_A(source:str, ip_server:str, intentos:int):
  '''
  Realiza una query tipo A a ip_server usando source como hostname y devuelve la DNS response obtenida.
  '''
  if intentos == 0: #Si ya enviamos muchas querys y no obtuvimos respuesta, nos rendimos.
    return None
  else:
    #creamos socket
    connectionSocket = socket(AF_INET, SOCK_DGRAM)

    #armamos y enviamos paquete (como bytes)
    pck = scapy.DNS(rd = 0, qd = scapy.DNSQR( qname = source, qtype = "A"))
    pck_bytes = scapy.raw(pck)
    connectionSocket.sendto(pck_bytes, (ip_server, 53))

    time.sleep(0.01) #espera de 10 ms a que llegue una respuesta

    try:
      #intentamos obtener rta
      data, addr = connectionSocket.recvfrom(512)
    
      connectionSocket.close() #cerramos socket

      #convertimos los bytes recibidos en un paquete de scapy para analizarlo más fácil
      response = scapy.DNS(data)
      return response
      
    except ConnectionResetError:
      #Si no se obtuvo respuesta, esperamos un segundo y reintentamos decrementando la cantidad de intentos restantes.
      print("No hubo respuesta. Reintentando...")
      time.sleep(1)
      connectionSocket.close() #cerramos socket
      query_A(source, ip_server, intentos - 1)

#Esta función toma una lista de registros NS o CNAME e intenta buscar las IPs asociadas a los mismos.
def resolver_ns_cname(regs, server_ip):
  '''
  Intenta obtener IPs autoritativas para al menos un registro en regs.
  '''
  i = 0
  ips_conseguidas = []
  while (i < len(regs) and len(ips_conseguidas) == 0):
    ips_conseguidas = get_ip_from_dom(regs[i], server_ip)
    i = i + 1
  return ips_conseguidas

def get_next_ips(source:str, ip_server:str, root_ip:str):
  '''
  Intenta obtener las IPs de los servidores de siguiente jerarquía en una busqueda DNS para resolver el hostname source.
  '''
  intentos:int = 3 #Máximo de 3 intentos por nivel de jerarquía
  response = query_A(source, ip_server, intentos) #Realizar query A y obtener respuesta

  #Si sobrepasamos cantidad máxima de intentos, abortamos.
  if response is None: 
    return None

  ips:list[str] = []
  regs_cname:list[str] = []
  regs_ns:list[str] = []

  eraAutoritativo:bool = False #Solamente habremos encontrado servers autoritativos cuando hayan regs A en sección answer

  #Analizamos seccion answer y guardamos los reistros A y CNAME recibidos
  for i in range(response.ancount):
    reg = response.an[i]
    if reg.type == 1:  # si es de Tipo A
      ips.append(reg.rdata)
      eraAutoritativo = True
    elif reg.type == 5: # si es Tipo CNAME
      regs_cname.append(reg.rdata.decode())
      #regs_cname.append(limpiar(str(reg.rdata))[1:])

  #Analizamos seccion additional records y guardamos los reistros A recibidos
  for i in range(response.arcount):
    reg = response.ar[i]
    if reg.type == 1:  # si es de Tipo A
      ips.append(reg.rdata)
  
  #Analizamos seccion ns y guardamos los reistros NS recibidos
  for i in range(response.nscount):
    reg = response.ns[i]
    if reg.type == 2:
      regs_ns.append(reg.rdata.decode())
  
  conseguiIPs:bool = len(ips) != 0
  IPsRepetidas:bool = ip_server in ips #Esto chequea que no nos hayan devuelto las mismas IPs que teníamos desde la consulta anterior

  if not conseguiIPs or IPsRepetidas:
    #ESTE BLOQUE TRATA DE CONSEGUIR IPS DESDE CNAMES 
    if len(regs_cname) != 0:
      ips_conseguidas_desde_cname = resolver_ns_cname(regs_cname, root_ip)
      if ips_conseguidas_desde_cname is None:
        return None
      if len(ips_conseguidas_desde_cname) != 0:
        ips = ips_conseguidas_desde_cname
        eraAutoritativo = True #Resuelta la IP final desde el CNAME, garantizamos haber encontrado IPs de los autoritativos.

    #ESTE BLOQUE TRATA DE CONSEGUIR IPS DESDE NS
    if  len(ips) == 0 and response.nscount != 0:
      ips_conseguidas_desde_ns = resolver_ns_cname(regs_ns, root_ip)
      if ips_conseguidas_desde_ns is None:
        return None
      if len(ips_conseguidas_desde_ns) != 0:
        ips = ips_conseguidas_desde_ns

  return ips, eraAutoritativo

def get_ip_from_dom(dom:str, root_ip:str):
  '''
  Resuelve una consulta DNS iterativa para un dominio dom. Devuelve una lista de IPs asociadas a dom. 
  '''
  eraAutoritativo:bool = False
  ips_server:list[str] = [root_ip]
  i:int = 0
  ips_obtenidas:list[str] = []
  while(not eraAutoritativo and i < len(ips_server) and len(ips_obtenidas) == 0): #Iteramos mientras no hayamos conseguido IPs, las obtenidas no sean autoritativas de server autorit. y queden IPs por consultar
    #while len(ips_obtenidas) == 0 and i < len(ips_server): #Iteramos mientras no hayamos obtenido IPs y queden IPs por consultar.
    ips_obtenidas, eraAutoritativo = get_next_ips(dom, ips_server[i], root_ip)
    if ips_obtenidas is None:
      return None
    i+=1
    if len(ips_obtenidas) != 0: #Si obtuvimos IPs en la query actual, sobreescribimos ips_server para utilizarlas en prox iteración.
      i = 0
      ips_server = ips_obtenidas
      if not eraAutoritativo:
        ips_obtenidas = []
  return ips_obtenidas
