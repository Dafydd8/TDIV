import dns_solver_funcs as DNS
roots_validos:list[str] = ['198.41.0.4', "170.247.170.2", "192.33.4.12", '199.7.91.13', '192.5.5.241', '192.203.230.10', '192.112.36.4', '128.63.2.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

entrada:str = input("Ingrese el dominio a resolver y (opcional) IP del root a usar: ").strip() #Usuario ingresa dominio a resolver

items:list[str] = entrada.split(" ")

if len(items) == 2 and items[1] in roots_validos:
    root_ip:str = items[1]
elif len(items) == 1:
    root_ip:str = "192.33.4.12" #IP Root Server hardcodeada
else:
    print("Los parámetros pasados no son válidos")
    quit()

dom:str = items[0]
rta = DNS.get_ip_from_dom(dom, root_ip)
if rta is None:
    print("Hubo un error, reintente") #cuando se sobrepasó la cantidad de intentos de consulta a un server
elif len(rta) == 0:
    print("No se encontraron IPs para", dom) #mostrar respuesta
else:
    print("Algunas direcciones ip para", dom, "son:", rta) #mostrar respuesta
