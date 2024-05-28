import dns_solver_funcs as DNS

dom:str = input("Ingrese el dominio a resolver: ") #Usuario ingresa dominio a resolver
root_ip:str = input("Ingrese Root Server a utilizar: ") #Usuario ingresa Root Server a utilizar

roots_validos:list[str] = ['198.41.0.4', "170.247.170.2", "192.33.4.12", '199.7.91.13', '192.5.5.241', '192.203.230.10', '192.112.36.4', '128.63.2.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

if not (root_ip in roots_validos): #chequeamos que la IP del Root sea válida
    print("La IP proporcionada no pertenece a un Root Server")
else:
    rta = DNS.get_ip_from_dom(dom, root_ip)
    if rta is None:
        print("No se pudo encontrar el dominio solicitado, reintente") #cuando se sobrepasó la cantidad de intentos de consulta a un server
    else:
        print("Algunas direcciones ip para", dom, "son:", rta) #mostrar respuesta
