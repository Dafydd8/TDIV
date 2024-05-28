import dns_solver_funcs as DNS

root_ip:str = "192.33.4.12" #IP Root Server hardcodeada

dom:str = input("Ingrese el dominio a resolver: ") #usuario ingresa dominio a resolver

rta = DNS.get_ip_from_dom(dom, root_ip) #llamado a función que resuelve
if rta is None:
    print("No se pudo encontrar el dominio solicitado, reintente") #cuando se sobrepasó la cantidad de intentos de consulta a un server
else:
    print("Algunas direcciones ip para", dom, "son:", rta) #mostrar respuesta
