#!/usr/bin/env python3
# network.py - Módulo mejorado para análisis de red
import nmap
import socket
import psutil
import logging
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger('security_scanner.network')

def obtener_interfaces_red():
    """
    Obtiene todas las interfaces de red con sus direcciones IP.
    
    Returns:
        dict: Diccionario con interfaces y sus direcciones IP
    """
    interfaces = {}
    try:
        for interfaz, datos in psutil.net_if_addrs().items():
            interfaces[interfaz] = {
                'direcciones': [],
                'estado': 'desconocido',
                'estadisticas': {}
            }
            
            # Obtener direcciones IP
            for dato in datos:
                if dato.family == socket.AF_INET:
                    interfaces[interfaz]['direcciones'].append({
                        'ip': dato.address,
                        'netmask': dato.netmask,
                        'broadcast': dato.broadcast
                    })
                elif dato.family == socket.AF_INET6:
                    interfaces[interfaz]['direcciones'].append({
                        'ipv6': dato.address,
                        'netmask': dato.netmask
                    })
                elif dato.family == psutil.AF_LINK:
                    interfaces[interfaz]['mac'] = dato.address
            
            # Obtener estadísticas si está disponible
            try:
                stats = psutil.net_if_stats().get(interfaz)
                if stats:
                    interfaces[interfaz]['estado'] = 'activo' if stats.isup else 'inactivo'
                    interfaces[interfaz]['estadisticas'] = {
                        'velocidad': f"{stats.speed} Mbps" if stats.speed > 0 else "desconocida",
                        'mtu': stats.mtu,
                        'duplex': stats.duplex if hasattr(stats, 'duplex') else "desconocido"
                    }
            except Exception as e:
                logger.warning(f"No se pudieron obtener estadísticas para {interfaz}: {e}")
                
    except Exception as e:
        logger.error(f"Error al obtener interfaces de red: {e}")
        return {"error": str(e)}
        
    return interfaces

def obtener_ip_local():
    """
    Obtiene la dirección IP local principal.
    
    Returns:
        str: Dirección IP local
    """
    try:
        # Intentar conectar a un servidor DNS público para determinar la interfaz de salida
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        logger.warning(f"No se pudo determinar IP mediante conexión externa: {e}")
        
        # Plan B: Buscar una IP no-loopback en las interfaces
        try:
            for _, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        return addr.address
        except Exception as e:
            logger.error(f"Error al buscar IP en interfaces: {e}")
            
        # Plan C: Usar localhost
        logger.warning("Usando dirección de loopback como último recurso")
        return "127.0.0.1"

def escanear_puerto(scanner, ip, puerto):
    """
    Escanea un puerto específico.
    
    Args:
        scanner: Instancia de nmap.PortScanner
        ip: Dirección IP a escanear
        puerto: Puerto a escanear
        
    Returns:
        dict: Información del puerto escaneado
    """
    try:
        scanner.scan(ip, arguments=f"-sT -p {puerto}")
        
        if ip not in scanner.all_hosts() or 'tcp' not in scanner[ip] or puerto not in scanner[ip]['tcp']:
            return {
                "puerto": puerto,
                "estado": "cerrado",
                "servicio": "desconocido"
            }
            
        info = scanner[ip]['tcp'][puerto]
        resultado = {
            "puerto": puerto,
            "estado": info['state'],
            "servicio": info.get('name', 'desconocido'),
            "producto": info.get('product', ''),
            "version": info.get('version', ''),
            "vulnerabilidades": []
        }
        
        # Solo analizar vulnerabilidades si el puerto está abierto
        if info['state'] == "open":
            try:
                scanner.scan(ip, arguments=f"-p {puerto} --script vulners")
                vulns = scanner[ip]['tcp'][puerto].get('script', {}).get('vulners', '')
                if vulns:
                    # Procesar y limpiar la salida de vulners
                    vulnerabilidades = []
                    for linea in vulns.split('\n'):
                        linea = linea.strip()
                        if linea and not linea.startswith('|'):
                            vulnerabilidades.append(linea)
                    resultado["vulnerabilidades"] = vulnerabilidades
            except Exception as e:
                logger.warning(f"Error al escanear vulnerabilidades en puerto {puerto}: {e}")
                resultado["vulnerabilidades"].append(f"Error al escanear: {str(e)}")
                
        return resultado
    except Exception as e:
        logger.error(f"Error al escanear puerto {puerto}: {e}")
        return {
            "puerto": puerto,
            "estado": "error",
            "error": str(e)
        }

def escanear_con_nmap(ip, puertos="22,80,443,3306,8080,21,23,25,53,110,143,445,3389", max_workers=5):
    """
    Escanea puertos en una dirección IP usando nmap.
    
    Args:
        ip: Dirección IP a escanear
        puertos: Lista de puertos a escanear (string separado por comas)
        max_workers: Número máximo de hilos para escaneo paralelo
        
    Returns:
        list: Lista de resultados del escaneo
    """
    try:
        # Validar IP
        ipaddress.ip_address(ip)
    except ValueError:
        logger.error(f"Dirección IP inválida: {ip}")
        return [{"error": f"Dirección IP inválida: {ip}"}]
    
    try:
        scanner = nmap.PortScanner()
        logger.info(f"🔍 Iniciando escaneo de puertos en {ip}...")
        
        # Obtener lista de puertos como enteros
        lista_puertos = [int(p.strip()) for p in puertos.split(',') if p.strip().isdigit()]
        
        if not lista_puertos:
            logger.warning("Lista de puertos vacía o inválida")
            return [{"error": "Lista de puertos vacía o inválida"}]
            
        # Escaneo inicial rápido para ver qué puertos responden
        scanner.scan(ip, arguments=f"-sT -p {puertos} --min-rate 1000")
        
        resultados = []
        
        # Si no hay resultados, devolver lista vacía
        if ip not in scanner.all_hosts() or 'tcp' not in scanner[ip]:
            logger.info("⚠️ No se encontraron puertos TCP abiertos.")
            return resultados
            
        # Escanear en detalle los puertos que respondieron
        puertos_detectados = list(scanner[ip]['tcp'].keys())
        
        # Usar ThreadPoolExecutor para escanear puertos en paralelo
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(escanear_puerto, scanner, ip, puerto) 
                      for puerto in puertos_detectados]
            
            for future in futures:
                try:
                    resultado = future.result()
                    resultados.append(resultado)
                    logger.debug(f"Puerto {resultado['puerto']} escaneado: {resultado['estado']}")
                except Exception as e:
                    logger.error(f"Error en escaneo paralelo: {e}")
        
        # Ordenar resultados por número de puerto
        resultados.sort(key=lambda x: x['puerto'])
        
        return resultados
        
    except Exception as e:
        logger.error(f"Error general en escaneo de puertos: {e}")
        return [{"error": f"Error en escaneo: {str(e)}"}]

def escanear_red_local(ip_base=None, mascara="/24", max_hosts=10):
    """
    Escanea hosts en la red local.
    
    Args:
        ip_base: IP base para escaneo (si es None, se usa la IP local)
        mascara: Máscara de red en formato CIDR
        max_hosts: Número máximo de hosts a escanear
        
    Returns:
        list: Lista de hosts activos
    """
    if not ip_base:
        ip_base = obtener_ip_local()
    
    # Crear red a partir de IP y máscara
    try:
        red = ipaddress.IPv4Network(f"{ip_base}{mascara}", strict=False)
        hosts = list(red.hosts())
        
        # Limitar número de hosts a escanear
        if len(hosts) > max_hosts:
            logger.warning(f"Limitando escaneo a {max_hosts} hosts de {len(hosts)} posibles")
            hosts = hosts[:max_hosts]
            
        logger.info(f"Escaneando {len(hosts)} hosts en la red {red}")
        
        scanner = nmap.PortScanner()
        hosts_activos = []
        
        # Escanear cada host
        for host in hosts:
            host_str = str(host)
            try:
                logger.debug(f"Escaneando host {host_str}...")
                scanner.scan(host_str, arguments="-sn")
                
                if host_str in scanner.all_hosts():
                    estado = scanner[host_str].state()
                    if estado == "up":
                        try:
                            nombre = socket.gethostbyaddr(host_str)[0]
                        except:
                            nombre = "desconocido"
                            
                        hosts_activos.append({
                            "ip": host_str,
                            "nombre": nombre,
                            "estado": estado
                        })
                        logger.info(f"Host activo encontrado: {host_str} ({nombre})")
            except Exception as e:
                logger.warning(f"Error al escanear host {host_str}: {e}")
                
        return hosts_activos
        
    except Exception as e:
        logger.error(f"Error al escanear red local: {e}")
        return [{"error": f"Error al escanear red: {str(e)}"}]

def escanear_red_completo(ip_base=None, mascara="/24", max_hosts=10, puertos_comunes="22,80,443,3306,8080,21,23,25,53,110,143,445,3389", intensidad_escaneo="normal"):
    """
    Escanea la red local para encontrar hosts activos y luego escanea sus puertos.
    
    Args:
        ip_base: IP base para escaneo (si es None, se usa la IP local)
        mascara: Máscara de red en formato CIDR
        max_hosts: Número máximo de hosts a escanear
        puertos_comunes: Lista de puertos a escanear (string separado por comas)
        intensidad_escaneo: Nivel de intensidad del escaneo ('ligero', 'normal', 'agresivo')
        
    Returns:
        dict: Resultados del escaneo de red con hosts y sus puertos abiertos
    """
    if not ip_base:
        ip_base = obtener_ip_local()
        
    logger.info(f"🌐 Iniciando escaneo completo de red {ip_base}{mascara}...")
    
    # Configurar parámetros según intensidad
    if intensidad_escaneo == "ligero":
        max_workers = 2
        timeout_scan = 2
        args_descubrimiento = "-sn -T2"
    elif intensidad_escaneo == "agresivo":
        max_workers = 10
        timeout_scan = 5
        args_descubrimiento = "-sn -T4"
    else:  # normal
        max_workers = 5
        timeout_scan = 3
        args_descubrimiento = "-sn -T3"
    
    try:
        # Crear red a partir de IP y máscara
        red = ipaddress.IPv4Network(f"{ip_base}{mascara}", strict=False)
        hosts = list(red.hosts())
        
        # Limitar número de hosts a escanear
        if len(hosts) > max_hosts:
            logger.warning(f"Limitando escaneo a {max_hosts} hosts de {len(hosts)} posibles")
            hosts = hosts[:max_hosts]
            
        logger.info(f"Escaneando {len(hosts)} hosts en la red {red}")
        
        # Inicializar scanner
        scanner = nmap.PortScanner()
        
        # Fase 1: Descubrimiento de hosts
        hosts_activos = []
        
        # Usar un enfoque más eficiente para descubrir hosts
        # Escanear rangos de IPs en lugar de una por una
        try:
            logger.info(f"Descubriendo hosts activos en {red}...")
            scanner.scan(hosts=str(red), arguments=args_descubrimiento)
            
            for host in scanner.all_hosts():
                if scanner[host].state() == "up":
                    try:
                        nombre = socket.gethostbyaddr(host)[0]
                    except:
                        nombre = "desconocido"
                        
                    hosts_activos.append({
                        "ip": host,
                        "nombre": nombre,
                        "estado": "up",
                        "mac": scanner[host].get("addresses", {}).get("mac", ""),
                        "vendor": scanner[host].get("vendor", {}).get(scanner[host].get("addresses", {}).get("mac", ""), "")
                    })
                    logger.info(f"Host activo encontrado: {host} ({nombre})")
        except Exception as e:
            logger.error(f"Error en descubrimiento de hosts: {e}")
            
            # Plan B: Escanear hosts individualmente si el escaneo de rango falló
            logger.info("Usando método alternativo para descubrir hosts...")
            for host in hosts:
                host_str = str(host)
                try:
                    scanner.scan(host_str, arguments="-sn")
                    
                    if host_str in scanner.all_hosts() and scanner[host_str].state() == "up":
                        try:
                            nombre = socket.gethostbyaddr(host_str)[0]
                        except:
                            nombre = "desconocido"
                            
                        hosts_activos.append({
                            "ip": host_str,
                            "nombre": nombre,
                            "estado": "up"
                        })
                        logger.info(f"Host activo encontrado: {host_str} ({nombre})")
                except Exception as e:
                    logger.warning(f"Error al escanear host {host_str}: {e}")
        
        logger.info(f"Descubrimiento completado. Encontrados {len(hosts_activos)} hosts activos.")
        
        # Fase 2: Escaneo de puertos en hosts activos
        resultados_red = {
            "red": str(red),
            "hosts_encontrados": len(hosts_activos),
            "timestamp": time.time(),
            "hosts": []
        }
        
        # Función para escanear un host completo
        def escanear_host_completo(host_info):
            ip = host_info["ip"]
            try:
                # Escaneo de puertos
                puertos_resultado = escanear_con_nmap(
                    ip, 
                    puertos=puertos_comunes, 
                    max_workers=max_workers
                )
                
                # Contar puertos abiertos
                puertos_abiertos = [p for p in puertos_resultado if p.get("estado") == "open"]
                
                # Añadir información de puertos al host
                host_info["puertos_escaneados"] = len(puertos_resultado)
                host_info["puertos_abiertos"] = len(puertos_abiertos)
                host_info["puertos"] = puertos_resultado
                
                # Intentar determinar el sistema operativo
                try:
                    scanner.scan(ip, arguments="-O")
                    os_matches = scanner[ip].get("osmatch", [])
                    if os_matches:
                        host_info["sistema_operativo"] = {
                            "nombre": os_matches[0].get("name", "Desconocido"),
                            "precision": os_matches[0].get("accuracy", "0")
                        }
                except Exception as e:
                    logger.warning(f"No se pudo determinar el SO de {ip}: {e}")
                
                return host_info
            except Exception as e:
                logger.error(f"Error al escanear host {ip}: {e}")
                host_info["error"] = str(e)
                return host_info
        
        # Escanear hosts en paralelo
        logger.info(f"Iniciando escaneo de puertos en {len(hosts_activos)} hosts activos...")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(escanear_host_completo, host) for host in hosts_activos]
            
            for future in futures:
                try:
                    host_resultado = future.result()
                    resultados_red["hosts"].append(host_resultado)
                    puertos_abiertos = host_resultado.get("puertos_abiertos", 0)
                    logger.info(f"Host {host_resultado['ip']} escaneado: {puertos_abiertos} puertos abiertos")
                except Exception as e:
                    logger.error(f"Error en escaneo paralelo de hosts: {e}")
        
        # Ordenar hosts por número de puertos abiertos (de más a menos)
        resultados_red["hosts"].sort(key=lambda x: x.get("puertos_abiertos", 0), reverse=True)
        
        # Añadir estadísticas
        total_puertos_abiertos = sum(host.get("puertos_abiertos", 0) for host in resultados_red["hosts"])
        resultados_red["estadisticas"] = {
            "total_puertos_abiertos": total_puertos_abiertos,
            "promedio_puertos_por_host": total_puertos_abiertos / len(hosts_activos) if hosts_activos else 0,
            "duracion_escaneo": time.time() - resultados_red["timestamp"]
        }
        
        logger.info(f"Escaneo de red completado. Encontrados {total_puertos_abiertos} puertos abiertos en total.")
        return resultados_red
        
    except Exception as e:
        logger.error(f"Error en escaneo completo de red: {e}")
        return {
            "error": str(e),
            "hosts": []
        }

def identificar_servicios_vulnerables(resultados_red):
    """
    Analiza los resultados del escaneo de red para identificar servicios potencialmente vulnerables.
    
    Args:
        resultados_red: Resultados del escaneo de red
        
    Returns:
        list: Lista de servicios vulnerables encontrados
    """
    servicios_vulnerables = []
    
    # Servicios conocidos por ser potencialmente inseguros
    servicios_riesgosos = {
        "telnet": "Telnet transmite datos en texto plano, incluyendo contraseñas",
        "ftp": "FTP puede transmitir credenciales en texto plano",
        "rsh": "Remote Shell tiene debilidades de autenticación conocidas",
        "rlogin": "Remote Login tiene debilidades de autenticación conocidas",
        "tftp": "Trivial FTP no requiere autenticación",
        "finger": "Finger puede revelar información de usuarios",
        "smtp": "Servidores SMTP mal configurados pueden ser usados para spam o revelar información",
        "snmp": "SNMP v1/v2 tienen debilidades de autenticación conocidas",
        "mysql": "Bases de datos expuestas a internet son objetivos comunes",
        "ms-sql-s": "SQL Server expuesto a internet es un objetivo común",
        "postgresql": "Bases de datos expuestas a internet son objetivos comunes",
        "vnc": "VNC puede tener contraseñas débiles o estar mal configurado",
        "rdp": "RDP puede ser vulnerable a ataques de fuerza bruta o tener vulnerabilidades conocidas",
        "smb": "SMB puede tener vulnerabilidades conocidas como EternalBlue",
        "netbios-ssn": "NetBIOS puede revelar información de la red",
        "http": "Servidores web pueden tener vulnerabilidades si no están actualizados",
        "https": "Servidores web pueden tener certificados inválidos o usar protocolos obsoletos",
        "ssh": "SSH puede tener configuraciones débiles o usar versiones antiguas"
    }
    
    # Versiones específicas conocidas por ser vulnerables
    versiones_vulnerables = {
        "OpenSSH 7.": "Puede contener vulnerabilidades si no está parcheado",
        "Apache 2.4.": "Versiones antiguas de Apache 2.4 pueden tener vulnerabilidades",
        "nginx 1.": "Versiones antiguas de nginx pueden tener vulnerabilidades",
        "Microsoft-IIS/7": "IIS 7 tiene vulnerabilidades conocidas",
        "Microsoft-IIS/6": "IIS 6 tiene vulnerabilidades críticas",
        "ProFTPD 1.3.": "Algunas versiones de ProFTPD 1.3.x tienen vulnerabilidades",
        "vsftpd 2.": "Algunas versiones antiguas de vsftpd tienen vulnerabilidades",
        "MySQL 5.": "Versiones antiguas de MySQL 5.x pueden tener vulnerabilidades",
        "Samba": "Algunas versiones de Samba son vulnerables a ataques",
    }
    
    try:
        for host in resultados_red.get("hosts", []):
            ip = host.get("ip", "desconocida")
            nombre = host.get("nombre", "desconocido")
            
            for puerto_info in host.get("puertos", []):
                if puerto_info.get("estado") != "open":
                    continue
                    
                puerto = puerto_info.get("puerto", 0)
                servicio = puerto_info.get("servicio", "").lower()
                producto = puerto_info.get("producto", "")
                version = puerto_info.get("version", "")
                
                # Verificar si es un servicio conocido como riesgoso
                if servicio in servicios_riesgosos:
                    servicios_vulnerables.append({
                        "ip": ip,
                        "nombre_host": nombre,
                        "puerto": puerto,
                        "servicio": servicio,
                        "producto": producto,
                        "version": version,
                        "riesgo": servicios_riesgosos[servicio],
                        "tipo": "servicio_riesgoso"
                    })
                
                # Verificar si es una versión conocida como vulnerable
                producto_version = f"{producto} {version}"
                for v_patron, v_riesgo in versiones_vulnerables.items():
                    if v_patron in producto_version:
                        servicios_vulnerables.append({
                            "ip": ip,
                            "nombre_host": nombre,
                            "puerto": puerto,
                            "servicio": servicio,
                            "producto": producto,
                            "version": version,
                            "riesgo": v_riesgo,
                            "tipo": "version_vulnerable"
                        })
                
                # Verificar vulnerabilidades detectadas por nmap
                if puerto_info.get("vulnerabilidades"):
                    servicios_vulnerables.append({
                        "ip": ip,
                        "nombre_host": nombre,
                        "puerto": puerto,
                        "servicio": servicio,
                        "producto": producto,
                        "version": version,
                        "vulnerabilidades": puerto_info.get("vulnerabilidades"),
                        "tipo": "vulnerabilidad_detectada"
                    })
        
        return servicios_vulnerables
    except Exception as e:
        logger.error(f"Error al identificar servicios vulnerables: {e}")
        return [{"error": str(e)}]