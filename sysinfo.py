#!/usr/bin/env python3
# sysinfo.py - Módulo mejorado para información del sistema
import platform
import os
import socket
import logging
import json
import subprocess
from datetime import datetime
import time

# Intentar importar módulos, con manejo de errores si no están disponibles
try:
    import distro
except ImportError:
    distro = None

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger('security_scanner.sysinfo')

def ejecutar_comando(comando):
    """
    Ejecuta un comando del sistema y devuelve su salida.
    
    Args:
        comando: Comando a ejecutar (string o lista)
        
    Returns:
        str: Salida del comando
    """
    try:
        if isinstance(comando, str):
            resultado = subprocess.run(comando, shell=True, capture_output=True, text=True, timeout=5)
        else:
            resultado = subprocess.run(comando, capture_output=True, text=True, timeout=5)
            
        if resultado.returncode == 0:
            return resultado.stdout.strip()
        else:
            logger.warning(f"Comando {comando} falló con código {resultado.returncode}: {resultado.stderr}")
            return ""
    except Exception as e:
        logger.error(f"Error al ejecutar comando {comando}: {e}")
        return ""

def obtener_info_sistema():
    """
    Obtiene información detallada del sistema.
    
    Returns:
        dict: Información del sistema
    """
    logger.info("Recopilando información del sistema...")
    
    info = {
        "nombre_host": platform.node(),
        "fecha_escaneo": datetime.now().isoformat(),
        "sistema_operativo": {
            "sistema": platform.system(),
            "version": platform.version(),
            "release": platform.release(),
            "arquitectura": platform.machine(),
        },
        "usuario_actual": os.getlogin() if hasattr(os, 'getlogin') else ejecutar_comando("whoami"),
        "uptime": None,
        "kernel": ejecutar_comando("uname -r"),
    }
    
    # Obtener información de distribución Linux si está disponible
    if distro:
        info["sistema_operativo"].update({
            "nombre": distro.name(),
            "version": distro.version(),
            "id": distro.id(),
            "like": distro.like(),
            "codename": distro.codename(),
        })
    else:
        # Intentar obtener información de /etc/os-release
        try:
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release") as f:
                    os_info = {}
                    for line in f:
                        if "=" in line:
                            key, value = line.strip().split("=", 1)
                            os_info[key] = value.strip('"')
                info["sistema_operativo"]["distribucion"] = os_info
        except Exception as e:
            logger.warning(f"No se pudo obtener información de distribución: {e}")
    
    # Información de CPU
    info["cpu"] = {
        "modelo": platform.processor() or ejecutar_comando("cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d: -f2").strip(),
    }
    
    # Información de memoria y CPU con psutil si está disponible
    if psutil:
        # CPU
        info["cpu"].update({
            "nucleos_fisicos": psutil.cpu_count(logical=False),
            "nucleos_logicos": psutil.cpu_count(logical=True),
            "uso_actual": psutil.cpu_percent(interval=1),
            "frecuencia_mhz": psutil.cpu_freq().current if psutil.cpu_freq() else None,
        })
        
        # Memoria
        mem = psutil.virtual_memory()
        info["memoria"] = {
            "total_mb": round(mem.total / (1024 * 1024), 2),
            "disponible_mb": round(mem.available / (1024 * 1024), 2),
            "usada_mb": round(mem.used / (1024 * 1024), 2),
            "porcentaje_uso": mem.percent,
        }
        
        # Disco
        info["discos"] = []
        for particion in psutil.disk_partitions():
            try:
                uso = psutil.disk_usage(particion.mountpoint)
                info["discos"].append({
                    "dispositivo": particion.device,
                    "punto_montaje": particion.mountpoint,
                    "sistema_archivos": particion.fstype,
                    "total_gb": round(uso.total / (1024**3), 2),
                    "usado_gb": round(uso.used / (1024**3), 2),
                    "libre_gb": round(uso.free / (1024**3), 2),
                    "porcentaje_uso": uso.percent,
                })
            except (PermissionError, OSError) as e:
                logger.warning(f"No se pudo acceder a {particion.mountpoint}: {e}")
        
        # Uptime
        info["uptime"] = round(time.time() - psutil.boot_time())
    else:
        # Alternativas si psutil no está disponible
        logger.warning("psutil no está disponible, usando métodos alternativos")
        
        # CPU cores
        cores = ejecutar_comando("nproc --all")
        if cores:
            info["cpu"]["nucleos_logicos"] = int(cores)
            
        # Memoria
        mem_info = ejecutar_comando("free -m | grep Mem")
        if mem_info:
            partes = mem_info.split()
            if len(partes) >= 7:
                info["memoria"] = {
                    "total_mb": int(partes[1]),
                    "usada_mb": int(partes[2]),
                    "libre_mb": int(partes[3]),
                    "disponible_mb": int(partes[6]),
                }
                
        # Uptime
        uptime = ejecutar_comando("cat /proc/uptime").split()
        if uptime:
            info["uptime"] = round(float(uptime[0]))
            
        # Discos
        df = ejecutar_comando("df -h --output=source,target,fstype,size,used,avail,pcent")
        if df:
            info["discos"] = []
            lineas = df.splitlines()
            if len(lineas) > 1:  # Ignorar la primera línea (encabezados)
                for linea in lineas[1:]:
                    partes = linea.split()
                    if len(partes) >= 7:
                        info["discos"].append({
                            "dispositivo": partes[0],
                            "punto_montaje": partes[1],
                            "sistema_archivos": partes[2],
                            "total": partes[3],
                            "usado": partes[4],
                            "disponible": partes[5],
                            "porcentaje_uso": partes[6],
                        })
    
    # Usuarios conectados
    usuarios = ejecutar_comando("who")
    if usuarios:
        info["usuarios_conectados"] = []
        for linea in usuarios.splitlines():
            partes = linea.split()
            if len(partes) >= 5:
                info["usuarios_conectados"].append({
                    "usuario": partes[0],
                    "terminal": partes[1],
                    "fecha": " ".join(partes[2:4]),
                    "desde": partes[4].strip("()") if "(" in partes[4] else "",
                })
    
    # Procesos en ejecución
    if psutil:
        info["procesos"] = {
            "total": len(psutil.pids()),
            "ejecutandose": len([p for p in psutil.process_iter(['status']) if p.info['status'] == 'running']),
        }
    else:
        procesos = ejecutar_comando("ps -e | wc -l")
        if procesos:
            info["procesos"] = {
                "total": int(procesos.strip()),
            }
    
    logger.info("Información del sistema recopilada correctamente")
    return info

def obtener_usuarios_sistema():
    """
    Obtiene la lista de usuarios del sistema.
    
    Returns:
        list: Lista de usuarios con información detallada
    """
    logger.info("Obteniendo información de usuarios del sistema...")
    
    usuarios = []
    try:
        with open("/etc/passwd", "r") as f:
            for linea in f:
                partes = linea.strip().split(":")
                if len(partes) >= 7:
                    usuario = {
                        "nombre": partes[0],
                        "uid": int(partes[2]),
                        "gid": int(partes[3]),
                        "info": partes[4],
                        "home": partes[5],
                        "shell": partes[6],
                    }
                    
                    # Verificar si es un usuario del sistema o real
                    if usuario["uid"] >= 1000 and usuario["shell"] != "/usr/sbin/nologin" and usuario["shell"] != "/bin/false":
                        usuario["tipo"] = "usuario"
                    else:
                        usuario["tipo"] = "sistema"
                        
                    usuarios.append(usuario)
        
        logger.info(f"Obtenidos {len(usuarios)} usuarios del sistema")
        return usuarios
    except Exception as e:
        logger.error(f"Error al obtener usuarios del sistema: {e}")
        return [{"error": str(e)}]

def obtener_servicios_activos():
    """
    Obtiene la lista de servicios activos en el sistema.
    
    Returns:
        list: Lista de servicios activos
    """
    logger.info("Obteniendo servicios activos...")
    
    servicios = []
    try:
        # Intentar con systemctl
        resultado = ejecutar_comando("systemctl list-units --type=service --state=running --no-pager --plain")
        
        if resultado:
            for linea in resultado.splitlines():
                partes = linea.split()
                if len(partes) >= 4 and partes[0].endswith(".service"):
                    nombre = partes[0].replace(".service", "")
                    estado = partes[3]
                    descripcion = " ".join(partes[4:]) if len(partes) > 4 else ""
                    
                    servicios.append({
                        "nombre": nombre,
                        "estado": estado,
                        "descripcion": descripcion,
                    })
        else:
            # Alternativa: usar ps para ver procesos de servicios
            logger.warning("systemctl no disponible, usando ps como alternativa")
            resultado = ejecutar_comando("ps -eo comm,user,pid,ppid,args | grep -v grep")
            
            if resultado:
                procesos_vistos = set()
                for linea in resultado.splitlines():
                    partes = linea.split(None, 4)
                    if len(partes) >= 5:
                        nombre = partes[0]
                        usuario = partes[1]
                        pid = partes[2]
                        
                        # Evitar duplicados
                        if nombre in procesos_vistos:
                            continue
                            
                        procesos_vistos.add(nombre)
                        servicios.append({
                            "nombre": nombre,
                            "usuario": usuario,
                            "pid": pid,
                            "comando": partes[4],
                        })
        
        logger.info(f"Obtenidos {len(servicios)} servicios activos")
        return servicios
    except Exception as e:
        logger.error(f"Error al obtener servicios activos: {e}")
        return [{"error": str(e)}]