#!/usr/bin/env python3
# permissions.py - Módulo mejorado para análisis de permisos
import os
import stat
import pwd
import grp
import logging
from pathlib import Path
import re

logger = logging.getLogger('security_scanner.permissions')

# Lista ampliada de archivos/directorios críticos a revisar
ARCHIVOS_CRITICOS = [
    # Archivos de configuración del sistema
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_config",
    "/etc/hosts",
    "/etc/hosts.allow",
    "/etc/hosts.deny",
    
    # Directorios importantes
    "/root",
    "/home",
    "/var/www",
    "/var/log",
    "/var/spool/cron",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.monthly",
    "/etc/cron.weekly",
    
    # Archivos de inicio
    "/etc/rc.local",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/crontab",
    
    # Archivos de configuración de servicios
    "/etc/apache2/apache2.conf",
    "/etc/nginx/nginx.conf",
    "/etc/mysql/my.cnf",
    "/etc/php/*/php.ini",
]

def analizar_permisos(ruta):
    """
    Analiza los permisos de un archivo o directorio.
    
    Args:
        ruta: Ruta del archivo o directorio a analizar
        
    Returns:
        dict: Información de permisos del archivo/directorio
    """
    try:
        # Expandir la ruta si contiene comodines
        if '*' in ruta:
            rutas_expandidas = list(Path('/').glob(ruta.lstrip('/')))
            if not rutas_expandidas:
                return {
                    "ruta": ruta,
                    "error": "No se encontraron archivos que coincidan con el patrón"
                }
            # Analizar solo el primer archivo encontrado
            ruta = str(rutas_expandidas[0])
            
        # Obtener información del archivo
        info = os.stat(ruta)
        modo = info.st_mode
        permisos = stat.filemode(modo)
        
        # Obtener propietario y grupo
        try:
            propietario = pwd.getpwuid(info.st_uid).pw_name
        except KeyError:
            propietario = str(info.st_uid)
            
        try:
            grupo = grp.getgrgid(info.st_gid).gr_name
        except KeyError:
            grupo = str(info.st_gid)
        
        # Analizar si los permisos son inseguros
        es_directorio = stat.S_ISDIR(modo)
        permisos_inseguros = False
        razones_inseguridad = []
        
        # Verificar permisos de escritura para grupo y otros
        if permisos[2] == "w":  # Usuario con escritura (normalmente está bien)
            pass
        if permisos[5] == "w":  # Grupo con escritura
            if es_directorio and ruta not in ["/home", "/var/www"]:
                permisos_inseguros = True
                razones_inseguridad.append("Grupo tiene permisos de escritura")
            elif not es_directorio and ruta in ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]:
                permisos_inseguros = True
                razones_inseguridad.append("Grupo tiene permisos de escritura en archivo crítico")
        if permisos[8] == "w":  # Otros con escritura
            permisos_inseguros = True
            razones_inseguridad.append("Todos los usuarios tienen permisos de escritura")
            
        # Verificar permisos SUID/SGID
        if modo & stat.S_ISUID:
            if not es_directorio:
                razones_inseguridad.append("Archivo con bit SUID activado")
                # Solo marcar como inseguro si no es un binario común con SUID
                if ruta not in ["/bin/su", "/bin/sudo", "/usr/bin/passwd"]:
                    permisos_inseguros = True
        if modo & stat.S_ISGID:
            if not es_directorio:
                razones_inseguridad.append("Archivo con bit SGID activado")
                permisos_inseguros = True
                
        # Verificar permisos de ejecución para todos en directorios sensibles
        if es_directorio and permisos[9] == "x" and ruta in ["/root", "/etc/sudoers.d"]:
            permisos_inseguros = True
            razones_inseguridad.append("Directorio sensible con permisos de ejecución para todos")
            
        return {
            "ruta": ruta,
            "tipo": "directorio" if es_directorio else "archivo",
            "permisos": permisos,
            "permisos_octal": oct(modo & 0o777),
            "propietario": propietario,
            "grupo": grupo,
            "tamaño": info.st_size,
            "ultima_modificacion": info.st_mtime,
            "inseguro": permisos_inseguros,
            "razones_inseguridad": razones_inseguridad
        }

    except Exception as e:
        logger.error(f"Error al analizar permisos de {ruta}: {e}")
        return {
            "ruta": ruta,
            "error": str(e)
        }

def escanear_archivos_criticos(archivos=None):
    """
    Escanea los permisos de archivos críticos del sistema.
    
    Args:
        archivos: Lista personalizada de archivos a escanear (opcional)
        
    Returns:
        list: Lista de resultados del análisis de permisos
    """
    if archivos is None:
        archivos = ARCHIVOS_CRITICOS
        
    resultados = []
    archivos_inseguros = 0
    
    for archivo in archivos:
        resultado = analizar_permisos(archivo)
        resultados.append(resultado)
        
        if resultado.get("inseguro", False):
            archivos_inseguros += 1
            logger.warning(f"Archivo con permisos inseguros: {archivo}")
            
    logger.info(f"Escaneados {len(resultados)} archivos críticos. {archivos_inseguros} con permisos inseguros.")
    return resultados

def buscar_archivos_suid_sgid(directorio="/"):
    """
    Busca archivos con bits SUID/SGID en el sistema.
    
    Args:
        directorio: Directorio desde donde iniciar la búsqueda
        
    Returns:
        list: Lista de archivos con SUID/SGID
    """
    logger.info(f"Buscando archivos SUID/SGID desde {directorio}...")
    
    try:
        # Usar find para buscar archivos SUID/SGID (más eficiente que recorrer el sistema de archivos)
        import subprocess
        cmd = f"find {directorio} -type f \$$ -perm -4000 -o -perm -2000 \$$ -ls 2>/dev/null"
        resultado = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        archivos = []
        for linea in resultado.stdout.splitlines():
            # Parsear la salida de find
            partes = re.split(r'\s+', linea.strip(), 10)
            if len(partes) >= 11:
                permisos = partes[2]
                propietario = partes[4]
                grupo = partes[5]
                tamaño = partes[6]
                ruta = partes[10]
                
                tipo_bit = ""
                if 's' in permisos[3:6]:  # SUID
                    tipo_bit = "SUID"
                if 's' in permisos[6:9]:  # SGID
                    tipo_bit += " SGID" if tipo_bit else "SGID"
                    
                archivos.append({
                    "ruta": ruta,
                    "permisos": permisos,
                    "propietario": propietario,
                    "grupo": grupo,
                    "tamaño": tamaño,
                    "tipo_bit": tipo_bit
                })
                
        logger.info(f"Encontrados {len(archivos)} archivos con bits SUID/SGID")
        return archivos
        
    except Exception as e:
        logger.error(f"Error al buscar archivos SUID/SGID: {e}")
        return [{"error": str(e)}]

def verificar_permisos_directorios_home():
    """
    Verifica los permisos de los directorios home de los usuarios.
    
    Returns:
        list: Lista de resultados del análisis
    """
    logger.info("Verificando permisos de directorios home...")
    
    try:
        resultados = []
        
        # Obtener todos los usuarios del sistema
        with open("/etc/passwd", "r") as f:
            for linea in f:
                partes = linea.strip().split(":")
                if len(partes) >= 6:
                    usuario = partes[0]
                    home_dir = partes[5]
                    
                    # Verificar solo directorios home válidos
                    if home_dir and home_dir != "/" and os.path.exists(home_dir):
                        resultado = analizar_permisos(home_dir)
                        resultado["usuario"] = usuario
                        resultados.append(resultado)
                        
                        # Verificar también archivos de configuración importantes
                        for archivo in [".bashrc", ".bash_profile", ".ssh/authorized_keys"]:
                            ruta_completa = os.path.join(home_dir, archivo)
                            if os.path.exists(ruta_completa):
                                resultado_archivo = analizar_permisos(ruta_completa)
                                resultado_archivo["usuario"] = usuario
                                resultados.append(resultado_archivo)
                        
        logger.info(f"Verificados {len(resultados)} directorios y archivos de usuarios")
        return resultados
        
    except Exception as e:
        logger.error(f"Error al verificar directorios home: {e}")
        return [{"error": str(e)}]