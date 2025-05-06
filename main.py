#!/usr/bin/env python3
# main.py - Script principal mejorado con escaneo de red completo
import argparse
import os
import sys
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Importaciones de módulos propios
from sysinfo import obtener_info_sistema
from permissions import escanear_archivos_criticos
from network import (
    obtener_interfaces_red, 
    obtener_ip_local, 
    escanear_con_nmap, 
    escanear_red_completo, 
    identificar_servicios_vulnerables
)
from report import guardar_json, guardar_txt, guardar_html, generar_reporte_resumen

# Configuración de logging
def configurar_logging(nivel=logging.INFO):
    """Configura el sistema de logging."""
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f'logs/scanner_{timestamp}.log'
    
    logging.basicConfig(
        level=nivel,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger('security_scanner')

def generar_info(logger, escanear_red=True, escaneo_red_completo=False, max_hosts=10, intensidad="normal"):
    """
    Genera toda la información del sistema y red.
    
    Args:
        logger: Logger para registrar eventos
        escanear_red: Si se debe escanear la red local
        escaneo_red_completo: Si se debe realizar un escaneo completo de la red
        max_hosts: Número máximo de hosts a escanear en la red
        intensidad: Intensidad del escaneo ('ligero', 'normal', 'agresivo')
    
    Returns:
        dict: Información recopilada del sistema y red
    """
    logger.info("Iniciando recopilación de información del sistema...")
    
    # Información del sistema
    try:
        info_sistema = obtener_info_sistema()
        logger.info("Información del sistema obtenida correctamente")
    except Exception as e:
        logger.error(f"Error al obtener información del sistema: {e}")
        info_sistema = {"error": str(e)}
    
    # Permisos de archivos críticos
    try:
        permisos = escanear_archivos_criticos()
        logger.info(f"Escaneados {len(permisos)} archivos críticos")
    except Exception as e:
        logger.error(f"Error al escanear permisos: {e}")
        permisos = [{"error": str(e)}]
    
    # Información de red
    try:
        interfaces = obtener_interfaces_red()
        ip_local = obtener_ip_local()
        logger.info(f"Información de red obtenida. IP local: {ip_local}")
    except Exception as e:
        logger.error(f"Error al obtener información de red: {e}")
        interfaces = {"error": str(e)}
        ip_local = "127.0.0.1"
    
    # Compilar información básica
    info = {
        "timestamp": datetime.now().isoformat(),
        "sistema": info_sistema,
        "permisos_archivos_criticos": permisos,
        "interfaces_red": interfaces,
        "ip_local": ip_local,
    }
    
    # Escaneo de red (opcional)
    if escanear_red:
        # Escaneo básico de puertos locales
        try:
            logger.info(f"Iniciando escaneo de puertos en {ip_local}...")
            puertos_abiertos = escanear_con_nmap(ip_local)
            info["puertos_abiertos"] = puertos_abiertos
            logger.info(f"Escaneo de puertos completado. Encontrados {len(puertos_abiertos)} puertos.")
        except Exception as e:
            logger.error(f"Error durante el escaneo de puertos: {e}")
            info["puertos_abiertos"] = [{"error": str(e)}]
        
        # Escaneo completo de red (si se solicita)
        if escaneo_red_completo:
            try:
                logger.info(f"Iniciando escaneo completo de red local...")
                red_local = escanear_red_completo(
                    ip_base=ip_local,
                    mascara="/24",
                    max_hosts=max_hosts,
                    intensidad_escaneo=intensidad
                )
                
                # Identificar servicios vulnerables
                logger.info("Analizando servicios vulnerables en la red...")
                servicios_vulnerables = identificar_servicios_vulnerables(red_local)
                
                # Añadir a la información recopilada
                info["red_local"] = red_local
                info["servicios_vulnerables"] = servicios_vulnerables
                
                logger.info(f"Escaneo de red completado. Encontrados {red_local.get('hosts_encontrados', 0)} hosts.")
                logger.info(f"Identificados {len(servicios_vulnerables)} servicios potencialmente vulnerables.")
            except Exception as e:
                logger.error(f"Error durante el escaneo completo de red: {e}")
                info["red_local"] = {"error": str(e)}
                info["servicios_vulnerables"] = []
    
    return info

def generar_reportes(info, formatos, directorio="reportes", logger=None):
    """Genera los reportes en los formatos especificados."""
    if not os.path.exists(directorio):
        os.makedirs(directorio)
    
    resultados = {}
    
    # Usar ThreadPoolExecutor para generar reportes en paralelo
    with ThreadPoolExecutor(max_workers=len(formatos)) as executor:
        futures = []
        
        if "json" in formatos:
            futures.append(executor.submit(guardar_json, info, directorio))
        if "txt" in formatos:
            futures.append(executor.submit(guardar_txt, info, directorio))
        if "html" in formatos:
            futures.append(executor.submit(guardar_html, info, directorio))
        
        for future in futures:
            try:
                nombre_archivo = future.result()
                if nombre_archivo.endswith('.json'):
                    resultados['json'] = nombre_archivo
                elif nombre_archivo.endswith('.txt'):
                    resultados['txt'] = nombre_archivo
                elif nombre_archivo.endswith('.html'):
                    resultados['html'] = nombre_archivo
                
                if logger:
                    logger.info(f"Reporte generado: {os.path.join(directorio, nombre_archivo)}")
            except Exception as e:
                if logger:
                    logger.error(f"Error al generar reporte: {e}")
    
    # Generar resumen ejecutivo
    try:
        resumen = generar_reporte_resumen(info)
        print("\n" + "=" * 80)
        print("RESUMEN EJECUTIVO DEL ESCANEO")
        print("=" * 80)
        print(resumen)
        print("=" * 80 + "\n")
    except Exception as e:
        if logger:
            logger.error(f"Error al generar resumen ejecutivo: {e}")
    
    return resultados

def main():
    """Función principal del programa."""
    parser = argparse.ArgumentParser(
        description="Herramienta avanzada de escaneo de seguridad para sistemas Linux",
        epilog="Ejemplo: python main.py --all --scan-network --output /ruta/personalizada"
    )
    
    # Argumentos para formatos de salida
    formato_grupo = parser.add_argument_group('Formatos de salida')
    formato_grupo.add_argument("--json", action="store_true", help="Exportar reporte en formato JSON")
    formato_grupo.add_argument("--txt", action="store_true", help="Exportar reporte en formato TXT")
    formato_grupo.add_argument("--html", action="store_true", help="Exportar reporte en formato HTML")
    formato_grupo.add_argument("--all", action="store_true", help="Exportar en todos los formatos")
    
    # Argumentos para opciones de escaneo
    escaneo_grupo = parser.add_argument_group('Opciones de escaneo')
    escaneo_grupo.add_argument("--no-network", action="store_true", help="Omitir escaneo de red")
    escaneo_grupo.add_argument("--scan-network", action="store_true", 
                              help="Realizar escaneo completo de la red local")
    escaneo_grupo.add_argument("--max-hosts", type=int, default=10, 
                              help="Número máximo de hosts a escanear en la red (por defecto: 10)")
    escaneo_grupo.add_argument("--intensity", choices=["ligero", "normal", "agresivo"], 
                              default="normal", help="Intensidad del escaneo de red")
    escaneo_grupo.add_argument("--output", "-o", type=str, default="reportes", 
                              help="Directorio de salida para los reportes")
    escaneo_grupo.add_argument("--verbose", "-v", action="store_true", 
                              help="Mostrar información detallada durante la ejecución")
    
    args = parser.parse_args()
    
    # Configurar logging
    nivel_log = logging.DEBUG if args.verbose else logging.INFO
    logger = configurar_logging(nivel_log)
    
    logger.info("Iniciando escaneo de seguridad...")
    
    # Determinar formatos de salida
    formatos = []
    if args.all:
        formatos = ["json", "txt", "html"]
    else:
        if args.json: formatos.append("json")
        if args.txt: formatos.append("txt")
        if args.html: formatos.append("html")
    
    if not formatos:
        logger.warning("No se especificó formato de exportación. Usando JSON por defecto.")
        formatos = ["json"]
    
    # Generar información
    info = generar_info(
        logger, 
        escanear_red=not args.no_network,
        escaneo_red_completo=args.scan_network,
        max_hosts=args.max_hosts,
        intensidad=args.intensity
    )
    
    # Generar reportes
    reportes = generar_reportes(info, formatos, args.output, logger)
    
    # Mostrar resumen
    logger.info("Escaneo completado.")
    for formato, archivo in reportes.items():
        print(f"✅ Reporte {formato.upper()} generado en: {os.path.join(args.output, archivo)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️ Escaneo interrumpido por el usuario.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}")
        sys.exit(2)