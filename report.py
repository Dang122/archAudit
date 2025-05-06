#!/usr/bin/env python3
# report.py - Módulo mejorado para generación de reportes con soporte para escaneo de red
import json
import os
import logging
from datetime import datetime
import base64
import socket

logger = logging.getLogger('security_scanner.report')

def timestamp():
    """
    Genera un timestamp para los nombres de archivo.
    
    Returns:
        str: Timestamp en formato YYYYMMDD_HHMMSS
    """
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def guardar_json(data, ruta="reportes"):
    """
    Guarda los datos en formato JSON.
    
    Args:
        data: Datos a guardar
        ruta: Directorio donde guardar el archivo
        
    Returns:
        str: Nombre del archivo generado
    """
    if not os.path.exists(ruta):
        os.makedirs(ruta)
        
    nombre = f"reporte_{timestamp()}.json"
    ruta_completa = os.path.join(ruta, nombre)
    
    try:
        with open(ruta_completa, "w") as f:
            json.dump(data, f, indent=4, default=str)
        logger.info(f"Reporte JSON guardado en {ruta_completa}")
        return nombre
    except Exception as e:
        logger.error(f"Error al guardar reporte JSON: {e}")
        # Intentar guardar en directorio actual como fallback
        fallback = f"reporte_{timestamp()}.json"
        try:
            with open(fallback, "w") as f:
                json.dump(data, f, indent=4, default=str)
            logger.warning(f"Reporte JSON guardado en directorio actual: {fallback}")
            return fallback
        except Exception as e2:
            logger.error(f"Error al guardar reporte JSON en fallback: {e2}")
            return f"ERROR: {str(e2)}"

def generar_txt(data, nivel=0):
    """
    Genera una representación en texto de los datos.
    
    Args:
        data: Datos a convertir a texto
        nivel: Nivel de indentación
        
    Returns:
        str: Representación en texto de los datos
    """
    resultado = ""
    sangria = "  " * nivel
    
    if isinstance(data, dict):
        for clave, valor in data.items():
            if isinstance(valor, (dict, list)) and valor:
                resultado += f"{sangria}{clave}:\n{generar_txt(valor, nivel+1)}"
            else:
                resultado += f"{sangria}{clave}: {valor}\n"
    elif isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, dict):
                resultado += f"{sangria}Elemento {i+1}:\n{generar_txt(item, nivel+1)}"
            else:
                resultado += f"{sangria}- {item}\n"
    else:
        resultado += f"{sangria}{data}\n"
        
    return resultado

def guardar_txt(data, ruta="reportes"):
    """
    Guarda los datos en formato TXT.
    
    Args:
        data: Datos a guardar
        ruta: Directorio donde guardar el archivo
        
    Returns:
        str: Nombre del archivo generado
    """
    if not os.path.exists(ruta):
        os.makedirs(ruta)
        
    nombre = f"reporte_{timestamp()}.txt"
    ruta_completa = os.path.join(ruta, nombre)
    
    try:
        # Generar encabezado
        contenido = f"""
=======================================================================
  REPORTE DE SEGURIDAD DEL SISTEMA LINUX
  Generado el: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  Host: {socket.gethostname()}
=======================================================================

"""
        # Generar secciones
        if "sistema" in data:
            contenido += "INFORMACIÓN DEL SISTEMA\n"
            contenido += "=====================\n"
            contenido += generar_txt(data["sistema"], 0)
            contenido += "\n"
            
        if "permisos_archivos_criticos" in data:
            contenido += "PERMISOS DE ARCHIVOS CRÍTICOS\n"
            contenido += "============================\n"
            # Filtrar archivos inseguros primero
            archivos_inseguros = [a for a in data["permisos_archivos_criticos"] 
                                if a.get("inseguro", False)]
            if archivos_inseguros:
                contenido += "ARCHIVOS CON PERMISOS INSEGUROS:\n"
                for archivo in archivos_inseguros:
                    contenido += f"  - {archivo['ruta']} ({archivo['permisos']})\n"
                    if "razones_inseguridad" in archivo and archivo["razones_inseguridad"]:
                        for razon in archivo["razones_inseguridad"]:
                            contenido += f"    * {razon}\n"
                contenido += "\n"
            
            contenido += "TODOS LOS ARCHIVOS ANALIZADOS:\n"
            contenido += generar_txt(data["permisos_archivos_criticos"], 0)
            contenido += "\n"
            
        if "interfaces_red" in data:
            contenido += "INTERFACES DE RED\n"
            contenido += "================\n"
            contenido += generar_txt(data["interfaces_red"], 0)
            contenido += "\n"
            
        if "puertos_abiertos" in data:
            contenido += "PUERTOS ABIERTOS\n"
            contenido += "===============\n"
            for puerto in data["puertos_abiertos"]:
                if puerto.get("estado") == "open":
                    contenido += f"  Puerto {puerto['puerto']} ({puerto['servicio']}): ABIERTO\n"
                    if puerto.get("producto"):
                        contenido += f"    Producto: {puerto['producto']} {puerto.get('version', '')}\n"
                    if puerto.get("vulnerabilidades"):
                        contenido += "    Vulnerabilidades detectadas:\n"
                        for vuln in puerto["vulnerabilidades"]:
                            contenido += f"      - {vuln}\n"
            contenido += "\n"
            
        # NUEVA SECCIÓN: Escaneo de red local
        if "red_local" in data:
            contenido += "ESCANEO DE RED LOCAL\n"
            contenido += "===================\n"
            red_info = data["red_local"]
            contenido += f"Red escaneada: {red_info.get('red', 'Desconocida')}\n"
            contenido += f"Hosts encontrados: {red_info.get('hosts_encontrados', 0)}\n"
            
            if "estadisticas" in red_info:
                stats = red_info["estadisticas"]
                contenido += f"Total puertos abiertos: {stats.get('total_puertos_abiertos', 0)}\n"
                contenido += f"Promedio puertos por host: {stats.get('promedio_puertos_por_host', 0):.2f}\n"
                contenido += f"Duración del escaneo: {stats.get('duracion_escaneo', 0):.2f} segundos\n\n"
            
            if "hosts" in red_info and red_info["hosts"]:
                contenido += "HOSTS DETECTADOS EN LA RED:\n"
                for host in red_info["hosts"]:
                    contenido += f"  - IP: {host.get('ip', 'Desconocida')}\n"
                    contenido += f"    Nombre: {host.get('nombre', 'Desconocido')}\n"
                    if "mac" in host and host["mac"]:
                        contenido += f"    MAC: {host['mac']}\n"
                    if "vendor" in host and host["vendor"]:
                        contenido += f"    Fabricante: {host['vendor']}\n"
                    if "sistema_operativo" in host:
                        so = host["sistema_operativo"]
                        contenido += f"    Sistema Operativo: {so.get('nombre', 'Desconocido')} (Precisión: {so.get('precision', '0')}%))\n"
                    
                    contenido += f"    Puertos abiertos: {host.get('puertos_abiertos', 0)}\n"
                    
                    # Mostrar puertos abiertos para cada host
                    if "puertos" in host:
                        puertos_abiertos = [p for p in host["puertos"] if p.get("estado") == "open"]
                        if puertos_abiertos:
                            contenido += "    Detalle de puertos:\n"
                            for puerto in puertos_abiertos:
                                contenido += f"      - Puerto {puerto['puerto']} ({puerto.get('servicio', 'desconocido')})"
                                if puerto.get("producto"):
                                    contenido += f": {puerto['producto']} {puerto.get('version', '')}"
                                contenido += "\n"
                                if puerto.get("vulnerabilidades"):
                                    contenido += "        Vulnerabilidades:\n"
                                    for vuln in puerto["vulnerabilidades"][:3]:  # Mostrar solo las primeras 3
                                        contenido += f"          * {vuln}\n"
                                    if len(puerto["vulnerabilidades"]) > 3:
                                        contenido += f"          * ... y {len(puerto['vulnerabilidades']) - 3} más\n"
                    contenido += "\n"
            
        # NUEVA SECCIÓN: Servicios vulnerables
        if "servicios_vulnerables" in data and data["servicios_vulnerables"]:
            contenido += "SERVICIOS VULNERABLES DETECTADOS\n"
            contenido += "==============================\n"
            
            # Agrupar por tipo de vulnerabilidad
            por_tipo = {}
            for servicio in data["servicios_vulnerables"]:
                tipo = servicio.get("tipo", "otro")
                if tipo not in por_tipo:
                    por_tipo[tipo] = []
                por_tipo[tipo].append(servicio)
            
            # Mostrar servicios riesgosos
            if "servicio_riesgoso" in por_tipo:
                contenido += "SERVICIOS POTENCIALMENTE RIESGOSOS:\n"
                for servicio in por_tipo["servicio_riesgoso"]:
                    contenido += f"  - {servicio.get('servicio', 'desconocido')} en {servicio.get('ip', 'IP desconocida')}:{servicio.get('puerto', '?')}\n"
                    contenido += f"    Riesgo: {servicio.get('riesgo', 'Desconocido')}\n"
                contenido += "\n"
            
            # Mostrar versiones vulnerables
            if "version_vulnerable" in por_tipo:
                contenido += "VERSIONES DE SOFTWARE POTENCIALMENTE VULNERABLES:\n"
                for servicio in por_tipo["version_vulnerable"]:
                    contenido += f"  - {servicio.get('producto', '')} {servicio.get('version', '')} en {servicio.get('ip', 'IP desconocida')}:{servicio.get('puerto', '?')}\n"
                    contenido += f"    Riesgo: {servicio.get('riesgo', 'Desconocido')}\n"
                contenido += "\n"
            
            # Mostrar vulnerabilidades detectadas
            if "vulnerabilidad_detectada" in por_tipo:
                contenido += "VULNERABILIDADES ESPECÍFICAS DETECTADAS:\n"
                for servicio in por_tipo["vulnerabilidad_detectada"]:
                    contenido += f"  - {servicio.get('servicio', 'desconocido')} ({servicio.get('producto', '')} {servicio.get('version', '')}) en {servicio.get('ip', 'IP desconocida')}:{servicio.get('puerto', '?')}\n"
                    if "vulnerabilidades" in servicio:
                        for i, vuln in enumerate(servicio["vulnerabilidades"][:5]):  # Mostrar solo las primeras 5
                            contenido += f"    * {vuln}\n"
                        if len(servicio["vulnerabilidades"]) > 5:
                            contenido += f"    * ... y {len(servicio['vulnerabilidades']) - 5} más\n"
                contenido += "\n"
            
        contenido += "=======================================================================\n"
        contenido += "FIN DEL REPORTE\n"
        
        with open(ruta_completa, "w") as f:
            f.write(contenido)
            
        logger.info(f"Reporte TXT guardado en {ruta_completa}")
        return nombre
    except Exception as e:
        logger.error(f"Error al guardar reporte TXT: {e}")
        return f"ERROR: {str(e)}"

def generar_html_recursivo(data):
    """
    Genera una representación HTML recursiva de los datos.
    
    Args:
        data: Datos a convertir a HTML
        
    Returns:
        str: Representación HTML de los datos
    """
    if isinstance(data, dict):
        html = "<ul class='dict-list'>"
        for clave, valor in data.items():
            html += f"<li><span class='key'>{clave}:</span> "
            if isinstance(valor, (dict, list)) and valor:
                html += generar_html_recursivo(valor)
            else:
                html += f"<span class='value'>{valor}</span>"
            html += "</li>"
        html += "</ul>"
    elif isinstance(data, list):
        html = "<ul class='list'>"
        for item in data:
            html += "<li>"
            if isinstance(item, (dict, list)):
                html += generar_html_recursivo(item)
            else:
                html += f"<span class='value'>{item}</span>"
            html += "</li>"
        html += "</ul>"
    else:
        html = f"<span class='value'>{data}</span>"
    return html

def guardar_html(data, ruta="reportes"):
    """
    Guarda los datos en formato HTML.
    
    Args:
        data: Datos a guardar
        ruta: Directorio donde guardar el archivo
        
    Returns:
        str: Nombre del archivo generado
    """
    if not os.path.exists(ruta):
        os.makedirs(ruta)
        
    nombre = f"reporte_{timestamp()}.html"
    ruta_completa = os.path.join(ruta, nombre)
    
    try:
        # Generar contenido HTML para cada sección
        sistema_html = generar_html_recursivo(data.get("sistema", {}))
        
        # Generar HTML para permisos, destacando los inseguros
        permisos_html = "<div class='permisos-section'>"
        archivos_inseguros = [a for a in data.get("permisos_archivos_criticos", []) 
                            if a.get("inseguro", False)]
        
        if archivos_inseguros:
            permisos_html += "<div class='alert alert-danger'>"
            permisos_html += f"<h4>⚠️ Se encontraron {len(archivos_inseguros)} archivos con permisos inseguros</h4>"
            permisos_html += "<ul class='insecure-files'>"
            for archivo in archivos_inseguros:
                permisos_html += f"<li><strong>{archivo['ruta']}</strong> ({archivo['permisos']})"
                if "razones_inseguridad" in archivo and archivo["razones_inseguridad"]:
                    permisos_html += "<ul>"
                    for razon in archivo["razones_inseguridad"]:
                        permisos_html += f"<li>{razon}</li>"
                    permisos_html += "</ul>"
                permisos_html += "</li>"
            permisos_html += "</ul>"
            permisos_html += "</div>"
        
        permisos_html += "<h4>Todos los archivos analizados</h4>"
        permisos_html += generar_html_recursivo(data.get("permisos_archivos_criticos", []))
        permisos_html += "</div>"
        
        # Generar HTML para interfaces de red
        interfaces_html = generar_html_recursivo(data.get("interfaces_red", {}))
        
        # Generar HTML para puertos, destacando los abiertos
        puertos_html = "<div class='puertos-section'>"
        puertos_abiertos = [p for p in data.get("puertos_abiertos", []) 
                          if p.get("estado") == "open"]
        
        if puertos_abiertos:
            puertos_html += f"<h4>Puertos abiertos ({len(puertos_abiertos)})</h4>"
            puertos_html += "<table class='table'>"
            puertos_html += "<thead><tr><th>Puerto</th><th>Servicio</th><th>Producto</th><th>Vulnerabilidades</th></tr></thead>"
            puertos_html += "<tbody>"
            
            for puerto in puertos_abiertos:
                vulnerabilidades = puerto.get("vulnerabilidades", [])
                clase_fila = "table-danger" if vulnerabilidades else ""
                
                puertos_html += f"<tr class='{clase_fila}'>"
                puertos_html += f"<td>{puerto['puerto']}</td>"
                puertos_html += f"<td>{puerto.get('servicio', 'desconocido')}</td>"
                puertos_html += f"<td>{puerto.get('producto', '')} {puerto.get('version', '')}</td>"
                
                puertos_html += "<td>"
                if vulnerabilidades:
                    puertos_html += "<ul class='vulnerabilities'>"
                    for vuln in vulnerabilidades[:3]:  # Mostrar solo las primeras 3
                        puertos_html += f"<li>{vuln}</li>"
                    if len(vulnerabilidades) > 3:
                        puertos_html += f"<li>... y {len(vulnerabilidades) - 3} más</li>"
                    puertos_html += "</ul>"
                puertos_html += "</td>"
                
                puertos_html += "</tr>"
            
            puertos_html += "</tbody></table>"
        else:
            puertos_html += "<p>No se encontraron puertos abiertos.</p>"
            
        puertos_html += "</div>"
        
        # NUEVA SECCIÓN: Generar HTML para escaneo de red
        red_local_html = ""
        hosts_en_red = 0
        total_puertos_abiertos_red = 0
        
        if "red_local" in data:
            red_local = data["red_local"]
            hosts_en_red = red_local.get("hosts_encontrados", 0)
            
            if "estadisticas" in red_local:
                total_puertos_abiertos_red = red_local["estadisticas"].get("total_puertos_abiertos", 0)
            
            red_local_html += "<div class='red-local-section'>"
            red_local_html += f"<h3>Red escaneada: {red_local.get('red', 'Desconocida')}</h3>"
            
            # Estadísticas de red
            if "estadisticas" in red_local:
                stats = red_local["estadisticas"]
                red_local_html += "<div class='stats-container'>"
                red_local_html += "<div class='stat-box'>"
                red_local_html += f"<div class='stat-value'>{stats.get('total_puertos_abiertos', 0)}</div>"
                red_local_html += "<div class='stat-label'>Puertos abiertos</div>"
                red_local_html += "</div>"
                
                red_local_html += "<div class='stat-box'>"
                red_local_html += f"<div class='stat-value'>{stats.get('promedio_puertos_por_host', 0):.1f}</div>"
                red_local_html += "<div class='stat-label'>Promedio por host</div>"
                red_local_html += "</div>"
                
                red_local_html += "<div class='stat-box'>"
                red_local_html += f"<div class='stat-value'>{stats.get('duracion_escaneo', 0):.1f}s</div>"
                red_local_html += "<div class='stat-label'>Duración del escaneo</div>"
                red_local_html += "</div>"
                red_local_html += "</div>"
            
            # Tabla de hosts
            if "hosts" in red_local and red_local["hosts"]:
                red_local_html += "<h4>Hosts detectados en la red</h4>"
                red_local_html += "<div class='table-responsive'>"
                red_local_html += "<table class='table table-hosts'>"
                red_local_html += "<thead><tr><th>IP</th><th>Nombre</th><th>MAC</th><th>Sistema Operativo</th><th>Puertos abiertos</th><th>Detalles</th></tr></thead>"
                red_local_html += "<tbody>"
                
                for host in red_local["hosts"]:
                    puertos_abiertos_host = host.get("puertos_abiertos", 0)
                    clase_fila = ""
                    if puertos_abiertos_host > 5:
                        clase_fila = "table-danger"
                    elif puertos_abiertos_host > 2:
                        clase_fila = "table-warning"
                    
                    red_local_html += f"<tr class='{clase_fila}'>"
                    red_local_html += f"<td>{host.get('ip', 'Desconocida')}</td>"
                    red_local_html += f"<td>{host.get('nombre', 'Desconocido')}</td>"
                    red_local_html += f"<td>{host.get('mac', '-')}</td>"
                    
                    # Sistema operativo
                    if "sistema_operativo" in host:
                        so = host["sistema_operativo"]
                        red_local_html += f"<td>{so.get('nombre', 'Desconocido')} ({so.get('precision', '0')}%)</td>"
                    else:
                        red_local_html += "<td>-</td>"
                    
                    red_local_html += f"<td>{puertos_abiertos_host}</td>"
                    
                    # Botón para mostrar detalles
                    host_id = host.get('ip', '').replace('.', '_')
                    red_local_html += f"<td><button class='btn-details' onclick=\"toggleDetails('{host_id}')\">Ver detalles</button></td>"
                    
                    red_local_html += "</tr>"
                    
                    # Fila de detalles (oculta por defecto)
                    red_local_html += f"<tr id='details_{host_id}' class='details-row' style='display:none;'>"
                    red_local_html += "<td colspan='6'>"
                    
                    # Mostrar puertos abiertos
                    if "puertos" in host:
                        puertos_abiertos = [p for p in host["puertos"] if p.get("estado") == "open"]
                        if puertos_abiertos:
                            red_local_html += "<div class='host-details'>"
                            red_local_html += "<h5>Puertos abiertos</h5>"
                            red_local_html += "<table class='inner-table'>"
                            red_local_html += "<thead><tr><th>Puerto</th><th>Servicio</th><th>Producto</th><th>Vulnerabilidades</th></tr></thead>"
                            red_local_html += "<tbody>"
                            
                            for puerto in puertos_abiertos:
                                vulnerabilidades = puerto.get("vulnerabilidades", [])
                                clase_puerto = "puerto-vulnerable" if vulnerabilidades else ""
                                
                                red_local_html += f"<tr class='{clase_puerto}'>"
                                red_local_html += f"<td>{puerto['puerto']}</td>"
                                red_local_html += f"<td>{puerto.get('servicio', 'desconocido')}</td>"
                                red_local_html += f"<td>{puerto.get('producto', '')} {puerto.get('version', '')}</td>"
                                
                                red_local_html += "<td>"
                                if vulnerabilidades:
                                    red_local_html += "<ul class='vuln-list'>"
                                    for vuln in vulnerabilidades[:3]:
                                        red_local_html += f"<li>{vuln}</li>"
                                    if len(vulnerabilidades) > 3:
                                        red_local_html += f"<li>... y {len(vulnerabilidades) - 3} más</li>"
                                    red_local_html += "</ul>"
                                red_local_html += "</td>"
                                
                                red_local_html += "</tr>"
                            
                            red_local_html += "</tbody></table>"
                            red_local_html += "</div>"
                    
                    red_local_html += "</td></tr>"
                
                red_local_html += "</tbody></table>"
                red_local_html += "</div>"
            else:
                red_local_html += "<p>No se encontraron hosts en la red.</p>"
            
            red_local_html += "</div>"
        
        # NUEVA SECCIÓN: Servicios vulnerables
        servicios_vulnerables_html = ""
        total_servicios_vulnerables = 0
        
        if "servicios_vulnerables" in data and data["servicios_vulnerables"]:
            servicios_vulnerables = data["servicios_vulnerables"]
            total_servicios_vulnerables = len(servicios_vulnerables)
            
            servicios_vulnerables_html += "<div class='servicios-vulnerables-section'>"
            servicios_vulnerables_html += f"<h3>Servicios vulnerables detectados ({total_servicios_vulnerables})</h3>"
            
            # Agrupar por tipo
            por_tipo = {}
            for servicio in servicios_vulnerables:
                tipo = servicio.get("tipo", "otro")
                if tipo not in por_tipo:
                    por_tipo[tipo] = []
                por_tipo[tipo].append(servicio)
            
            # Servicios riesgosos
            if "servicio_riesgoso" in por_tipo:
                servicios_vulnerables_html += "<div class='vuln-category'>"
                servicios_vulnerables_html += "<h4>Servicios potencialmente riesgosos</h4>"
                servicios_vulnerables_html += "<table class='table'>"
                servicios_vulnerables_html += "<thead><tr><th>Servicio</th><th>IP:Puerto</th><th>Producto</th><th>Riesgo</th></tr></thead>"
                servicios_vulnerables_html += "<tbody>"
                
                for servicio in por_tipo["servicio_riesgoso"]:
                    servicios_vulnerables_html += "<tr class='table-warning'>"
                    servicios_vulnerables_html += f"<td>{servicio.get('servicio', 'desconocido')}</td>"
                    servicios_vulnerables_html += f"<td>{servicio.get('ip', 'Desconocida')}:{servicio.get('puerto', '?')}</td>"
                    servicios_vulnerables_html += f"<td>{servicio.get('producto', '')} {servicio.get('version', '')}</td>"
                    servicios_vulnerables_html += f"<td>{servicio.get('riesgo', 'Desconocido')}</td>"
                    servicios_vulnerables_html += "</tr>"
                
                servicios_vulnerables_html += "</tbody></table>"
                servicios_vulnerables_html += "</div>"
            
            # Versiones vulnerables
            if "version_vulnerable" in por_tipo:
                servicios_vulnerables_html += "<div class='vuln-category'>"
                servicios_vulnerables_html += "<h4>Versiones de software potencialmente vulnerables</h4>"
                servicios_vulnerables_html += "<table class='table'>"
                servicios_vulnerables_html += "<thead><tr><th>Producto</th><th>IP:Puerto</th><th>Servicio</th><th>Riesgo</th></tr></thead>"
                servicios_vulnerables_html += "<tbody>"
                
                for servicio in por_tipo["version_vulnerable"]:
                    servicios_vulnerables_html += "<tr class='table-warning'>"
                    servicios_vulnerables_html += f"<td>{servicio.get('producto', '')} {servicio.get('version', '')}</td>"
                    servicios_vulnerables_html += f"<td>{servicio.get('ip', 'Desconocida')}:{servicio.get('puerto', '?')}</td>"
                    servicios_vulnerables_html += f"<td>{servicio.get('servicio', 'desconocido')}</td>"
                    servicios_vulnerables_html += f"<td>{servicio.get('riesgo', 'Desconocido')}</td>"
                    servicios_vulnerables_html += "</tr>"
                
                servicios_vulnerables_html += "</tbody></table>"
                servicios_vulnerables_html += "</div>"
            
            # Vulnerabilidades específicas
            if "vulnerabilidad_detectada" in por_tipo:
                servicios_vulnerables_html += "<div class='vuln-category'>"
                servicios_vulnerables_html += "<h4>Vulnerabilidades específicas detectadas</h4>"
                servicios_vulnerables_html += "<table class='table'>"
                servicios_vulnerables_html += "<thead><tr><th>Servicio</th><th>IP:Puerto</th><th>Producto</th><th>Vulnerabilidades</th></tr></thead>"
                servicios_vulnerables_html += "<tbody>"
                
                for servicio in por_tipo["vulnerabilidad_detectada"]:
                    servicios_vulnerables_html += "<tr class='table-danger'>"
                    servicios_vulnerables_html += f"<td>{servicio.get('servicio', 'desconocido')}</td>"
                    servicios_vulnerables_html += f"<td>{servicio.get('ip', 'Desconocida')}:{servicio.get('puerto', '?')}</td>"
                    servicios_vulnerables_html += f"<td>{servicio.get('producto', '')} {servicio.get('version', '')}</td>"
                    
                    servicios_vulnerables_html += "<td>"
                    if "vulnerabilidades" in servicio:
                        servicios_vulnerables_html += "<ul class='vuln-list'>"
                        for vuln in servicio["vulnerabilidades"][:5]:
                            servicios_vulnerables_html += f"<li>{vuln}</li>"
                        if len(servicio["vulnerabilidades"]) > 5:
                            servicios_vulnerables_html += f"<li>... y {len(servicio['vulnerabilidades']) - 5} más</li>"
                        servicios_vulnerables_html += "</ul>"
                    servicios_vulnerables_html += "</td>"
                    
                    servicios_vulnerables_html += "</tr>"
                
                servicios_vulnerables_html += "</tbody></table>"
                servicios_vulnerables_html += "</div>"
            
            servicios_vulnerables_html += "</div>"
        
        # Plantilla HTML completa con las nuevas secciones
        html = f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Reporte de Seguridad Linux - {datetime.now().strftime('%Y-%m-%d')}</title>
            <style>
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    line-height: 1.6;
                    color: #333;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f8f9fa;
                }}
                .container {{ 
                    background-color: #fff;
                    border-radius: 8px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    padding: 20px;
                    margin-bottom: 20px;
                }}
                h1, h2, h3, h4 {{ 
                    color: #2c3e50;
                    margin-top: 0;
                }}
                h1 {{ 
                    text-align: center;
                    padding-bottom: 10px;
                    border-bottom: 2px solid #3498db;
                    margin-bottom: 30px;
                }}
                h2 {{ 
                    border-bottom: 1px solid #eee;
                    padding-bottom: 10px;
                    margin-top: 30px;
                }}
                .section {{ 
                    margin-bottom: 30px;
                }}
                .key {{ 
                    font-weight: bold;
                    color: #3498db;
                }}
                .value {{ 
                    color: #333;
                }}
                ul.dict-list, ul.list {{ 
                    padding-left: 20px;
                    list-style-type: none;
                }}
                ul.dict-list li, ul.list li {{ 
                    margin-bottom: 5px;
                }}
                .alert {{ 
                    padding: 15px;
                    border-radius: 4px;
                    margin-bottom: 20px;
                }}
                .alert-danger {{ 
                    background-color: #f8d7da;
                    border: 1px solid #f5c6cb;
                    color: #721c24;
                }}
                .table {{ 
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                }}
                .table th, .table td {{ 
                    padding: 12px 15px;
                    border: 1px solid #ddd;
                    text-align: left;
                }}
                .table th {{ 
                    background-color: #f2f2f2;
                    font-weight: bold;
                }}
                .table tbody tr:hover {{ 
                    background-color: #f5f5f5;
                }}
                .table-danger {{ 
                    background-color: #fff3f3;
                }}
                .table-warning {{ 
                    background-color: #fff9e6;
                }}
                .footer {{ 
                    text-align: center;
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #eee;
                    color: #777;
                    font-size: 0.9em;
                }}
                .summary-box {{ 
                    display: flex;
                    flex-wrap: wrap;
                    margin-bottom: 20px;
                }}
                .summary-item {{ 
                    flex: 1;
                    min-width: 200px;
                    background-color: #e9f7fe;
                    border-radius: 8px;
                    padding: 15px;
                    margin: 10px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
                }}
                .summary-item.warning {{ 
                    background-color: #fff3cd;
                }}
                .summary-item.danger {{ 
                    background-color: #f8d7da;
                }}
                .summary-item h3 {{ 
                    margin-top: 0;
                    font-size: 16px;
                }}
                .summary-item p {{ 
                    font-size: 24px;
                    font-weight: bold;
                    margin: 10px 0 0;
                }}
                
                /* Nuevos estilos para secciones de red */
                .stats-container {{
                    display: flex;
                    justify-content: space-between;
                    margin-bottom: 20px;
                }}
                .stat-box {{
                    flex: 1;
                    background-color: #f8f9fa;
                    border-radius: 8px;
                    padding: 15px;
                    margin: 0 10px;
                    text-align: center;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
                }}
                .stat-value {{
                    font-size: 24px;
                    font-weight: bold;
                    color: #2c3e50;
                }}
                .stat-label {{
                    font-size: 14px;
                    color: #7f8c8d;
                    margin-top: 5px;
                }}
                .table-responsive {{
                    overflow-x: auto;
                }}
                .table-hosts {{
                    min-width: 800px;
                }}
                .btn-details {{
                    background-color: #3498db;
                    color: white;
                    border: none;
                    padding: 5px 10px;
                    border-radius: 4px;
                    cursor: pointer;
                }}
                .btn-details:hover {{
                    background-color: #2980b9;
                }}
                .details-row {{
                    background-color: #f9f9f9;
                }}
                .host-details {{
                    padding: 15px;
                }}
                .inner-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 10px;
                }}
                .inner-table th, .inner-table td {{
                    padding: 8px 10px;
                    border: 1px solid #ddd;
                }}
                .puerto-vulnerable {{
                    background-color: #fff3f3;
                }}
                .vuln-list {{
                    margin: 0;
                    padding-left: 20px;
                }}
                .vuln-category {{
                    margin-bottom: 30px;
                }}
                @media print {{
                    body {{ 
                        background-color: white;
                        padding: 0;
                    }}
                    .container {{ 
                        box-shadow: none;
                        border: 1px solid #ddd;
                    }}
                    .no-print {{ 
                        display: none;
                    }}
                }}
            </style>
            <script>
                function toggleDetails(hostId) {{
                    var detailsRow = document.getElementById('details_' + hostId);
                    if (detailsRow.style.display === 'none') {{
                        detailsRow.style.display = 'table-row';
                    }} else {{
                        detailsRow.style.display = 'none';
                    }}
                }}
            </script>
        </head>
        <body>
            <div class="container">
                <h1>Reporte de Seguridad Linux</h1>
                
                <div class="summary-box">
                    <div class="summary-item">
                        <h3>Host</h3>
                        <p>{data.get('sistema', {}).get('nombre_host', 'Desconocido')}</p>
                    </div>
                    <div class="summary-item">
                        <h3>IP</h3>
                        <p>{data.get('ip_local', 'Desconocida')}</p>
                    </div>
                    <div class="summary-item {('danger' if archivos_inseguros else '')}">
                        <h3>Archivos Inseguros</h3>
                        <p>{len(archivos_inseguros)}</p>
                    </div>
                    <div class="summary-item {('warning' if puertos_abiertos else '')}">
                        <h3>Puertos Abiertos</h3>
                        <p>{len(puertos_abiertos)}</p>
                    </div>
                    <div class="summary-item {('warning' if hosts_en_red > 1 else '')}">
                        <h3>Hosts en Red</h3>
                        <p>{hosts_en_red}</p>
                    </div>
                    <div class="summary-item {('danger' if total_servicios_vulnerables > 0 else '')}">
                        <h3>Servicios Vulnerables</h3>
                        <p>{total_servicios_vulnerables}</p>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Información del Sistema</h2>
                    {sistema_html}
                </div>
                
                <div class="section">
                    <h2>Archivos Críticos y Permisos</h2>
                    {permisos_html}
                </div>
                
                <div class="section">
                    <h2>Interfaces de Red</h2>
                    {interfaces_html}
                </div>
                
                <div class="section">
                    <h2>Escaneo de Puertos</h2>
                    {puertos_html}
                </div>
                
                <div class="section">
                    <h2>Escaneo de Red Local</h2>
                    {red_local_html}
                </div>
                
                <div class="section">
                    <h2>Servicios Vulnerables</h2>
                    {servicios_vulnerables_html}
                </div>
                
                <div class="footer">
                    <p>Reporte generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p>Herramienta de Análisis de Seguridad Linux</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        with open(ruta_completa, "w") as f:
            f.write(html)
            
        logger.info(f"Reporte HTML guardado en {ruta_completa}")
        return nombre
    except Exception as e:
        logger.error(f"Error al guardar reporte HTML: {e}")
        return f"ERROR: {str(e)}"

def generar_reporte_resumen(data):
    """
    Genera un resumen ejecutivo de los hallazgos de seguridad.
    
    Args:
        data: Datos del escaneo
        
    Returns:
        str: Resumen ejecutivo en formato texto
    """
    try:
        # Contar problemas de seguridad
        archivos_inseguros = [a for a in data.get("permisos_archivos_criticos", []) 
                            if a.get("inseguro", False)]
        
        puertos_abiertos = [p for p in data.get("puertos_abiertos", []) 
                          if p.get("estado") == "open"]
        
        vulnerabilidades = []
        for puerto in puertos_abiertos:
            vulnerabilidades.extend(puerto.get("vulnerabilidades", []))
        
        # Contar hosts en red y servicios vulnerables
        hosts_en_red = 0
        if "red_local" in data:
            hosts_en_red = data["red_local"].get("hosts_encontrados", 0)
        
        servicios_vulnerables = data.get("servicios_vulnerables", [])
        
        # Generar resumen
        resumen = f"""
RESUMEN EJECUTIVO DE SEGURIDAD
==============================
Host: {data.get('sistema', {}).get('nombre_host', 'Desconocido')}
IP: {data.get('ip_local', 'Desconocida')}
Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

HALLAZGOS PRINCIPALES:
- Archivos con permisos inseguros: {len(archivos_inseguros)}
- Puertos abiertos: {len(puertos_abiertos)}
- Vulnerabilidades potenciales: {len(vulnerabilidades)}
- Hosts detectados en la red: {hosts_en_red}
- Servicios vulnerables en la red: {len(servicios_vulnerables)}

"""
        
        # Añadir detalles de archivos inseguros
        if archivos_inseguros:
            resumen += "\nARCHIVOS CON PERMISOS INSEGUROS:\n"
            for archivo in archivos_inseguros[:5]:  # Mostrar solo los primeros 5
                resumen += f"- {archivo['ruta']} ({archivo['permisos']})\n"
            if len(archivos_inseguros) > 5:
                resumen += f"  ... y {len(archivos_inseguros) - 5} más\n"
        
        # Añadir detalles de puertos abiertos
        if puertos_abiertos:
            resumen += "\nPUERTOS ABIERTOS:\n"
            for puerto in puertos_abiertos[:5]:  # Mostrar solo los primeros 5
                resumen += f"- Puerto {puerto['puerto']} ({puerto.get('servicio', 'desconocido')})"
                if puerto.get("producto"):
                    resumen += f": {puerto['producto']} {puerto.get('version', '')}"
                resumen += "\n"
            if len(puertos_abiertos) > 5:
                resumen += f"  ... y {len(puertos_abiertos) - 5} más\n"
        
        # Añadir detalles de vulnerabilidades
        if vulnerabilidades:
            resumen += "\nVULNERABILIDADES POTENCIALES:\n"
            for vuln in vulnerabilidades[:5]:  # Mostrar solo las primeras 5
                resumen += f"- {vuln}\n"
            if len(vulnerabilidades) > 5:
                resumen += f"  ... y {len(vulnerabilidades) - 5} más\n"
        
        # Añadir detalles de hosts en red
        if "red_local" in data and "hosts" in data["red_local"] and data["red_local"]["hosts"]:
            resumen += "\nHOSTS DETECTADOS EN LA RED:\n"
            for host in data["red_local"]["hosts"][:5]:  # Mostrar solo los primeros 5
                resumen += f"- {host.get('ip', 'Desconocida')} ({host.get('nombre', 'Desconocido')})"
                if "puertos_abiertos" in host:
                    resumen += f" - {host['puertos_abiertos']} puertos abiertos"
                resumen += "\n"
            if len(data["red_local"]["hosts"]) > 5:
                resumen += f"  ... y {len(data['red_local']['hosts']) - 5} más\n"
        
        # Añadir detalles de servicios vulnerables
        if servicios_vulnerables:
            resumen += "\nSERVICIOS VULNERABLES EN LA RED:\n"
            for servicio in servicios_vulnerables[:5]:  # Mostrar solo los primeros 5
                resumen += f"- {servicio.get('servicio', 'desconocido')} en {servicio.get('ip', 'IP desconocida')}:{servicio.get('puerto', '?')}"
                if "riesgo" in servicio:
                    resumen += f" - {servicio['riesgo']}"
                resumen += "\n"
            if len(servicios_vulnerables) > 5:
                resumen += f"  ... y {len(servicios_vulnerables) - 5} más\n"
        
        return resumen
    except Exception as e:
        logger.error(f"Error al generar resumen: {e}")
        return f"Error al generar resumen: {str(e)}"