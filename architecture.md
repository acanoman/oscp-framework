# 🛠️ ESPECIFICACIÓN DE ARQUITECTURA — FRAMEWORK OSCP ENUMERATION

## 🎯 OBJETIVO

Diseñar e implementar un framework de enumeración para entornos tipo OSCP que:

* Automatice tareas repetitivas de **reconocimiento y enumeración**
* Mantenga el **control manual del usuario en todo momento**
* NO realice explotación automática
* NO viole ninguna restricción del examen OSCP
* Mejore la eficiencia sin sustituir el razonamiento del pentester

---

## 🚫 RESTRICCIONES OBLIGATORIAS (CRÍTICAS)

El sistema DEBE cumplir estrictamente:

### ❌ PROHIBIDO

* Autopwn (explotación automática)
* SQLmap, SQLninja u herramientas similares
* Escáneres masivos (Nessus, OpenVAS, etc.)
* Uso de IA o LLMs
* Toma de decisiones autónoma de explotación
* Ejecución automática de exploits
* Suplantación (ARP spoofing, etc.)

### ✅ PERMITIDO

* Nmap (incluyendo scripts NSE)
* Gobuster / Dirsearch
* Nikto
* smbclient, smbmap, rpcclient
* enum4linux
* Burp Suite Community
* Scripts propios (bash/python)

---

## 🧠 FILOSOFÍA DEL FRAMEWORK

El sistema debe ser:

> “Un asistente de enumeración, no un atacante automático”

Debe:

* Sugerir acciones
* Organizar resultados
* Guiar el flujo
* Nunca ejecutar explotación sin intervención

---

## 🧬 ARQUITECTURA GENERAL

El sistema será híbrido:

* **Python → Orquestador (core lógico)**
* **Bash → Ejecución de herramientas (wrappers)**

---

## 📁 ESTRUCTURA DEL PROYECTO

```
oscp-framework/
│
├── core/
│   ├── engine.py              # Orquestador principal
│   ├── parser.py              # Parsing de outputs
│   ├── recommender.py         # Motor de sugerencias
│   ├── session.py             # Gestión de sesiones
│
├── modules/
│   ├── network.py             # Nmap wrapper
│   ├── smb.py                 # SMB enum
│   ├── web.py                 # Web enum
│   ├── ldap.py                # LDAP enum
│
├── wrappers/
│   ├── smb_enum.sh            # (tu script actual modularizado)
│   ├── web_enum.sh
│   ├── recon.sh
│
├── output/
│   ├── targets/
│   │   └── <IP>/
│   │        ├── scans/
│   │        ├── loot/
│   │        ├── notes.md
│
├── main.py
```

---

## ⚙️ COMPONENTES

### 1. ENGINE (core/engine.py)

Responsabilidades:

* Controlar flujo de ejecución
* Detectar servicios abiertos (desde Nmap)
* Invocar módulos según contexto
* Mantener estado de la sesión

Ejemplo:

```python
if 445 in open_ports:
    run_module("smb")
```

---

### 2. PARSER (core/parser.py)

Responsabilidades:

* Parsear outputs de herramientas:

  * Nmap (XML o grepable)
  * Gobuster
  * smbmap
* Extraer:

  * puertos
  * servicios
  * rutas web
  * shares SMB

NO debe ejecutar herramientas.

---

### 3. RECOMMENDER (core/recommender.py)

Responsabilidades:

* Generar sugerencias tipo OSCP

Ejemplo:

```text
[+] SMB detectado:
    - Probar null session
    - Enumerar shares
    - Revisar permisos
```

IMPORTANTE:

* Solo sugerencias, nunca ejecución automática

---

### 4. MÓDULOS (modules/)

Cada módulo:

* Llama a scripts bash existentes
* Guarda resultados
* Notifica al engine

Ejemplo smb.py:

```python
def run(target):
    subprocess.run(["bash", "wrappers/smb_enum.sh", target])
```

---

### 5. WRAPPERS (bash)

Aquí se reutiliza el script existente del usuario:

* Debe dividirse en:

  * smb_enum.sh
  * web_enum.sh
  * recon.sh

Reglas:

* No lógica compleja en bash
* Solo ejecución de herramientas

---

## 🔄 FLUJO DE EJECUCIÓN

1. Usuario ejecuta:

```
python main.py --target 10.10.10.10
```

2. Engine:

   * lanza Nmap
   * parsea resultados

3. Según puertos:

| Puerto | Acción      |
| ------ | ----------- |
| 80/443 | módulo web  |
| 445    | módulo smb  |
| 389    | módulo ldap |

4. Se ejecutan módulos (bash)

5. Parser analiza resultados

6. Recommender sugiere siguientes pasos

---

## 🧾 OUTPUT

Debe generar:

* Carpeta por objetivo
* Archivos estructurados
* Notas automáticas

Ejemplo:

```
output/10.10.10.10/
├── scans/nmap.xml
├── web/gobuster.txt
├── smb/shares.txt
├── notes.md
```

---

## 🧠 REGLAS CRÍTICAS DE DISEÑO

1. ❌ NO autopwn
2. ❌ NO ejecución automática de exploits
3. ✅ SI enumeración automatizada
4. ✅ SI sugerencias inteligentes
5. ✅ SI control manual del usuario

---

## 🔐 SEGURIDAD Y CUMPLIMIENTO OSCP

El framework debe:

* Ser transparente (mostrar comandos ejecutados)
* Permitir ejecución manual alternativa
* No ocultar lógica
* No tomar decisiones ofensivas

---

## 🚀 OBJETIVO FINAL

Construir una herramienta que:

* Acelere la enumeración
* Mejore la organización
* Refuerce la metodología OSCP
* NO sustituya al pentester

---

## 📌 INPUT PARA IMPLEMENTACIÓN

Se proporcionarán:

1. Script bash actual del usuario (enumeración completa)
2. Código de referencia adicional (Python tool)

---

## 📌 OUTPUT ESPERADO

* Código Python modular
* Wrappers bash funcionales
* Sistema ejecutable con:

```
python main.py --target <IP>
```

* Sin violar restricciones OSCP
* Listo para uso en laboratorio y examen

---
