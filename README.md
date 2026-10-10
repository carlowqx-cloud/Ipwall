IPWall v4.6.1
IPWall es un panel local para Windows que convierte Windows Defender Firewall en un firewall de tipo allowlist-only: todo el tráfico queda bloqueado por defecto y únicamente pueden comunicarse las IP o redes CIDR incluidas explícitamente en las listas blancas.
El sistema utiliza PowerShell, Windows Filtering Platform (WFP) y un panel PHP local para administrar las reglas, detectar conexiones bloqueadas y permitir autorizar destinos directamente desde el navegador.
Funcionamiento
- Bloqueo por defecto de entrada y salida en los perfiles Domain, Private y Public.
- Mantiene reglas Block explícitas que representan el complemento completo de las listas blancas tanto en IPv4 como IPv6.
- whitelist.txt controla las conexiones salientes permitidas.
- whitelist-inbound.txt controla las conexiones entrantes permitidas.
- Las IP que no aparecen en las listas permanecen bloqueadas.
- Un agente ejecutado como SYSTEM supervisa continuamente la política del firewall.
- Captura eventos WFP 5152/5157 para mostrar en el panel las IP a las que Windows intentó conectarse y fueron bloqueadas.
- Las IP detectadas aparecen en runtime\requests.json y pueden aprobarse posteriormente desde el panel.
- La detección de IP ocurre antes de las consultas DNS/PTR para que una resolución DNS lenta no retrase su aparición.
- No crea excepciones DNS ocultas. Si el servidor DNS debe utilizarse, su IP también debe estar autorizada explícitamente.
- Los cambios de whitelist se aplican de forma fail-closed: primero se instala el nuevo bloqueo y después se retiran las reglas anteriores, reduciendo el riesgo de abrir tráfico accidental durante una actualización.
- Los archivos de estado, heartbeats y temporales viven dentro de runtime\, evitando que la carpeta principal esté cambiando constantemente.
- El panel comprueba el estado del agente, perfiles, reglas estrictas, WFP y posibles reglas Allow-Bypass.
- Antes de modificar el firewall se conserva una copia de seguridad .wfw, permitiendo usar Restaurar firewall para volver a la configuración anterior.
- Incluye scripts de diagnóstico y registros de errores para instalación, aplicación de reglas y ejecución del agente.

- Internet / red
      │
      ▼
Windows Defender Firewall
      │
      ├── IP/CIDR en whitelist ─────► ALLOW
      │
      └── cualquier otra dirección ─► BLOCK
                                         │
                                         ▼
                                  Evento WFP 5152/5157
                                         │
                                         ▼
                                    agent.ps1
                                         │
                                         ▼
                               runtime\requests.json
                                         │
                                         ▼
                                   Panel IPWall

  El panel se ejecuta localmente, por ejemplo:
  http://localhost/ipwall/

Permite instalar/restaurar IPWall, revisar el estado del modo hermético, consultar intentos bloqueados y añadir IP o bloques CIDR a las listas permitidas.
Filosofía de seguridad
IPWall trabaja con una política fail-closed: si una dirección no está explícitamente autorizada, debe permanecer bloqueada. Incluso el DNS sigue esta misma regla.
El estado Modo hermético: ACTIVO únicamente se muestra cuando IPWall puede comprobar que la configuración esperada de Windows Defender Firewall está aplicada correctamente.
IPWall controla la política que puede administrar mediante Windows Defender Firewall. Una GPO con mayor prioridad, un administrador local, software de seguridad con drivers propios, determinadas VPN/hipervisores o la desactivación del propio firewall pueden alterar ese modelo.
Descripción corta para GitHub
También puedes poner esto en el campo About del repositorio:
Firewall allowlist-only para Windows con panel web, bloqueo IPv4/IPv6, captura WFP de conexiones bloqueadas, agente SYSTEM y administración de whitelist en tiempo real.

Y como subtítulo del README:
Todo bloqueado salvo lo explícitamente autorizado.

<img width="1892" height="1033" alt="image" src="https://github.com/user-attachments/assets/debeffc5-8687-421b-a8b7-82c79dde0977" />
