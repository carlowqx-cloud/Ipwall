
Comentario del autor:
IPWall v4.6.1 es un Software anti espionaje, bloquea por defecto todas las IP automatizadas que lanza chromium o algún software de windows en segundo plano. Para no estar limpiando las IP a mano el autor combino este sniffer  con una VPN, y la velocidad del renderizado en javascript se hizo más liviano en gran medida (recomiendo que investiguen eso el cambio no fue pequeño). El código fuente es libre, tienes derecho absoluto de hacer lo que quieras, sería ideal en el futuro crear un sistema operativo nativo con IPwall que controle el tráfico desde la tarjeta de red y en el mediano plazo con la llegada de la IA y el espionaje con esta tecnología sería interesante que windows quede encerrado del dockers.


Explicación técnica:
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

<img width="360" height="376" alt="image" src="https://github.com/user-attachments/assets/397d2dac-078e-4144-b75e-bde8698b3e29" />


  El panel se ejecuta localmente, por ejemplo:
  http://localhost/ipwall/

Permite instalar/restaurar IPWall, revisar el estado del modo hermético, consultar intentos bloqueados y añadir IP o bloques CIDR a las listas permitidas.
Filosofía de seguridad
IPWall trabaja con una política fail-closed: si una dirección no está explícitamente autorizada, debe permanecer bloqueada. Incluso el DNS sigue esta misma regla.
El estado Modo hermético: ACTIVO únicamente se muestra cuando IPWall puede comprobar que la configuración esperada de Windows Defender Firewall está aplicada correctamente.
IPWall controla la política que puede administrar mediante Windows Defender Firewall. Una GPO con mayor prioridad, un administrador local, software de seguridad con drivers propios, determinadas VPN/hipervisores o la desactivación del propio firewall pueden alterar ese modelo.


<img width="1892" height="1033" alt="image" src="https://github.com/user-attachments/assets/debeffc5-8687-421b-a8b7-82c79dde0977" />
<img width="1919" height="1036" alt="image" src="https://github.com/user-attachments/assets/e3d82e4c-991d-4b58-8899-697110156f72" />


