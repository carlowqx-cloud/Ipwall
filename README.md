# IPWall v4.6.1 - hotfix NetSecurity IPv6, instalacion y captura WFP


## Hotfix v4.6.1 - error `::/0`

Esta revision corrige el error real observado en Windows:

`No se pudo crear regla ... v6 ... muestra: ::/0: Uno o más de los prefijos de dirección no es válido.`

Cuando una whitelist no tenia ninguna entrada IPv6, v4.6 representaba el complemento IPv6 completo como `::/0`. Algunas compilaciones del proveedor NetSecurity de Windows rechazan ese prefijo al crear una regla con `New-NetFirewallRule`.

v4.6.1 representa exactamente el mismo espacio sin huecos mediante dos prefijos ordinarios: `::/1` y `8000::/1`. Por simetria, el espacio IPv4 completo se representa como `0.0.0.0/1` y `128.0.0.0/1`. Ademas, `New-IPWallChunkedRules` contiene una segunda defensa que expande cualquier `/0` que pudiera llegar desde otra ruta antes de invocar NetSecurity.

Esto **no debilita el modo hermetico**: cada pareja de `/1` cubre matematicamente el 100% de su familia de direcciones. La instalacion puede continuar hasta arrancar el agente WFP; si vuelve a fallar, el panel conservara el siguiente error concreto.

## Reparacion v4.6

Esta revision ataca el fallo visible como `Falló apply-whitelist.ps1`/`FallÃ³ apply-whitelist.ps1` y el estado `Agente: RESTAURADO / INACTIVO`:

- `install.ps1` ejecuta `apply-whitelist.ps1` en el mismo proceso y conserva la excepcion real en el panel, en vez de reducirla a un codigo 1.
- `strict-firewall.ps1` valida/arranca BFE y MpsSvc, importa NetSecurity, separa reglas IPv4/IPv6 y usa lotes conservadores de direcciones.
- `apply-whitelist.ps1` registra el detalle en `C:\ProgramData\IPWhitelistFirewall\apply-errors.log` y muestra archivo/linea si una whitelist contiene una entrada invalida.
- el agente vuelve a habilitar la auditoria WFP 5157/5152 al arrancar y el instalador no declara exito hasta confirmar tanto el modo hermetico como la lectura WFP.
- los `.ps1` se distribuyen con BOM UTF-8 para Windows PowerShell 5.1; esto elimina textos como `FallÃ³`.

El ZIP sigue sin incluir `whitelist.txt`, `whitelist-inbound.txt`, `runtime\` ni JSON de estado, por lo que copiarlo encima de la instalacion conserva tus permisos y datos.

IPWall v4.6.1 mantiene la arquitectura estricta de v4.3 y separa los archivos de ejecucion que cambian continuamente de los archivos de codigo/editables.

## Arquitectura de firewall

Para cada direccion se usan dos capas:

1. `DefaultInboundAction Block` y `DefaultOutboundAction Block` en Domain, Private y Public.
2. Reglas `Block` explicitas que cubren el complemento completo IPv4 + IPv6 de cada whitelist.

Las unicas reglas `Allow` creadas por IPWall contienen las IP/CIDR de:

- `whitelist.txt`: salida.
- `whitelist-inbound.txt`: entrada.

Una IP que no esta en la lista correspondiente queda dentro de una regla `Block` explicita. El agente SYSTEM tambien deshabilita continuamente reglas locales habilitadas que no pertenezcan a `IPWhitelistFirewall` o `IPWallStrictBlock`.

## Carpeta principal estable

En versiones anteriores `control-broker-status.json.tmp.<PID>` aparecia y desaparecia en la raiz aproximadamente una vez por segundo. El Explorador de Windows trataba esos cambios como altas/bajas de archivos y podia mover filas, perder seleccion o interrumpir un cambio de nombre.

Desde v4.4 los archivos volatiles viven en `runtime\`:

- `runtime\agent-status.json`
- `runtime\requests.json`
- `runtime\control-broker-status.json`
- `runtime\control-status.json`
- `runtime\system-control.request.json`
- flags y temporales de ejecucion

La carpeta `runtime` se marca como oculta al instalar/arrancar. En la raiz quedan estables los scripts PHP/PowerShell y las dos whitelists para poder editarlos sin que el broker altere continuamente la lista del Explorador.

La actualizacion desde 4.0-4.3 conserva un puente de compatibilidad: si el broker anterior sigue cargado en memoria, `index.php` usa temporalmente las rutas antiguas para poder lanzar la instalacion 4.6. Una vez confirmado el nuevo agente y broker, se eliminan los JSON/temporales legacy de la raiz.

## Sin bypass DNS oculto

La version estricta no crea `IPWall-DNS-UDP` ni `IPWall-DNS-TCP`. Los servidores DNS detectados se guardan en `C:\ProgramData\IPWhitelistFirewall\dns-servers.txt` solo como referencia. Si quieres resolucion DNS, agrega explicitamente la IP del DNS a `whitelist.txt`.

Esto significa que una instalacion con whitelist de salida vacia puede perder Internet y DNS por diseno. El objetivo es fail-closed.

## Cambio atomico de whitelist

`apply-whitelist.ps1` valida las dos listas antes de tocar el firewall. Luego crea primero el nuevo complemento `Block`, despues las nuevas reglas `Allow` y solo al final elimina la generacion anterior.

- Al quitar una IP de la whitelist, el nuevo `Block` entra antes de retirar el `Allow` anterior.
- Al agregar una IP, la generacion anterior puede mantenerla bloqueada durante la transicion, pero no se abre un hueco temporal hacia otras IP.

## Verificacion continua

`agent.ps1` publica en `runtime\agent-status.json`:

- `strict_hermetic`
- `strict_profiles_ok`
- `strict_block_rules_inbound`
- `strict_block_rules_outbound`
- `strict_allow_bypass_rules`
- `strict_foreign_local_rules`
- `strict_disabled_rules_last_cycle`
- `strict_error`

El panel solo muestra `Modo hermetico: ACTIVO` cuando los tres perfiles estan activos en Block, existen reglas estrictas de complemento en ambas direcciones y no se detecta una regla `Allow-Bypass` externa. Las reglas locales ajenas normales se siguen deshabilitando, pero su mera existencia no causa un falso ERROR porque un Block explicito coincidente prevalece sobre un Allow normal.

## Limite que el panel no oculta

Una regla administrada tipo `Allow-Bypass` puede estar disenada para saltarse reglas Block. Si Windows reporta una de esas reglas, IPWall no muestra un falso estado verde: marca `Modo hermetico: NO CONFIRMADO` y muestra el contador de `Allow-Bypass` externos.

Tambien un administrador local, una GPO, un producto de seguridad con driver propio, una VPN/hipervisor con ruta fuera del firewall de Windows o la desactivacion del servicio de firewall pueden cambiar el modelo. IPWall v4.6.1 garantiza el modelo allowlist-only dentro de la politica efectiva de Windows Defender Firewall que puede controlar y auditar; no afirma poder vencer una politica de mayor privilegio.

## Actualizacion desde v4.5 / v4.4 / v4.3 / v4.2 / v4.0

Ademas de la reparacion v4.6 descrita arriba, se conservan estas correcciones de las revisiones anteriores:

- El instalador ya no vacia `requests.json` ni adelanta el cursor WFP al actualizar. Migra el historial legacy si el runtime nuevo esta vacio.
- El agente publica su primer heartbeat/estado hermetico al arrancar, antes del ciclo pesado de WFP/DNS. El instalador espera hasta 45 s y deja el mensaje de error real si algo falla.
- Las IP WFP se guardan en `requests.json` inmediatamente despues de detectarlas; DNS/PTR se anaden en una segunda escritura. La aparicion de una IP ya no espera una resolucion DNS lenta.
- El panel elige la fuente runtime/legacy realmente activa y, si ambas estan caidas, muestra el archivo de solicitudes util mas reciente en vez de un `runtime\requests.json` vacio.


1. Copia los archivos de codigo de esta version sobre `C:\xampp\htdocs\ipwall`.
2. No borres `whitelist.txt` ni `whitelist-inbound.txt`.
3. Abre `http://localhost/ipwall/`.
4. Pulsa `Instalar IPWall`.
5. Espera a ver `Agente: ACTIVO`, `Modo hermetico: ACTIVO` y `Control SYSTEM: ACTIVO`.

Si ya existe el broker SYSTEM, la actualizacion no depende de `exec`, `popen` o `shell_exec` de PHP. Un agente 4.0/4.2/4.3 activo tambien puede usar el puente de compatibilidad para lanzar la actualizacion SYSTEM.

## Restauracion

`Restaurar firewall` importa el respaldo `.wfw` creado antes de la primera instalacion de IPWall, restaura la auditoria anterior y retira la tarea del agente de politica. El broker SYSTEM se conserva para permitir reinstalar desde el panel.

## Diagnostico

`diagnose.ps1` muestra el estado de los perfiles, ejecuta la auditoria estricta y lista los eventos WFP 5152/5157 recientes. Lee primero el estado de `runtime\` y conserva fallback de lectura para instalaciones antiguas.

El archivo de errores del agente es:

`C:\ProgramData\IPWhitelistFirewall\agent-errors.log`

## Panel anti-cache

El boton `Actualizar` fuerza respuesta `no-store/no-cache`, usa un nonce nuevo y espera brevemente un nuevo ciclo del agente. La autorrecarga continua cada 3 segundos cuando la pagina esta visible.
