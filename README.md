# hostspy

Interceptor HTTPS genérico y proxy TCP con terminación TLS. Redirige dominios
concretos a tu propia máquina vía `hosts`, sirve un certificado local y puede
reenviar peticiones al servidor real mientras registra cabeceras, respuestas,
frames de WebSocket y, en puertos TCP adicionales como `1119`, los bytes de
aplicación descifrados en ambos sentidos. El guardado de cuerpos completos es
opcional y está desactivado en la configuración de ejemplo. También puede
generar `.decoded.txt` con una interpretación heurística de WebSocket y
protobuf.

Algunos clientes pueden aplicar validaciones TLS adicionales. HostSpy no las
omite: `tcpTls.passthroughHosts` permite tunelar TLS extremo a extremo sin
descifrarlo. En ese modo el contenido de aplicación no se registra ni se
decodifica.

```
HTTP/HTTPS:
cliente --(hosts: 127.0.0.1)--> hostspy --(TLS real)--> servidor real

TCP/TLS (ej. SC2 1119):
cliente --(hosts: 127.0.0.1)--> hostspy:1119 --(TLS real)--> servidor real:1119
cliente --(hosts: 127.0.0.1)--> hostspy:1119 --(TLS original tunelado)--> servidor real:1119
```

## Por qué self-signed y no una CA

En Windows, Schannel comprueba la revocación (CRL/OCSP) de cualquier
certificado que **no** sea una raíz de confianza. Un certificado emitido por una
CA local no tiene CRL y falla con:

```
CRYPT_E_NO_REVOCATION_CHECK (0x80092012)
```

Un certificado **self-signed instalado en `LocalMachine\Root`** es su propia
ancla de confianza, así que Windows no intenta comprobar revocación. Es
exactamente lo que hace `ageLANServer` con AoE2.

## Por qué el upstream se resuelve con DNS público

El `hosts` apunta esos dominios a `127.0.0.1`. Si el proxy reenviara usando la
resolución del sistema, se llamaría a sí mismo en bucle (miles de
`context canceled`). Por eso:

1. Se consulta el registro real **directamente por UDP/TCP a `dnsServers`**
   (implementación DNS propia: Go siempre mira el `hosts` antes de DNS, incluso
   con un `Dial` custom).
2. Las IPs se cachean 5 minutos (30 si vienen de la resolución de arranque).
3. La resolución de arranque es **concurrente y con presupuesto**
   (`resolveTimeoutMs`, 3 s por defecto), así que el arranque nunca se cuelga.
4. Si un dominio no existe públicamente, **no se añade al `hosts`**, para no
   cambiar el comportamiento del cliente (sigue recibiendo NXDOMAIN).
5. Como red de seguridad, un upstream que resuelva a loopback se rechaza con
   `refusing to forward ... to loopback (hosts recursion)`.

## Uso rápido (Windows)

Copia `config.example.json` como `config.json` y ajusta dominios, upstreams y
puertos para tu entorno. El ejemplo deja desactivado el guardado de cuerpos.

```powershell
Copy-Item .\config.example.json .\config.json
# Doble clic o consola normal: se auto-eleva a Administrador
.\run.ps1
```

`run.ps1`:
1. Compila si hay cambios en el código.
2. Genera el certificado y lo instala en `LocalMachine\Root` (si hace falta).
3. Limpia bloques viejos del `hosts`.
4. Arranca `hostspy.exe` (modifica `hosts`, escucha `:443`, `:80` y los
   puertos de `interceptPorts`, por ejemplo `:1119`).
5. Al salir restaura el `hosts`.

Luego abre el juego normalmente. Todo se guarda en `logs/`.

## Uso manual

```powershell
# Como Administrador
.\hostspy.exe                       # arranca (modifica hosts + escucha)
.\hostspy.exe -install-cert         # solo genera e instala el certificado
.\hostspy.exe -regen-cert           # regenera el certificado (p.ej. nuevos dominios)
.\hostspy.exe -restore              # quita el bloque de hostspy del hosts
.\hostspy.exe -no-hosts             # no toca el hosts (útil para pruebas)
.\hostspy.exe -config otra.json
```

Si el proceso muere de golpe y el `hosts` queda modificado:

```powershell
.\restore.ps1
```

## Configuración (`config.json`)

| Campo | Descripción |
|---|---|
| `listenHTTPS` | Puerto TLS (por defecto `:443`, obligatorio para el juego). |
| `listenHTTP` | Puerto HTTP plano (por defecto `:80`). Vacío para desactivar. |
| `listenIP` | IP de escucha; vacío = todas. |
| `logDir` | Carpeta de logs (relativa al config). |
| `saveBodies` | Guardar peticiones/respuestas completas en archivos. |
| `redactLogs` | Redactar secretos en los logs (por defecto `true`): `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Auth-Token`, `X-Api-Key`, `X-Csrf-Token` y parámetros de query tipo token. |
| `restoreHostsOnExit` | Restaurar el `hosts` al salir. |
| `upstreamInsecureSkipVerify` | No verificar el TLS del servidor real (solo si te da problemas). |
| `dnsServers` | DNS públicos para resolver el destino real (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`). |
| `resolveTimeoutMs` | Presupuesto total (ms) para resolver los dominios al arrancar. Por defecto `3000`. |
| `certificateDomains` | Nombres (y comodines) que lleva el certificado. |
| `interceptHosts` | Nombres que se redirigen a `127.0.0.1` en el `hosts`. |
| `upstreams` | Override `host -> URL`; por defecto `https://host`. |
| `interceptPorts` | Puertos TCP extra con terminación TLS (por defecto `[]`; para SC2, `[1119]`). No pueden coincidir con `listenHTTP`/`listenHTTPS`. |
| `tcpTls.logApplicationData` | Escribir los bytes descifrados de cada conexión en un archivo propio. Activo en `config.json`; desactivado en `config.example.json`. |
| `tcpTls.logHex` | Incluir volcado hexadecimal con offsets en el log de datos. Obligatorio si se activa el decodificador. |
| `tcpTls.maxLoggedBytesPerDirection` | Tope de bytes registrados por sentido. `0` = `65536` por defecto; negativo = sin límite; positivo = tope explícito. El tráfico se reenvía completo. |
| `tcpTls.handshakeTimeoutMs` | Timeout de las negociaciones TLS (cliente y upstream). Por defecto `10000`. |
| `tcpTls.connectTimeoutMs` | Timeout de conexión al upstream. Por defecto `15000`. |
| `tcpTls.upstreams` | Override `host -> host:puerto` o URL para los puertos TCP; tiene prioridad sobre `upstreams`. |
| `tcpTls.defaultUpstream` | Destino usado solo si el cliente TLS no envía SNI. Sin esto, esas conexiones se cierran y se registran. |
| `tcpTls.plaintextUpstream` | Si se define, el tráfico no-TLS de esos puertos se reenvía tal cual a ese destino (passthrough). Vacío = se rechaza. |
| `tcpTls.passthroughHosts` | Patrones (`path.Match`, p. ej. `*.actual.battle.net`) cuyo TLS **no** se descifra: se tunela el TLS original de extremo a extremo. Útil cuando un cliente rechaza el certificado local; el motivo exacto debe verificarse para cada cliente. Vacío = todo se descifra. |
| `tcpTls.halfCloseTimeoutMs` | Margen (ms) que se espera al otro sentido tras un *half-close*. Si no llega nada, se cierran ambos lados. Por defecto `5000`; evita sockets atascados en `FIN_WAIT_2`. |
| `tcpTls.decodeApplicationData` | Crea un `.decoded.txt` junto a cada log TCP: handshake HTTP, frames WebSocket, control, fragmentos y campos protobuf genéricos. Requiere `logApplicationData` y `logHex`. Desactivado en el ejemplo; activo en `config.json`. |
| `tcpTls.decodedMaxDepth` | Profundidad máxima al interpretar mensajes protobuf anidados. Por defecto `12`. |
| `tcpTls.decodedIncludeHex` | Incluir el hex de cada payload de frame en el `.decoded.txt` (además de los campos interpretados). |
| `tcpTls.decodedChunkEvents` | Anotar en el `.decoded.txt` cada lectura de socket, con su tamaño y offset de flujo. |

Al añadir dominios nuevos a `certificateDomains`, ejecuta `.\run.ps1
-ForceCert` (o, como Administrador, `.\hostspy.exe -regen-cert -install-cert`).
`run.ps1` reinstala el certificado en cada arranque y `ca.Ensure` lo regenera si
no cubre todos los nombres configurados.

### Dominios de AoE2:DE

`config.json` ya trae la lista que usa el cliente:

```
api.ageofempires.com
cdn.ageofempires.com
aoe-api.worldsedgelink.com
pb-live-release{1..12}-api.worldsedgelink.com
```

`aoe-api.relic.link` no tiene DNS público (lo inventa `ageLANServer`), por eso no
se intercepta por defecto.

## Qué se registra

```
logs/
  hostspy.log                        # resumen en vivo: HTTP, WS, TLS, TCP
  2026-10-25/
    001_012618.715_api.ageofempires.com_getProfile.txt
    002_012619.002_...txt
    websocket.log                    # frames WS decodificados (texto legible)
    tcp_001_121802.012_us.actual.battle.net_1119.log   # si logApplicationData
```

Cada `.txt` compara las dos caras de la transacción:

1. **Petición del cliente**, tal y como llegó (antes de tocar nada).
2. **Cambios aplicados solo por transporte**: `Host` cuando el upstream es otro,
   y cabeceras hop-by-hop eliminadas.
3. **Petición enviada al upstream**, con las cabeceras y el cuerpo reales.
4. **Respuesta del upstream**, con su estado, cabeceras y cuerpo originales.
5. **Respuesta entregada al cliente**: mismo estado y mismos bytes.

Los cuerpos se guardan hasta 2 MiB por sentido. Si son mayores, el log lo indica
con `log capture truncated`, pero **el cliente recibe todos los bytes**. Si la
respuesta viene comprimida, se reenvía comprimida y el log muestra una copia
descomprimida marcada como tal.

`hostspy.log` también incluye los errores del servidor TLS (por ejemplo
`http: TLS handshake error ... remote error: tls: bad certificate`), lo que
permite distinguir un fallo de certificado de un fallo de aplicación.

## Interceptación TCP con TLS (StarCraft II, puerto 1119)

`interceptPorts` añade listeners TCP independientes de `:443` y `:80`. En cada
conexión HostSpy termina el TLS del cliente, registra los bytes descifrados y
abre **otra sesión TLS independiente** contra el servidor real. El contenido de
aplicación no se interpreta como HTTP: se reenvía byte a byte.

```
cliente SC2 --(hosts: 127.0.0.1)--> 127.0.0.1:1119
                                      │ TLS cliente (certificado self-signed)
                                      ▼
                                 hostspy: descifra y registra
                                      │ TLS upstream independiente (validado)
                                      ▼
                              us.actual.battle.net:1119
```

### Cómo se recupera el destino original

El `hosts` solo asocia un **nombre** a `127.0.0.1`; cuando el cliente conecta a
`127.0.0.1:1119` la IP ya no identifica el servidor. La fuente fiable es el
**SNI del ClientHello TLS**:

- `us.actual.battle.net` + el puerto de escucha `1119` ⇒ upstream
  `us.actual.battle.net:1119`.
- `tcpTls.upstreams` permite un override explícito por host (valores
  `host:puerto`, `host` o URL; `https://`/`tls://` cifran, `http://`/`tcp://`
  van en plano).
- `tcpTls.defaultUpstream` se usa **solo** si el cliente no envía SNI.
- Nunca se usa `127.0.0.1:1119` como upstream ni se adivina el dominio por el
  puerto.

Si no hay SNI y no hay `defaultUpstream`, la conexión se registra y se cierra;
no se inventa un destino. Si una captura de tu cliente no trae SNI, fija
`defaultUpstream` en el host de **tu** región (`eu.actual.battle.net:1119`
en `config.json`). Como el emparejamiento de passthrough también mira el
`defaultUpstream`, esa elección decide a qué servidor se tunela el TLS.

El nombre debe estar además en `interceptHosts`; `config.json` ya incluye
`us.actual.battle.net`, `eu.actual.battle.net`, `kr.actual.battle.net` y
`us-s2.logon.battle.net`. Para SC2 conviene dejar solo las entradas de su
región: las demás redirigen tráfico que nunca se usa y ensucian los logs.

### Las dos sesiones TLS

1. **Cliente → HostSpy**: se presenta el mismo certificado self-signed que en
   HTTPS. Los errores de certificado o negociación se registran como
   `CLIENT HANDSHAKE FAILED`.
2. **HostSpy → servidor real**: se abre TCP al host resuelto por DNS público
   (nunca por el `hosts`) y se valida el certificado y el hostname del servidor.
   Un fallo aquí se registra como `UPSTREAM HANDSHAKE FAILED`, separado del
   anterior. `upstreamInsecureSkipVerify` desactiva esa validación; no se
   recomienda.

ALPN: se copia la lista de protocolos que ofrece el cliente en ambas sesiones.
En estos puertos no se anuncia `h2`/`http/1.1` por iniciativa propia porque el
tráfico es binario, no HTTP.

### Tráfico que no es TLS

El primer byte se inspecciona antes de negociar. Si no parece un registro TLS:

- por defecto se registra (`non-TLS data ...`) y se cierra;
- si `tcpTls.plaintextUpstream` tiene valor, se hace passthrough TCP sin
  descifrar a ese destino.

Así un puerto mal configurado no se fuerza a la lógica HTTP ni se envía basura a
un servidor TLS.

### Certificado del cliente

Se reutiliza `certs/selfsigned.crt`. La configuración incluye
`*.actual.battle.net` y `*.logon.battle.net`, pero tras cambiar
`certificateDomains` hay que regenerarlo e instalarlo:

```powershell
.\run.ps1 -ForceCert
# o, como Administrador:
.\hostspy.exe -regen-cert -install-cert
```

Que Windows confíe en el certificado **no garantiza** que el juego lo acepte:
algunos clientes aplican *certificate pinning* o validaciones propias.

### Validación TLS y el ensayo de StarCraft II

En una prueba con SC2 5.0.17, HostSpy registró que el handshake TLS terminaba y
que el cliente cerraba la conexión antes de enviar datos de aplicación. Eso
sitúa el cierre después o durante la transición al protocolo de aplicación,
pero **no demuestra pinning**. Entre las explicaciones posibles están la
validación del certificado o de su SPKI, el bundle de huellas BGS, otra
inicialización del cliente o una condición de sesión.

La petición del bundle `bgs-key-fingerprint` y su aceptación tampoco quedaron
confirmadas en esa prueba. Instalar el certificado local en Windows no prueba
que SC2 acepte el bundle ni sus validaciones propias.

Para observar únicamente la conectividad, HostSpy puede tunelar el TLS original
sin descifrarlo:

```json
"passthroughHosts": ["*.actual.battle.net"]
```

En ese modo los bytes siguen cifrados y no se generan registros de aplicación o
`.decoded.txt`. La redirección solo sirve para inspección de transporte; no
convierte HostSpy en un servidor BGS local.

### Half-close y `FIN_WAIT_2`

Cuando un lado envía FIN, el relay propaga el cierre y espera al otro sentido:

- si **no** se intercambió ningún byte de aplicación, cierra de inmediato (un
  cliente que rechaza el certificado no deja nada que drenar);
- si hubo datos, espera `halfCloseTimeoutMs` y después cierra ambos lados.

Sin ese margen, un cliente que cerraba tras el handshake dejaba su socket en
`FIN_WAIT_2` indefinidamente, porque el servidor real no cerraba su lado. Los
cierres quedan registrados como `half-close grace expired` o
`closing before any application data`.


### Log de una conexión TCP

Con `tcpTls.logApplicationData: true` se crea un archivo por conexión:

```
logs/2026-10-26/tcp_001_121802.012_us.actual.battle.net_1119.log
```

Cabecera con host, protocolo, listener, cliente, upstream y parámetros TLS
negociados. Después, un bloque por cada lectura de socket:

```
[12:18:02.019] client->upstream 1024 bytes
00000000  16 03 01 02 00 01 00 01 fc 03 03 ...
text: "..."            # solo si es UTF-8 imprimible
```

- TCP es un flujo: cada bloque es **una lectura de socket**, no un mensaje de
  aplicación.
- El hex lleva offsets y no tiene columna ASCII. Los datos binarios nunca se
  presentan como texto.
- `maxLoggedBytesPerDirection` limita lo escrito; el resto se reenvía y se
  resume como `Not logged (...)`. `0` usa 64 KiB por sentido; un valor negativo
  desactiva el límite.
- Al cerrar se anota el motivo: EOF/FIN/close_notify, RST, timeout, cierre local
  o error, además de bytes y duración.
- **`redactLogs` no se aplica** a estos bytes descifrados.

### Log decodificado (`.decoded.txt`)

Con `tcpTls.decodeApplicationData: true` —y también `logApplicationData` y
`logHex`— se crea un segundo archivo junto al crudo:

```
logs/2026-10-26/tcp_001_125144.322_us.actual.battle.net_1119.log
logs/2026-10-26/tcp_001_125144.322_us.actual.battle.net_1119.decoded.txt
```

El decodificador es **opcional y best-effort**. Recorre el mismo flujo
descifrado que el log crudo y, en orden cronológico, escribe:

1. **Handshake HTTP**: línea de petición o respuesta, cada cabecera, estado
   `101` y el texto HTTP original.
2. **Frames WebSocket**: `FIN`, `RSV1`/`RSV2`/`RSV3`, opcode con nombre
   (`binary`, `text`, `continuation`, `close`, `ping`, `pong`), máscara,
   longitud, clave de máscara y payload. Los frames del cliente se desenmascaran
   antes de interpretarlos.
3. **Fragmentación**: los frames `continuation` se acumulan y se presenta un
   único mensaje con `frames=N`; no se inventa un mensaje por fragmento.
4. **Control**: `ping`/`pong` con su payload y `close` con código numérico,
   nombre estándar y motivo.
5. **Framing de aplicación**: se prueba la forma observada en Battle.net
   `[longitud de cabecera de 2 bytes big-endian][protobuf cabecera][protobuf
   cuerpo]`. Si no encaja, el payload completo se trata como un solo protobuf.
   No se asume ningún campo; solo se separan los dos mensajes.
6. **Protobuf genérico**: número de campo, wire type y valor: `varint`,
   `fixed64`, `fixed32`, `string` entrecomillado, mensaje anidado, `bytes` en
   hex y grupos. Los nombres de campo son desconocidos: **no hay esquema de
   Battle.net hardcodeado**. Si un mensaje no parsea, se anota el error y se
   vuelca su hex.
7. **Cronología**: cada lectura de socket (`chunk #N`), frame, mensaje y campo
   aparece en el orden en que llegó. El número de mensaje es independiente por
   sentido (`C->S`, `S->C`).

Ejemplo del formato (datos ficticios):

```
[12:51:44.743] C->S chunk #3 80 bytes (stream offset 207)
[12:51:44.743] C->S frame #1 fin=true rsv1=false rsv2=false rsv3=false opcode=2 (binary) masked=true payload=74
[12:51:44.743] C->S message #1 opcode=2 (binary) frames=1 payload=74
  application framing: 2-byte big-endian length prefix (heuristic); header=11 body=61
  header (11 bytes):
    1: varint 0
    2: varint 1
  body (61 bytes):
    5: message(55) {
      1: string(11) "BGS C++ SDK"
    }
```

Detalles prácticos:

- El `.log` crudo sigue siendo la **fuente de verdad**. El `.decoded.txt` es una
  interpretación: si el tope del log crudo corta una lectura, el decodificador
  se detiene y lo anota; no continúa con bytes que no están en el crudo.
- Los hosts de `tcpTls.passthroughHosts` **no** generan `.decoded.txt` ni log de
  bytes: el TLS viaja cifrado y HostSpy no ve el texto claro. El modo
  passthrough no permite observar el contenido TLS.
- Si el primer tráfico no parece HTTP/WebSocket, pasa a modo `raw` y solo vuelca
  el hex de los bloques.
- `tcpTls.decodedIncludeHex: true` añade el hex de cada payload de frame;
  `tcpTls.decodedChunkEvents: true` añade una línea por lectura de socket. Es la
  combinación de máximo detalle.
- `tcpTls.decodedMaxDepth` controla la recursión en mensajes anidados.
- Un `maxLoggedBytesPerDirection` negativo registra todo lo que pase, pero el
  archivo puede crecer mucho; el decodificador crece con él.

**Privacidad:** el `.decoded.txt` contiene los mismos datos sensibles que el
crudo, ya en texto claro: correo, BattleTag, IDs de cuenta y sesión, amigos,
grupos, canales, claves y tokens. No lo compartas ni lo subas a un repositorio.
Para publicar un análisis, extrae solo los campos necesarios y redáctalos a
mano.

### Qué se observa en el 1119

> Esta captura procede del cliente de escritorio de Battle.net (`BGS C++ SDK
> 8.1.0`), no de SC2. No se debe asumir que SC2 use exactamente los mismos
> mensajes o que HostSpy pueda descifrarlos.

En una captura real de Battle.net el flujo es:

- `GET / HTTP/1.1` con `Upgrade: websocket`, `Connection: Upgrade` y
  `Sec-WebSocket-Protocol: v1.rpc.battle.net`; el servidor responde `101`.
- Todos los frames observados son binarios (opcode `2`); el cliente los envía
  enmascarados y el servidor sin máscara.
- Cada payload binario es un RPC de Battle.net en protobuf, con la forma
  `[2 bytes big-endian: longitud de cabecera][cabecera protobuf][cuerpo
  protobuf]`.
- La cabecera usa campos como tipo de mensaje, servicio, token y un
  identificador de sesión; el cuerpo contiene datos de SDK/versión, plataforma,
  idioma, cuenta, BattleTag, amigos, grupos y canales.
- El cliente y el upstream negocian TLS de forma independiente (en la captura,
  TLS 1.2 hacia HostSpy y TLS 1.3 hacia el servidor); no hay downgrade.

Los números y nombres exactos de los campos no se asumen en el código: el
`.decoded.txt` muestra lo que hay en el cable, campo por campo.

### Gameplay: el 1119 no lleva la partida

El canal `1119` transporta plataforma, login, presencia, social, grupos y
servicios de Battle.net. **No contiene el estado de la partida.** Para analizar
una partida hacen falta capturas **UDP** de los relays del juego
(`27013-27015` en SC2) y/o el análisis de *replays*; el `.decoded.txt` de un
`1119` no va a mostrar unidades, órdenes ni mapa.

### Cómo comprobar que funciona

1. Pon `"interceptPorts": [1119]` y arranca hostspy.
2. La consola debe mostrar `TCP/TLS listening on ...:1119`.
3. Comprueba el puerto:
   ```powershell
   Test-NetConnection 127.0.0.1 -Port 1119
   ```
   Ese test envía tráfico no-TLS: es normal que se registre y se cierre.
4. Prueba el cliente que quieras observar y correlaciona sus mensajes con los
   logs de conexión. Un handshake TLS correcto no demuestra por sí solo que el
   cliente haya aceptado la conexión para enviar datos de aplicación.
5. Si la sesión **no** es de passthrough y activaste `decodeApplicationData`,
   abre el `.decoded.txt` de la misma conexión: debe empezar por el `GET /` y el
   `101`, y seguir con frames y campos protobuf en orden. El arranque muestra
   `decoded: ...decoded.txt`.
6. Confirma que el upstream es el nombre real de tu región (por ejemplo
   `eu.actual.battle.net:1119`), nunca `127.0.0.1`.
7. Comprueba que ya no se acumulan cierres a medias:
   ```powershell
   Get-NetTCPConnection -LocalPort 1119 | Group-Object State
   ```
   Tras cerrar SC2 no deben quedar conexiones en `FINWait2`.
8. Verifica que HTTP/HTTPS siguen igual: `curl.exe -v https://api.ageofempires.com/`.

### Si el puerto 1119 no se puede abrir

Hyper-V, WSL o Docker pueden reservar rangos de puertos TCP en Windows. Si
`1119` cae dentro de uno, el `bind` falla con un error de permisos aunque el
puerto parezca libre:

```powershell
netsh interface ipv4 show excludedportrange protocol=tcp
```

`run.ps1` avisa si algún `interceptPort` está en un rango excluido. La forma
más simple de arrancar es dejar que pare `winnat` durante la sesión y lo
reinicie al salir:

```powershell
.\run.ps1 -StopWinNAT
```

Equivalente manual (Administrador):

```powershell
net stop winnat
.\run.ps1
# al terminar hostspy:
net start winnat
```

Parar `winnat` interrumpe temporalmente la red de WSL2/Docker/Hyper-V. Como
alternativa permanente, mueve el rango dinámico y reinicia:

```powershell
netsh int ipv4 set dynamicport tcp start=49152 num=16384
```

### Limitaciones de TCP/TLS

- Requiere SNI (o `tcpTls.defaultUpstream`).
- Solo TCP. UDP, QUIC y HTTP/3 no se interceptan.
- Si un cliente rechaza el certificado local por una política propia, el modo
  `tcpTls.passthroughHosts` conserva el TLS original pero no permite descifrar
  ni decodificarlo. La causa debe confirmarse por cliente; el ensayo de SC2
  descrito arriba no identificó qué validación cerró la conexión.
- El certificado del servidor real debe validar contra las raíces del sistema
  (o usar `upstreamInsecureSkipVerify`).
- Un puerto ocupado o reservado por Windows impide arrancar: los listeners TCP
  se abren **antes** de modificar el `hosts`, para no dejar la máquina apuntando
  a un servicio muerto.
- Las IPs literales y el tráfico que no pase por `hosts` no se redirigen.

## Fidelidad del reenvío

La regla es que el servidor real reciba la misma petición que habría recibido sin
proxy, y que el cliente reciba la misma respuesta:

- Se conservan **exactamente** `Origin`, `Referer`, `User-Agent`, `Cookie`,
  `Authorization`, `Content-Type`, `Accept`, `Accept-Language`,
  `Access-Control-Request-*`, `Sec-Fetch-*`, `Cache-Control`, `If-None-Match` e
  `If-Modified-Since`, entre otras.
- Se conservan el **método**, la **ruta y query** (orden, codificación y valores
  repetidos) y el **cuerpo byte a byte**.
- Se conservan el **estado**, las **cabeceras de aplicación** y el **cuerpo** de la
  respuesta. No se siguen redirecciones: el cliente ve el `3xx` real.
- Solo cambia lo estrictamente necesario para el transporte: `Host` (si el
  upstream resuelto es otro), SNI/TLS, `Connection`/`Keep-Alive`/
  `Transfer-Encoding` (hop-by-hop) y `Content-Length` cuando hay que recalcularlo.
- No se añade ninguna cabecera `X-Forwarded-*`.
- **`Accept-Encoding` es transparente**: se reenvía tal cual y el transporte tiene
  la compresión desactivada, así que la respuesta llega con sus bytes y su
  `Content-Encoding` originales. La descompresión para el log se hace sobre una
  copia, nunca sobre el cuerpo entregado.
- **WebSocket**: el handshake y los frames se reenvían byte a byte, incluido
  `Sec-WebSocket-Extensions`, por lo que `permessage-deflate` sigue funcionando.
  Los frames comprimidos se marcan en el log en vez de imprimirlos.

## Verificar que funciona

Con hostspy corriendo:

```powershell
curl.exe -v https://api.ageofempires.com/
```

Debe devolver `HTTP/1.1 200` sin errores de `schannel` y aparecer una línea en
`logs/hostspy.log`.

Comprobar TLS y ALPN:

```powershell
"" | openssl s_client -connect 127.0.0.1:443 -servername api.ageofempires.com -alpn h2,http/1.1
```

Debe mostrar `ALPN protocol: h2`.

## Limitaciones

- El tráfico que no use `hosts` (IPs literales, DoH propio del cliente, QUIC o
  HTTP/3 sobre UDP 443) no se intercepta.
- El tráfico UDP del juego (relays de partida en `27013-27015`) tampoco se captura.
- El `.decoded.txt` es heurístico: no conoce el esquema protobuf de Battle.net,
  así que muestra números de campo, no nombres. Se detiene si el log crudo
  alcanza su tope, y un cambio de protocolo solo produce un volcado `raw`.
- Si el WebSocket negocia `permessage-deflate`, los frames comprimidos se marcan
  (`RSV1`) pero no se descomprimen: el payload se vuelca tal cual. La captura
  observada en `1119` no negocia esa extensión.
- En `interceptPorts`, el cliente debe enviar SNI; sin SNI hace falta
  `tcpTls.defaultUpstream`.
- WebSocket: se reenvía byte a byte y se decodifican los frames para el log.
- DNS: no se toca nada más allá del `hosts`.

## Notas de seguridad

- `certs/selfsigned.key` es la clave privada del certificado de confianza. No la
  compartas.
- Con `redactLogs` activo se ocultan cabeceras de autorización/cookies y valores
  de query sensibles. Aun así, **revisa los cuerpos antes de compartir un log**:
  pueden contener credenciales en JSON o formularios.
- `tcpTls.logApplicationData` escribe los bytes descifrados **sin redacción**.
  Pueden contener tickets, tokens o credenciales del juego: trata esos
  `tcp_*.log` como secretos y desactiva la opción cuando no los necesites.
- `tcpTls.decodeApplicationData` crea un `.decoded.txt` que hace esos datos aún
  más legibles: correo, BattleTag, IDs de cuenta/sesión, amigos, grupos, canales
  y claves en texto plano. Aplica la misma regla: no lo compartas. Para
  publicarlo, redacta manualmente los campos sensibles.
- Mientras hostspy corre, esos dominios apuntan a tu máquina. Al cerrarlo se
  restaura el `hosts`; si algo falla, usa `restore.ps1`.
