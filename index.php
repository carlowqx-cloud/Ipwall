<?php
/* IPWall v4.6.1 - runtime estable, migracion robusta y panel sin cache - PHP 5.6+ */
// El panel es operativo y sus datos cambian continuamente. Nunca permitir que
// navegador, proxy o Apache reutilicen una copia anterior de index.php.
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private');
header('Pragma: no-cache');
header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
header('Surrogate-Control: no-store');
header('X-Accel-Expires: 0');
require_once __DIR__ . DIRECTORY_SEPARATOR . 'ipwall-net.php';
$dir = __DIR__;
$whitelistFile = $dir . DIRECTORY_SEPARATOR . 'whitelist.txt'; // Permisos salientes heredados
$inboundWhitelistFile = $dir . DIRECTORY_SEPARATOR . 'whitelist-inbound.txt';
$runtimeDir = $dir . DIRECTORY_SEPARATOR . 'runtime';
if (!is_dir($runtimeDir)) @mkdir($runtimeDir, 0775, true);

// Desde v4.4 los ficheros que cambian cada segundo viven fuera de la raiz.
// v4.6 conserva lectura legacy durante migraciones/fallos para que un runtime
// vacio o incompleto nunca oculte IPs que el agente anterior sigue registrando.
$runtimeRequestsFile = $runtimeDir . DIRECTORY_SEPARATOR . 'requests.json';
$runtimeStatusFile = $runtimeDir . DIRECTORY_SEPARATOR . 'agent-status.json';
$runtimeClearFlag = $runtimeDir . DIRECTORY_SEPARATOR . 'clear-requests.flag';
$runtimeRestoreFlag = $runtimeDir . DIRECTORY_SEPARATOR . 'restore-firewall.flag';
$runtimeControlStatusFile = $runtimeDir . DIRECTORY_SEPARATOR . 'control-status.json';
$runtimeControlRequestFile = $runtimeDir . DIRECTORY_SEPARATOR . 'system-control.request.json';
$runtimeBrokerStatusFile = $runtimeDir . DIRECTORY_SEPARATOR . 'control-broker-status.json';

$legacyRequestsFile = $dir . DIRECTORY_SEPARATOR . 'requests.json';
$legacyStatusFile = $dir . DIRECTORY_SEPARATOR . 'agent-status.json';
$legacyClearFlag = $dir . DIRECTORY_SEPARATOR . 'clear-requests.flag';
$legacyRestoreFlag = $dir . DIRECTORY_SEPARATOR . 'restore-firewall.flag';
$legacyControlStatusFile = $dir . DIRECTORY_SEPARATOR . 'control-status.json';
$legacyControlRequestFile = $dir . DIRECTORY_SEPARATOR . 'system-control.request.json';
$legacyBrokerStatusFile = $dir . DIRECTORY_SEPARATOR . 'control-broker-status.json';

$requestsFile = $runtimeRequestsFile;
$statusFile = $runtimeStatusFile;
$clearFlag = $runtimeClearFlag;
$restoreFlag = $runtimeRestoreFlag;
$controlStatusFile = $runtimeControlStatusFile;
$controlRequestFile = $runtimeControlRequestFile;
$brokerStatusFile = $runtimeBrokerStatusFile;
$controlScript = $dir . DIRECTORY_SEPARATOR . 'ipwall-control.ps1';
$systemWorkerScript = $dir . DIRECTORY_SEPARATOR . 'ipwall-system-worker.ps1';

$remote = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
if ($remote !== '127.0.0.1' && $remote !== '::1') {
    http_response_code(403);
    exit('Solo localhost.');
}

session_name('IPWALLSESSID');
if (session_status() !== PHP_SESSION_ACTIVE) session_start();
// session_start puede instalar su propio cache limiter; reafirmar la politica
// despues de abrir la sesion para que la respuesta final siga siendo no-store.
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private');
header('Pragma: no-cache');
header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
if (empty($_SESSION['ipwall_token'])) {
    $_SESSION['ipwall_token'] = bin2hex(openssl_random_pseudo_bytes(24));
}
$csrfToken = $_SESSION['ipwall_token'];

if (!file_exists($whitelistFile)) file_put_contents($whitelistFile, '');
if (!file_exists($inboundWhitelistFile)) file_put_contents($inboundWhitelistFile, '');
// No crear JSON de runtime vacios desde PHP. Un placeholder reciente podia
// ocultar datos legacy validos durante una migracion fallida. El agente/broker
// crean sus propios archivos cuando realmente arrancan.

function valid_ip($ip) {
    return ipwall_valid_ip($ip);
}

// Las acciones antiguas sin direction siguen siendo salientes al actualizar.
function requested_direction() {
    if (!isset($_POST['direction'])) return 'outbound';
    if (!is_string($_POST['direction']) || !in_array($_POST['direction'], array('inbound', 'outbound'), true)) {
        throw new Exception('Dirección de tráfico inválida.');
    }
    return $_POST['direction'];
}

function read_json_file($file, $default) {
    // El agente reescribe estos JSON cada pocos segundos. Limpiar el stat cache
    // y reintentar evita mostrar [] si PHP alcanza el archivo durante la escritura.
    for ($attempt = 0; $attempt < 4; $attempt++) {
        clearstatcache(true, $file);
        if (!file_exists($file)) return $default;
        $raw = @file_get_contents($file);
        if ($raw !== false && trim($raw) !== '') {
            if (substr($raw, 0, 3) === "\xEF\xBB\xBF") $raw = substr($raw, 3);
            $v = json_decode($raw, true);
            if (is_array($v)) return $v;
        }
        if ($attempt < 3) usleep(20000);
    }
    return $default;
}

// Defensa adicional: nunca presentar filas heredadas del log general de
// Windows ni atribuciones por proximidad. Solo un evento WFP 5152/5157 directo
// con ejecutable de navegador entra en la tabla.
function browser_request_verified($r) {
    if (!is_array($r)) return false;
    if (!isset($r['browser_verified']) || $r['browser_verified'] !== true) return false;
    if (!isset($r['application_source']) || !in_array($r['application_source'], array('WFP 5152 (directo)', 'WFP 5157 (directo)'), true)) return false;
    $exe = isset($r['application_exe']) ? strtolower(trim((string)$r['application_exe'])) : '';
    $browsers = array(
        'brave.exe', 'chrome.exe', 'chromium.exe', 'msedge.exe', 'firefox.exe',
        'opera.exe', 'opera_gx.exe', 'vivaldi.exe', 'waterfox.exe',
        'librewolf.exe', 'iexplore.exe', 'zen.exe', 'floorp.exe',
        'palemoon.exe', 'seamonkey.exe', 'duckduckgo.exe', 'arc.exe'
    );
    return in_array($exe, $browsers, true) &&
        isset($r['ip']) && valid_ip((string)$r['ip']);
}

function read_whitelist($file) {
    clearstatcache(true, $file);
    $rows = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($rows === false) return array();
    $out = array();
    foreach ($rows as $row) {
        try {
            $entry = ipwall_normalize_entry($row);
            if (!in_array($entry, $out, true)) $out[] = $entry;
        } catch (Exception $e) {
            // Ignorar entradas no validas; nunca convertirlas en rangos abiertos.
        }
    }
    natcasesort($out);
    return array_values($out);
}

function write_whitelist($file, $ips) {
    $clean = array();
    foreach ($ips as $ip) {
        $entry = ipwall_normalize_entry($ip);
        if (!in_array($entry, $clean, true)) $clean[] = $entry;
    }
    natcasesort($clean);
    $clean = array_values($clean);
    $data = count($clean) ? implode(PHP_EOL, $clean) . PHP_EOL : '';
    $tmp = $file . '.tmp';
    if (@file_put_contents($tmp, $data, LOCK_EX) === false) {
        throw new Exception('No se pudo escribir ' . basename($file));
    }
    if (file_exists($file)) @unlink($file);
    if (!@rename($tmp, $file)) {
        @unlink($tmp);
        throw new Exception('No se pudo reemplazar ' . basename($file));
    }
}

function h($v) {
    return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8');
}

function fresh_nonce() {
    $rand = '';
    try { $rand = bin2hex(openssl_random_pseudo_bytes(5)); } catch (Exception $e) { $rand = mt_rand(10000, 99999); }
    return str_replace('.', '', sprintf('%.6F', microtime(true))) . '-' . $rand;
}

function redirect_fresh() {
    // 303 evita reenvio del POST y el nonce obliga una peticion GET nueva.
    header('Location: ./?_refresh=' . rawurlencode(fresh_nonce()), true, 303);
    exit;
}

function write_json_atomic($file, $data) {
    $json = json_encode($data);
    if ($json === false) throw new Exception('No se pudo serializar el estado de control.');
    $tmp = $file . '.tmp';
    if (@file_put_contents($tmp, $json, LOCK_EX) === false) throw new Exception('No se pudo escribir ' . basename($file));
    if (file_exists($file)) @unlink($file);
    if (!@rename($tmp, $file)) {
        @unlink($tmp);
        throw new Exception('No se pudo actualizar ' . basename($file));
    }
}

function agent_status_is_alive($status, $requiredVersion) {
    $heartbeat = isset($status['heartbeat_unix']) ? (int)$status['heartbeat_unix'] : 0;
    $version = isset($status['agent_version']) ? (string)$status['agent_version'] : '';
    return $version === $requiredVersion && $heartbeat > 0 && (time() - $heartbeat) <= 12;
}

function agent_status_is_alive_any($status) {
    $heartbeat = isset($status['heartbeat_unix']) ? (int)$status['heartbeat_unix'] : 0;
    return $heartbeat > 0 && (time() - $heartbeat) <= 12;
}

function broker_status_is_alive($status) {
    $heartbeat = isset($status['heartbeat_unix']) ? (int)$status['heartbeat_unix'] : 0;
    return $heartbeat > 0 && (time() - $heartbeat) <= 15;
}

// Elegir la fuente REAL que esta viva. Si ninguna tiene heartbeat, usar el
// archivo de solicitudes mas reciente/no vacio para no esconder datos durante
// una actualizacion fallida. Nunca confiar solo en que runtime\ exista.
$runtimeStatusProbe = read_json_file($runtimeStatusFile, array());
$legacyStatusProbe = read_json_file($legacyStatusFile, array());
$runtimeHeartbeatProbe = isset($runtimeStatusProbe['heartbeat_unix']) ? (int)$runtimeStatusProbe['heartbeat_unix'] : 0;
$legacyHeartbeatProbe = isset($legacyStatusProbe['heartbeat_unix']) ? (int)$legacyStatusProbe['heartbeat_unix'] : 0;
$runtimeAliveProbe = agent_status_is_alive_any($runtimeStatusProbe);
$legacyAliveProbe = agent_status_is_alive_any($legacyStatusProbe);
if ($legacyAliveProbe && (!$runtimeAliveProbe || $legacyHeartbeatProbe > $runtimeHeartbeatProbe)) {
    $requestsFile = $legacyRequestsFile;
    $statusFile = $legacyStatusFile;
    $clearFlag = $legacyClearFlag;
    $restoreFlag = $legacyRestoreFlag;
} elseif (!$runtimeAliveProbe && !$legacyAliveProbe) {
    clearstatcache(true, $runtimeRequestsFile);
    clearstatcache(true, $legacyRequestsFile);
    $runtimeMtimeProbe = file_exists($runtimeRequestsFile) ? (int)@filemtime($runtimeRequestsFile) : 0;
    $legacyMtimeProbe = file_exists($legacyRequestsFile) ? (int)@filemtime($legacyRequestsFile) : 0;
    $runtimeSizeProbe = file_exists($runtimeRequestsFile) ? (int)@filesize($runtimeRequestsFile) : 0;
    $legacySizeProbe = file_exists($legacyRequestsFile) ? (int)@filesize($legacyRequestsFile) : 0;
    if ($legacySizeProbe > 2 && ($runtimeSizeProbe <= 2 || $legacyMtimeProbe >= $runtimeMtimeProbe)) {
        $requestsFile = $legacyRequestsFile;
        $statusFile = $legacyStatusFile;
        $clearFlag = $legacyClearFlag;
        $restoreFlag = $legacyRestoreFlag;
    }
}
$runtimeBrokerProbe = read_json_file($runtimeBrokerStatusFile, array());
$legacyBrokerProbe = read_json_file($legacyBrokerStatusFile, array());
$runtimeBrokerHeartbeat = isset($runtimeBrokerProbe['heartbeat_unix']) ? (int)$runtimeBrokerProbe['heartbeat_unix'] : 0;
$legacyBrokerHeartbeat = isset($legacyBrokerProbe['heartbeat_unix']) ? (int)$legacyBrokerProbe['heartbeat_unix'] : 0;
$runtimeBrokerAlive = broker_status_is_alive($runtimeBrokerProbe);
$legacyBrokerAlive = broker_status_is_alive($legacyBrokerProbe);
if ($legacyBrokerAlive && (!$runtimeBrokerAlive || $legacyBrokerHeartbeat > $runtimeBrokerHeartbeat)) {
    $brokerStatusFile = $legacyBrokerStatusFile;
    $controlRequestFile = $legacyControlRequestFile;
    $controlStatusFile = $legacyControlStatusFile;
}

function queue_system_control_action($requestFile, $workerScript, $whitelistFile, $action, $statusFile, $nudgeAgent) {
    if (!in_array($action, array('install', 'restore'), true)) throw new Exception('Acción SYSTEM inválida.');
    if (!file_exists($workerScript)) throw new Exception('Falta ipwall-system-worker.ps1.');
    if (!file_exists($whitelistFile)) throw new Exception('No existe whitelist.txt para despertar al agente SYSTEM.');

    $id = bin2hex(openssl_random_pseudo_bytes(16));
    write_json_atomic($requestFile, array(
        'id' => $id,
        'action' => $action,
        'created_unix' => time(),
        'requested_by' => 'index.php'
    ));
    write_json_atomic($statusFile, array(
        'action' => $action,
        'state' => 'queued',
        'message' => 'Orden enviada al agente SYSTEM existente...',
        'updated_unix' => time()
    ));

    if ($nudgeAgent) {
        // Compatibilidad con el agente 4.0 ya cargado en memoria: vigila el
        // SHA-256 de whitelist.txt y ejecuta apply-whitelist.ps1 como SYSTEM.
        // Una línea vacía cambia el hash pero no cambia ninguna IP permitida.
        if (@file_put_contents($whitelistFile, PHP_EOL, FILE_APPEND | LOCK_EX) === false) {
            @unlink($requestFile);
            throw new Exception('No se pudo despertar al agente SYSTEM escribiendo whitelist.txt.');
        }
    }
}

function launch_control_action($script, $action, $projectDir, $resultFile) {
    if (stripos(PHP_OS, 'WIN') !== 0) throw new Exception('La instalación automática solo puede ejecutarse en Windows.');
    if (!in_array($action, array('install', 'restore'), true)) throw new Exception('Acción de control inválida.');
    if (!file_exists($script)) throw new Exception('Falta ipwall-control.ps1.');

    $q = function($v) { return '"' . str_replace('"', '\"', $v) . '"'; };
    $ps = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File '
        . $q($script) . ' -Action ' . $q($action) . ' -ProjectDir ' . $q($projectDir) . ' -ResultFile ' . $q($resultFile);
    $cmd = 'cmd.exe /d /c start "" /b ' . $ps . ' >NUL 2>&1';

    // Para una instalación totalmente nueva no existe todavía agente SYSTEM.
    // Se prueban todos los mecanismos de creación de procesos que suelen estar
    // disponibles en PHP/XAMPP, no solo popen/exec.
    if (class_exists('COM')) {
        try {
            $wsh = new COM('WScript.Shell');
            $rc = $wsh->Run($cmd, 0, false);
            if ($rc === 0) return;
        } catch (Exception $e) {}
    }
    if (function_exists('proc_open')) {
        $spec = array(
            0 => array('file', 'NUL', 'r'),
            1 => array('file', 'NUL', 'a'),
            2 => array('file', 'NUL', 'a')
        );
        $pipes = array();
        $proc = @proc_open($cmd, $spec, $pipes);
        if (is_resource($proc)) {
            $rc = @proc_close($proc);
            if ($rc === 0 || $rc === -1) return;
        }
    }
    if (function_exists('popen') && function_exists('pclose')) {
        $handle = @popen($cmd, 'r');
        if ($handle !== false) {
            $rc = @pclose($handle);
            if ($rc === 0 || $rc === -1) return;
        }
    }
    if (function_exists('exec')) {
        $output = array(); $rc = 1;
        @exec($cmd, $output, $rc);
        if ($rc === 0) return;
    }
    if (function_exists('system')) {
        $rc = 1; ob_start(); @system($cmd, $rc); ob_end_clean();
        if ($rc === 0) return;
    }
    if (function_exists('passthru')) {
        $rc = 1; ob_start(); @passthru($cmd, $rc); ob_end_clean();
        if ($rc === 0) return;
    }

    throw new Exception('No hay un agente SYSTEM activo y PHP tiene bloqueada la creación de procesos. En este equipo la actualización automática sí funciona cuando el agente existente está ACTIVO; para una instalación desde cero Windows necesita un primer proceso elevado.');
}

// Tiempo transcurrido desde el primer intento que el agente observó.
// Un nuevo bloqueo de la misma IP/puerto/proceso no reinicia el contador.
function first_attempt_age($firstUnix, $nowUnix) {
    $firstUnix = (int)$firstUnix;
    if ($firstUnix <= 0) return 'Sin fecha';
    return 'Hace ' . max(0, (int)$nowUnix - $firstUnix) . ' s';
}

function confidence_text($score) {
    $score = (int)$score;
    if ($score >= 95) return 'Alta';
    if ($score >= 80) return 'Media';
    if ($score > 0) return 'Baja';
    return '';
}

function confidence_class($score) {
    $score = (int)$score;
    if ($score >= 95) return 'conf-high';
    if ($score >= 80) return 'conf-mid';
    return 'conf-low';
}

$err = '';
try {
    $ips = read_whitelist($whitelistFile);
    $ipsInbound = read_whitelist($inboundWhitelistFile);

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!isset($_POST['csrf']) || !is_string($_POST['csrf']) || !hash_equals($csrfToken, $_POST['csrf'])) {
            throw new Exception('Formulario caducado o no autorizado. Actualiza la página.');
        }
        $action = isset($_POST['action']) && is_string($_POST['action']) ? $_POST['action'] : '';
        $ip = isset($_POST['ip']) && is_string($_POST['ip']) ? trim($_POST['ip']) : '';

        if ($action === 'refresh_panel') {
            // Un clic en Actualizar no se limita a recargar HTML. Si el agente
            // esta vivo, esperamos brevemente a que publique un ciclo nuevo
            // (heartbeat o requests.json) y luego hacemos un GET con nonce.
            clearstatcache(true, $requestsFile);
            $beforeMtime = file_exists($requestsFile) ? (int)@filemtime($requestsFile) : 0;
            $beforeStatus = read_json_file($statusFile, array());
            $beforeHeartbeat = isset($beforeStatus['heartbeat_unix']) ? (int)$beforeStatus['heartbeat_unix'] : 0;
            $shouldWait = agent_status_is_alive_any($beforeStatus);
            if ($shouldWait) {
                $deadline = microtime(true) + 2.75;
                do {
                    usleep(100000);
                    clearstatcache(true, $requestsFile);
                    $mtime = file_exists($requestsFile) ? (int)@filemtime($requestsFile) : 0;
                    $probeStatus = read_json_file($statusFile, array());
                    $probeHeartbeat = isset($probeStatus['heartbeat_unix']) ? (int)$probeStatus['heartbeat_unix'] : 0;
                    if ($probeHeartbeat > $beforeHeartbeat || $mtime > $beforeMtime) break;
                } while (microtime(true) < $deadline);
            }
            redirect_fresh();
        }

        if ($action === 'install_ipwall') {
            $liveStatus = read_json_file($statusFile, array());
            $liveBroker = read_json_file($brokerStatusFile, array());
            if (broker_status_is_alive($liveBroker)) {
                queue_system_control_action($controlRequestFile, $systemWorkerScript, $whitelistFile, 'install', $controlStatusFile, false);
            } elseif (agent_status_is_alive_any($liveStatus)) {
                // Ruta de migración desde 4.0: el agente anterior ejecutará el
                // apply-whitelist.ps1 nuevo como SYSTEM y arrancará el worker.
                queue_system_control_action($controlRequestFile, $systemWorkerScript, $whitelistFile, 'install', $controlStatusFile, true);
            } else {
                write_json_atomic($controlStatusFile, array(
                    'action' => 'install', 'state' => 'launching',
                    'message' => 'Iniciando instalación inicial...', 'updated_unix' => time()
                ));
                launch_control_action($controlScript, 'install', $dir, $controlStatusFile);
            }
            redirect_fresh();
        }

        if ($action === 'restore_firewall') {
            $liveStatus = read_json_file($statusFile, array());
            $liveBroker = read_json_file($brokerStatusFile, array());
            if (broker_status_is_alive($liveBroker)) {
                queue_system_control_action($controlRequestFile, $systemWorkerScript, $whitelistFile, 'restore', $controlStatusFile, false);
            } elseif (agent_status_is_alive_any($liveStatus)) {
                queue_system_control_action($controlRequestFile, $systemWorkerScript, $whitelistFile, 'restore', $controlStatusFile, true);
            } else {
                write_json_atomic($controlStatusFile, array(
                    'action' => 'restore', 'state' => 'launching',
                    'message' => 'Iniciando restauración de recuperación...', 'updated_unix' => time()
                ));
                launch_control_action($controlScript, 'restore', $dir, $controlStatusFile);
            }
            redirect_fresh();
        }

        if ($action === 'clear_requests') {
            // Solicitar al agente descartar los eventos WFP anteriores (no basta
            // con vaciar el JSON: el agente puede tener entradas en memoria).
            if (@file_put_contents($clearFlag, (string)time(), LOCK_EX) === false) {
                throw new Exception('No se pudo solicitar la limpieza al agente. Comprueba los permisos de la carpeta IPWall.');
            }
            if (@file_put_contents($requestsFile, '[]', LOCK_EX) === false) {
                throw new Exception('No se pudo vaciar requests.json. El agente intentará completar la limpieza.');
            }
            // Nunca modificar ninguna whitelist ni las reglas del firewall.
            redirect_fresh();
        }

        if ($action === 'add' || $action === 'allow') {
            $direction = requested_direction();
            $targetFile = $direction === 'inbound' ? $inboundWhitelistFile : $whitelistFile;
            $targetIps = $direction === 'inbound' ? $ipsInbound : $ips;
            $entry = ipwall_normalize_entry($ip);
            if ($action === 'allow' && !valid_ip($ip)) throw new Exception('Selecciona una IP individual válida.');
            if (!in_array($entry, $targetIps, true)) {
                $targetIps[] = $entry;
                write_whitelist($targetFile, $targetIps);
            }
            redirect_fresh();
        }

        if ($action === 'allow_block' || $action === 'allow_group') {
            $direction = requested_direction();
            $targetFile = $direction === 'inbound' ? $inboundWhitelistFile : $whitelistFile;
            $targetIps = $direction === 'inbound' ? $ipsInbound : $ips;
            // Los dos botones autorizan las redes OBSERVADAS del mismo grupo,
            // en el sentido elegido; no permiten redes arbitrarias enviadas por POST.
            $observed = file_exists($clearFlag) ? array() : array_values(array_filter(read_json_file($requestsFile, array()), 'browser_request_verified'));
            $groupsNow = ipwall_build_groups($observed, $ips, $ipsInbound);
            $candidateBlocks = array();
            if ($action === 'allow_group') {
                $key = isset($_POST['group']) && is_string($_POST['group']) ? $_POST['group'] : '';
                if (!isset($groupsNow[$key])) throw new Exception('Grupo no disponible. Actualiza la página.');
                $candidateBlocks = array_keys($groupsNow[$key]['blocks']);
            } else {
                $block = isset($_POST['block']) && is_string($_POST['block']) ? $_POST['block'] : '';
                foreach ($groupsNow as $g) {
                    if (isset($g['blocks'][$block])) { $candidateBlocks = array($block); break; }
                }
                if (!$candidateBlocks) throw new Exception('Bloque no observado. Actualiza la página.');
            }
            $added = 0;
            foreach ($candidateBlocks as $block) {
                if (ipwall_block_covered($block, $targetIps)) continue;
                if ($added >= 40) break; // Límite por clic y por dirección.
                $targetIps[] = ipwall_normalize_entry($block);
                $added++;
            }
            if ($added > 0) write_whitelist($targetFile, $targetIps);
            redirect_fresh();
        }

        if ($action === 'remove') {
            $direction = requested_direction();
            $targetFile = $direction === 'inbound' ? $inboundWhitelistFile : $whitelistFile;
            $targetIps = $direction === 'inbound' ? $ipsInbound : $ips;
            $entry = ipwall_normalize_entry($ip);
            $newIps = array();
            foreach ($targetIps as $current) {
                if ($current !== $entry) $newIps[] = $current;
            }
            write_whitelist($targetFile, $newIps);
            redirect_fresh();
        }
    }
} catch (Exception $e) {
    $err = $e->getMessage();
}

$ips = read_whitelist($whitelistFile);
$ipsInbound = read_whitelist($inboundWhitelistFile);
// Hasta que el agente procese la señal de limpieza, no enseñar datos
// posiblemente reescritos por su iteración anterior.
$requests = file_exists($clearFlag) ? array() : array_values(array_filter(read_json_file($requestsFile, array()), 'browser_request_verified'));
$groups = ipwall_build_groups($requests, $ips, $ipsInbound);
$nowUnix = time();
clearstatcache(true, $requestsFile);
$requestsMtime = file_exists($requestsFile) ? (int)@filemtime($requestsFile) : 0;
$requestsAge = $requestsMtime > 0 ? max(0, $nowUnix - $requestsMtime) : -1;
$panelReadAt = date('H:i:s', $nowUnix);
$status = read_json_file($statusFile, array());

usort($requests, function($a, $b) {
    $aa = isset($a['last_seen_unix']) ? (int)$a['last_seen_unix'] : 0;
    $bb = isset($b['last_seen_unix']) ? (int)$b['last_seen_unix'] : 0;
    if ($aa === $bb) return 0;
    return ($aa < $bb) ? 1 : -1;
});
$requests = array_slice($requests, 0, 500);

$heartbeat = isset($status['heartbeat_unix']) ? (int)$status['heartbeat_unix'] : 0;
$agentAlive = ($heartbeat > 0 && (time() - $heartbeat) <= 12);
$logExists = isset($status['firewall_log_exists']) ? (bool)$status['firewall_log_exists'] : false;
$dnsIntel = isset($status['dns_event_log_available']) ? (bool)$status['dns_event_log_available'] : false;
$wfpSecurity = isset($status['wfp_security_log_available']) ? (bool)$status['wfp_security_log_available'] : false;
$wfpConfigured = isset($status['wfp_audit_configured']) ? (bool)$status['wfp_audit_configured'] : false;
$browserEvents = isset($status['browser_events_since_start']) ? (int)$status['browser_events_since_start'] : 0;
$agentVersion = isset($status['agent_version']) ? (string)$status['agent_version'] : '';
$agentUpToDate = ($agentVersion === '4.6.1');
$brokerStatus = read_json_file($brokerStatusFile, array());
$brokerAlive = broker_status_is_alive($brokerStatus);
$brokerError = isset($brokerStatus['last_error']) ? (string)$brokerStatus['last_error'] : '';
$packetAuditConfigured = isset($status['wfp_packet_audit_configured']) ? (bool)$status['wfp_packet_audit_configured'] : false;
$wfpReadError = isset($status['wfp_read_error']) ? (string)$status['wfp_read_error'] : '';
$wfpLastParseError = isset($status['wfp_last_parse_error']) ? (string)$status['wfp_last_parse_error'] : '';
$wfpParseErrors = isset($status['wfp_parse_errors_last_cycle']) ? (int)$status['wfp_parse_errors_last_cycle'] : 0;
$appTracking = ($wfpSecurity && ($wfpConfigured || $packetAuditConfigured) && $agentUpToDate && $wfpReadError === '');
$agentRestored = isset($status['restored']) ? (bool)$status['restored'] : false;
$lastError = isset($status['last_error']) ? $status['last_error'] : '';
$strictHermetic = isset($status['strict_hermetic']) ? (bool)$status['strict_hermetic'] : false;
$strictProfilesOk = isset($status['strict_profiles_ok']) ? (bool)$status['strict_profiles_ok'] : false;
$strictInboundRules = isset($status['strict_block_rules_inbound']) ? (int)$status['strict_block_rules_inbound'] : 0;
$strictOutboundRules = isset($status['strict_block_rules_outbound']) ? (int)$status['strict_block_rules_outbound'] : 0;
$strictAllowBypassRules = isset($status['strict_allow_bypass_rules']) ? (int)$status['strict_allow_bypass_rules'] : 0;
$strictForeignLocalRules = isset($status['strict_foreign_local_rules']) ? (int)$status['strict_foreign_local_rules'] : 0;
$strictDisabledLastCycle = isset($status['strict_disabled_rules_last_cycle']) ? (int)$status['strict_disabled_rules_last_cycle'] : 0;
$strictError = isset($status['strict_error']) ? (string)$status['strict_error'] : '';
$controlStatus = read_json_file($controlStatusFile, array());
// Durante la migracion 4.0-4.3 -> 4.4 el worker antiguo puede escribir el
// resultado final en la ruta legacy justo antes de arrancar el runtime nuevo.
// Mostrar siempre el estado de control mas reciente de ambos lugares.
$runtimeControlProbe = read_json_file($runtimeControlStatusFile, array());
$legacyControlProbe = read_json_file($legacyControlStatusFile, array());
$runtimeControlTs = isset($runtimeControlProbe['updated_unix']) ? (int)$runtimeControlProbe['updated_unix'] : 0;
$legacyControlTs = isset($legacyControlProbe['updated_unix']) ? (int)$legacyControlProbe['updated_unix'] : 0;
if ($runtimeControlTs > 0 || $legacyControlTs > 0) {
    $controlStatus = ($legacyControlTs > $runtimeControlTs) ? $legacyControlProbe : $runtimeControlProbe;
}
$controlState = isset($controlStatus['state']) ? (string)$controlStatus['state'] : '';
$controlAction = isset($controlStatus['action']) ? (string)$controlStatus['action'] : '';
$controlMessage = isset($controlStatus['message']) ? (string)$controlStatus['message'] : '';
$controlUpdated = isset($controlStatus['updated_unix']) ? (int)$controlStatus['updated_unix'] : 0;
$controlClass = $controlState === 'success' ? 'green' : ($controlState === 'error' ? 'red' : 'yellow');
?>
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, max-age=0">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="0">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IPWall</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f4f6f8;color:#172033;font-family:Arial,sans-serif}.wrap{max-width:1540px;margin:25px auto;padding:0 18px}
h1{margin:0 0 8px;font-size:34px}.sub{margin-bottom:17px;color:#64748b}.pill{display:inline-block;padding:7px 11px;border-radius:20px;font-weight:bold;margin-right:8px}.red{background:#fee2e2;color:#b91c1c}.green{background:#dcfce7;color:#166534}.yellow{background:#fef3c7;color:#92400e}
.grid{display:grid;grid-template-columns:minmax(0,3fr) minmax(280px,1fr);gap:18px}.card{overflow-x:auto;background:white;border:1px solid #dbe1e8;border-radius:13px;padding:18px;margin-bottom:18px;box-shadow:0 2px 8px rgba(0,0,0,.03)}
h2{margin:0 0 13px}.small{font-size:12px;color:#64748b}.error{background:#fee2e2;color:#991b1b;padding:10px;border-radius:8px;margin-bottom:12px}table{width:100%;border-collapse:collapse}th,td{padding:9px 7px;border-bottom:1px solid #e5e7eb;text-align:left;vertical-align:middle}th{font-size:11px;color:#64748b;text-transform:uppercase}
code{background:#f1f5f9;padding:2px 5px;border-radius:5px;font-family:Consolas,monospace}button{border:0;border-radius:7px;padding:8px 10px;font-weight:bold;cursor:pointer}.allow{background:#16a34a;color:white}.remove{background:#e5e7eb}.add{background:#2563eb;color:white}.clear{background:#dc2626;color:white}
.row{display:flex;gap:8px}.row input{flex:1}.row input,input[type=text],.row select{padding:10px;border:1px solid #cbd5e1;border-radius:7px;background:white}.headrow{display:flex;justify-content:space-between;align-items:center;gap:12px}.domain{font-weight:bold;word-break:break-word}.ptr{font-family:Consolas,monospace;font-size:12px;word-break:break-all}.muted{color:#94a3b8}.allowed{font-weight:bold;color:#15803d}.diag{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 20px}
.badge{display:inline-block;font-size:10px;font-weight:bold;border-radius:999px;padding:3px 7px;margin:4px 4px 0 0;background:#e2e8f0;color:#334155}.conf-high{background:#dcfce7;color:#166534}.conf-mid{background:#fef3c7;color:#92400e}.conf-low{background:#f1f5f9;color:#64748b}.candidates{margin-top:5px}.candidates summary{cursor:pointer;color:#475569;font-size:11px}.candidate-list{margin:5px 0 0;padding-left:17px;font-size:11px;color:#64748b}.provider{margin-top:4px;font-size:11px;color:#475569;font-weight:bold}.appname{font-weight:bold;white-space:nowrap}.appmeta{margin-top:4px;font-size:11px;color:#475569}.apppath{font-family:Consolas,monospace;font-size:10px;word-break:break-all;color:#64748b}.appcell{min-width:180px}.blocklist{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}.blockitem{display:inline-block;border:1px solid #e2e8f0;border-radius:7px;padding:5px 8px;font-size:12px}.note{background:#fff7ed;color:#9a3412;border:1px solid #fed7aa;padding:10px;border-radius:7px}.group-details{max-width:560px}.group-details summary{cursor:pointer;color:#334155;font-size:12px}.actionline{display:flex;gap:6px;flex-wrap:wrap}.actionline form{display:inline-block}.stacked-actions{display:flex;flex-direction:column;gap:5px;align-items:stretch}.stacked-actions form{margin:0}.stacked-actions button{width:100%;padding:7px 8px;font-size:11px;line-height:1.25}.stacked-actions .allowed{font-size:11px}.detailtable{width:100%}.detailpanel summary{cursor:pointer;font-weight:bold;font-size:17px;padding:3px}.counts{white-space:nowrap}.topbar{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap;margin-bottom:16px}.topbar .sub{margin-bottom:0}.topbar form{margin:3px 0 0}.topbar .clear{padding:11px 16px;font-size:14px}.topactions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.refreshbtn{background:#0f766e;color:white;padding:11px 16px;font-size:14px}.refreshbtn[disabled]{opacity:.65;cursor:wait}.freshness{font-size:12px;color:#475569;font-weight:bold}.age{font-weight:bold;white-space:nowrap}.controlbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.controlbar form{margin:0}.installbtn{background:#2563eb;color:#fff;padding:11px 16px}.restorebtn{background:#7c3aed;color:#fff;padding:11px 16px}.controlstatus{margin-top:10px}.controlnote{margin-top:8px;font-size:12px;color:#64748b}
@media(max-width:980px){.grid{grid-template-columns:1fr}.card{overflow-x:auto}}
</style>
<script>
window.addEventListener('DOMContentLoaded', function () {
    var scrollKey = 'ipwall-autorizacion-' + location.pathname;

    function collectViewState() {
        var openGroups = [];
        var expanded = document.querySelectorAll('details[data-keep-open][open]');
        for (var j = 0; j < expanded.length; j++) openGroups.push(expanded[j].getAttribute('data-keep-open'));
        return {
            y: window.scrollY || window.pageYOffset || 0,
            detailOpen: !!document.querySelector('details.detailpanel[open]'),
            groupsOpen: openGroups
        };
    }

    function saveViewState() {
        try { sessionStorage.setItem(scrollKey, JSON.stringify(collectViewState())); } catch (e) {}
    }

    // Restaurar posicion y paneles abiertos despues de una recarga real.
    var saved = null;
    try {
        var raw = sessionStorage.getItem(scrollKey);
        if (raw) {
            sessionStorage.removeItem(scrollKey);
            saved = JSON.parse(raw);
        }
    } catch (e) {}
    if (saved) {
        var detail = document.querySelector('details.detailpanel');
        if (detail && saved.detailOpen) detail.open = true;
        var groupDetails = document.querySelectorAll('details[data-keep-open]');
        var openIds = Array.isArray(saved.groupsOpen) ? saved.groupsOpen : [];
        for (var gi = 0; gi < groupDetails.length; gi++) {
            if (openIds.indexOf(groupDetails[gi].getAttribute('data-keep-open')) !== -1) groupDetails[gi].open = true;
        }
        var y = Math.max(0, Number(saved.y) || 0);
        window.requestAnimationFrame(function () { window.scrollTo(0, y); });
    }

    // Conservar la vista al permitir/quitar/agregar y tambien en la recarga automatica.
    var forms = document.querySelectorAll('form');
    for (var fi = 0; fi < forms.length; fi++) {
        var input = forms[fi].querySelector('input[name="action"]');
        if (!input || !/^(allow|allow_block|allow_group|add|remove)$/.test(input.value)) continue;
        forms[fi].addEventListener('submit', saveViewState);
    }

    function updateElapsed() {
        var now = Math.floor(Date.now() / 1000);
        var cells = document.querySelectorAll('[data-first-unix]');
        for (var i = 0; i < cells.length; i++) {
            var first = parseInt(cells[i].getAttribute('data-first-unix'), 10);
            if (first > 0) cells[i].textContent = 'Hace ' + Math.max(0, now - first) + ' s';
        }
    }
    updateElapsed();
    window.setInterval(updateElapsed, 1000);

    function cacheBustedUrl() {
        var base = location.pathname || './';
        return base + '?_refresh=' + Date.now() + '-' + Math.random().toString(36).slice(2);
    }

    function navigateFresh() {
        saveViewState();
        // replace evita llenar el historial; el nonce impide reutilizar cualquier respuesta previa.
        location.replace(cacheBustedUrl());
    }

    // Autorrecarga continua. Antes solo se intentaba una vez y un <details> abierto
    // podia dejar el panel congelado para siempre. Ahora se reintenta cada 3 s.
    window.setInterval(function () {
        if (document.hidden) return;
        var active = document.activeElement;
        if (active && /^(INPUT|SELECT|TEXTAREA|BUTTON)$/.test(active.tagName)) return;
        navigateFresh();
    }, 3000);

    // Si la pagina vuelve desde bfcache, forzar una lectura nueva.
    window.addEventListener('pageshow', function (ev) {
        if (ev.persisted) navigateFresh();
    });

    var refreshForm = document.getElementById('refreshPanelForm');
    var refreshButton = document.getElementById('refreshPanelButton');
    if (refreshForm) {
        refreshForm.addEventListener('submit', function () {
            saveViewState();
            if (refreshButton) {
                refreshButton.disabled = true;
                refreshButton.textContent = 'Actualizando...';
            }
        });
    }
});
</script>
</head>
<body>
<div class="wrap">
<div class="topbar">
    <div>
        <h1>IPWall <span class="small">v4.6.1 · modo hermético allowlist-only · runtime estable</span></h1>
        <div class="sub"><span class="pill red">POLÍTICA HERMÉTICA: TODO BLOQUEADO SALVO WHITELIST</span> Bloqueo explícito del complemento IPv4/IPv6 en entrada y salida; no hay bypass DNS oculto.</div>
    </div>
    <div class="topactions">
        <form method="post" id="refreshPanelForm">
            <input type="hidden" name="csrf" value="<?php echo h($csrfToken); ?>">
            <input type="hidden" name="action" value="refresh_panel">
            <button class="refreshbtn" id="refreshPanelButton" type="submit">Actualizar</button>
        </form>
        <form method="post" onsubmit="return confirm('¿Limpiar las solicitudes e IP detectadas del panel? No se borrarán los permisos de entrada ni los de salida.');">
            <input type="hidden" name="csrf" value="<?php echo h($csrfToken); ?>">
            <input type="hidden" name="action" value="clear_requests">
            <button class="clear" type="submit">Limpiar datos</button>
        </form>
    </div>
</div>

<div class="card">
    <h2>Instalación / restauración</h2>
    <div class="controlbar">
        <form method="post">
            <input type="hidden" name="csrf" value="<?php echo h($csrfToken); ?>">
            <input type="hidden" name="action" value="install_ipwall">
            <button class="installbtn" type="submit">Instalar IPWall</button>
        </form>
        <form method="post">
            <input type="hidden" name="csrf" value="<?php echo h($csrfToken); ?>">
            <input type="hidden" name="action" value="restore_firewall">
            <button class="restorebtn" type="submit">Restaurar firewall</button>
        </form>
        <?php if ($controlState !== ''): ?>
            <span class="pill <?php echo h($controlClass); ?>"><?php echo h(strtoupper($controlState)); ?></span>
        <?php endif; ?>
    </div>
    <?php if ($controlMessage !== ''): ?><div class="controlstatus"><b><?php echo $controlAction === 'restore' ? 'Restauración' : 'Instalación'; ?>:</b> <?php echo h($controlMessage); ?></div><?php endif; ?>
    <div class="controlnote">Desde v4.4 los JSON, heartbeats y temporales se guardan dentro de <code>runtime\</code>; v4.6.1 preserva y recupera datos legacy durante actualizaciones fallidas, por lo que la carpeta principal deja de cambiar cada segundo mientras editas scripts o whitelists. El broker SYSTEM permanece activo incluso después de Restaurar firewall y los botones siguen funcionando sin exec/popen de PHP.</div>
</div>

<div class="diag">
    <span class="pill <?php echo $agentAlive ? 'green' : ($agentRestored ? 'yellow' : 'red'); ?>">Agente: <?php echo $agentAlive ? 'ACTIVO' : ($agentRestored ? 'RESTAURADO / INACTIVO' : 'NO RESPONDE'); ?></span>
    <span class="pill <?php echo ($agentAlive && $strictHermetic) ? 'green' : 'red'; ?>">Modo hermético: <?php echo ($agentAlive && $strictHermetic) ? 'ACTIVO' : 'NO CONFIRMADO'; ?></span>
    <span class="pill <?php echo $brokerAlive ? 'green' : 'yellow'; ?>">Control SYSTEM: <?php echo $brokerAlive ? 'ACTIVO' : 'NO DISPONIBLE'; ?></span>
    <span class="pill <?php echo $logExists ? 'green' : 'red'; ?>">Firewall log: <?php echo $logExists ? 'OK' : 'NO DISPONIBLE'; ?></span>
    <span class="pill <?php echo $dnsIntel ? 'green' : 'yellow'; ?>">DNS inteligente: <?php echo $dnsIntel ? 'ACTIVO' : 'LIMITADO'; ?></span>
    <span class="pill <?php echo $appTracking ? 'green' : 'yellow'; ?>">Detección navegador: <?php echo $appTracking ? 'ACTIVA' : 'NO DISPONIBLE'; ?></span>
    <span class="pill yellow">Intentos capturados (desde inicio): <?php echo $browserEvents; ?> · Destinos en lista: <?php echo count($requests); ?></span>
    <span class="pill yellow freshness">Lectura nueva: <?php echo h($panelReadAt); ?> · requests.json: <?php echo $requestsAge >= 0 ? ('hace ' . (int)$requestsAge . ' s') : 'sin fecha'; ?></span>
</div>
<div class="note"><b>DNS en modo hermético:</b> IPWall no crea excepciones DNS especiales. Si el resolvedor DNS de Windows no está incluido en la whitelist saliente, las consultas DNS quedarán bloqueadas igual que cualquier otro destino.</div>

<?php if ($err !== ''): ?><div class="error"><?php echo h($err); ?></div><?php endif; ?>
<?php if (file_exists($clearFlag)): ?><p class="small">Limpieza solicitada: el agente está descartando las solicitudes anteriores. Ambas listas de permisos permanecen intactas.</p><?php endif; ?>
<?php if ($lastError !== ''): ?><div class="error"><b>Error del agente:</b> <?php echo h($lastError); ?></div><?php endif; ?>
<?php if ($brokerError !== ''): ?><div class="error"><b>Error del control SYSTEM:</b> <?php echo h($brokerError); ?></div><?php endif; ?>
<?php if ($wfpReadError !== ''): ?><div class="error"><b>Error leyendo Security:</b> <?php echo h($wfpReadError); ?></div><?php endif; ?>
<?php if ($wfpParseErrors > 0): ?><div class="error"><b>Errores al interpretar eventos WFP:</b> <?php echo (int)$wfpParseErrors; ?>. <?php echo h($wfpLastParseError); ?></div><?php endif; ?>
<?php if ($agentAlive && !$agentUpToDate): ?><div class="error"><b>Agente anterior detectado:</b> el panel necesita el agente 4.6.1. Pulsa <b>Instalar IPWall</b>; el propio agente SYSTEM existente hará la actualización aunque PHP tenga exec/popen deshabilitados.</div><?php endif; ?>
<?php if ($agentAlive && $agentUpToDate && !$strictHermetic): ?><div class="error"><b>ALERTA: el modo hermético no está confirmado.</b> Perfiles: <?php echo $strictProfilesOk ? 'OK' : 'ERROR'; ?> · bloqueos estrictos entrada: <?php echo (int)$strictInboundRules; ?> · salida: <?php echo (int)$strictOutboundRules; ?> · Allow-Bypass externos: <?php echo (int)$strictAllowBypassRules; ?> · reglas locales ajenas aún activas: <?php echo (int)$strictForeignLocalRules; ?>. <?php if ($strictError !== ''): ?><?php echo h($strictError); ?><?php endif; ?></div><?php endif; ?>
<?php if ($agentAlive && $strictHermetic): ?><div class="controlstatus"><b>Verificación estricta:</b> perfiles Domain/Private/Public en Block, complemento IPv4/IPv6 protegido por reglas Block explícitas y reglas locales ajenas deshabilitadas. <?php if ($strictDisabledLastCycle > 0): ?>En el último ciclo se cerraron <?php echo (int)$strictDisabledLastCycle; ?> regla(s) local(es) ajena(s).<?php endif; ?></div><?php endif; ?>

<div class="grid">
<div>
<div class="card">
<h2>Aprobar bloques por servicio</h2>
<p class="small">Redes detectadas en intentos bloqueados del navegador, tanto entrantes como salientes: <b>/24 en IPv4</b> y <b>/120 en IPv6</b>. Los servicios se infieren usando DNS, pero la identidad puede ser incierta. Cada botón autoriza el mismo conjunto de redes observadas, <b>solo</b> en la dirección indicada.</p>
<p class="note"><b>Atención:</b> permitir un CIDR autoriza todas sus IP, incluso las de servicios ajenos. <b>Una red entrante permitida puede conectarse a puertos locales accesibles</b>; no se restringe solo al navegador o a una web. Los botones no descubren automáticamente todas las IP de un servicio.</p>
<?php if (count($groups) === 0): ?>
<p class="muted">Todavía no hay redes detectadas. Abre una página desde tu navegador para generar solicitudes.</p>
<?php else: ?>
<table><thead><tr><th>Servicio / dominio probable</th><th>Redes observadas</th><th>IP vistas</th><th>Se inició hace</th><th>Estado</th><th>Acción</th></tr></thead><tbody>
<?php foreach ($groups as $g):
    $blockCount = count($g['blocks']);
    $inAllowed = $blockCount - $g['remaining_inbound'];
    $outAllowed = $blockCount - $g['remaining_outbound'];
    $labelIn = $g['remaining_inbound'] > 40 ? 'Permitir 40 bloques entrantes' : 'Permitir todos los bloques entrantes';
    $labelOut = $g['remaining_outbound'] > 40 ? 'Permitir 40 bloques salientes' : 'Permitir todos los bloques salientes';
?>
<tr>
<td><div class="domain"><?php echo h($g['label']); ?></div><div class="small"><?php echo h($g['kind']); ?></div>
<?php if (count($g['domains']) > 0): ?><details class="group-details" data-keep-open="<?php echo h($g['key']); ?>:hosts"><summary><?php echo count($g['domains']); ?> hostname(s) observados</summary><div class="small"><?php echo h(implode(', ', array_keys($g['domains']))); ?></div></details><?php endif; ?>
</td>
<td><strong><?php echo $blockCount; ?></strong><details class="group-details" data-keep-open="<?php echo h($g['key']); ?>:blocks"><summary>Ver bloques y dar acceso individual</summary>
<div class="blocklist"><?php foreach ($g['blocks'] as $cidr => $info): ?><div class="blockitem"><code><?php echo h($cidr); ?></code><div class="small"><?php echo count($info['ips']); ?> IP observada(s)</div>
<div class="stacked-actions">
<?php foreach (array('inbound' => 'entrante', 'outbound' => 'saliente') as $direction => $word): ?>
<?php if ($info['allowed_' . $direction]): ?><span class="allowed">Red <?php echo h($word); ?> permitida</span>
<?php else: ?><form method="post"><input type="hidden" name="csrf" value="<?php echo h($csrfToken); ?>"><input type="hidden" name="action" value="allow_block"><input type="hidden" name="direction" value="<?php echo h($direction); ?>"><input type="hidden" name="block" value="<?php echo h($cidr); ?>"><button class="allow" type="submit">Permitir red <?php echo h($word); ?></button></form><?php endif; ?>
<?php endforeach; ?>
</div></div><?php endforeach; ?></div>
</details></td>
<td class="counts"><?php echo count($g['ips']); ?></td>
<td class="counts"><?php if ($g['first_seen_unix'] > 0): ?><time class="age" data-first-unix="<?php echo (int)$g['first_seen_unix']; ?>"><?php echo first_attempt_age($g['first_seen_unix'], $nowUnix); ?></time><?php else: ?><span class="muted">Sin fecha</span><?php endif; ?><div class="small">Primer intento del grupo</div></td>
<td class="counts"><div class="small">Entradas: <?php echo $inAllowed; ?> / <?php echo $blockCount; ?></div><div class="small">Salidas: <?php echo $outAllowed; ?> / <?php echo $blockCount; ?></div></td>
<td><div class="stacked-actions">
<?php if ($g['remaining_inbound'] === 0): ?><span class="allowed">Entrantes permitidos</span>
<?php else: ?><form method="post"><input type="hidden" name="csrf" value="<?php echo h($csrfToken); ?>"><input type="hidden" name="action" value="allow_group"><input type="hidden" name="direction" value="inbound"><input type="hidden" name="group" value="<?php echo h($g['key']); ?>"><button class="allow" type="submit" title="Autoriza hasta 40 redes entrantes observadas; puede incluir otras aplicaciones e IP ajenas"><?php echo h($labelIn); ?></button></form><?php endif; ?>
<?php if ($g['remaining_outbound'] === 0): ?><span class="allowed">Salientes permitidos</span>
<?php else: ?><form method="post"><input type="hidden" name="csrf" value="<?php echo h($csrfToken); ?>"><input type="hidden" name="action" value="allow_group"><input type="hidden" name="direction" value="outbound"><input type="hidden" name="group" value="<?php echo h($g['key']); ?>"><button class="allow" type="submit" title="Autoriza hasta 40 redes salientes observadas; puede incluir otras aplicaciones e IP ajenas"><?php echo h($labelOut); ?></button></form><?php endif; ?>
</div></td>
</tr>
<?php endforeach; ?>
</tbody></table>
<?php endif; ?>
</div>
<div class="card">
<details class="detailpanel"><summary>Ver IP individuales y detalles (<?php echo count($requests); ?>)</summary>
<h2>IP bloqueadas detectadas en navegadores</h2>
<p class="small">Solo se muestran bloqueos WFP entrantes o salientes atribuidos directamente a ejecutables de navegadores. Para entradas se identifica la <b>IP remota de origen</b>; para salidas, la <b>IP remota de destino</b>. Otros procesos no se muestran. Las respuestas a conexiones establecidas se gestionan de forma automática por el firewall de Windows.</p>
<?php if (!$appTracking): ?><div class="error">Captura WFP no lista: comprueba que el agente esté actualizado y las auditorías 5152/5157 estén activadas. Ejecuta <code>upgrade.ps1</code> como administrador y revisa <code>diagnose.ps1</code>.</div><?php endif; ?>

<?php if (count($requests) === 0): ?>
<p class="muted">Aún no se han registrado bloqueos de navegador. Abre una web externa nueva desde Brave, Chrome o Firefox. Si continúa vacío, ejecuta <code>diagnose.ps1</code> como administrador.</p>
<?php else: ?>
<table>
<thead><tr><th>Identificación probable</th><th>Navegador de origen</th><th>IP remota</th><th>Reverse DNS / red</th><th>Puerto</th><th>Protocolo</th><th>Intentos</th><th>Se inició hace</th><th>Último intento</th><th></th></tr></thead>
<tbody>
<?php foreach ($requests as $r):
    $ip = isset($r['ip']) ? $r['ip'] : '';
    $domain = isset($r['domain']) ? $r['domain'] : '';
    $source = isset($r['domain_source']) ? $r['domain_source'] : '';
    $confidence = isset($r['domain_confidence']) ? (int)$r['domain_confidence'] : 0;
    $candidates = (isset($r['domain_candidates']) && is_array($r['domain_candidates'])) ? $r['domain_candidates'] : array();
    $reverseDns = isset($r['reverse_dns']) ? $r['reverse_dns'] : '';
    $provider = isset($r['provider_hint']) ? $r['provider_hint'] : '';
    $application = isset($r['application']) ? $r['application'] : '';
    $applicationExe = isset($r['application_exe']) ? $r['application_exe'] : '';
    $applicationPath = isset($r['application_path']) ? $r['application_path'] : '';
    $processId = isset($r['process_id']) ? (int)$r['process_id'] : 0;
    $applicationSource = isset($r['application_source']) ? $r['application_source'] : '';
    $applicationConfidence = isset($r['application_confidence']) ? (int)$r['application_confidence'] : 0;
    $applicationCandidates = (isset($r['application_candidates']) && is_array($r['application_candidates'])) ? $r['application_candidates'] : array();
    $port = isset($r['port']) ? $r['port'] : '';
    $proto = isset($r['protocol']) ? $r['protocol'] : '';
    $count = isset($r['count']) ? (int)$r['count'] : 1;
    $last = isset($r['last_seen']) ? $r['last_seen'] : '';
    $firstUnix = isset($r['first_seen_unix']) ? (int)$r['first_seen_unix'] : 0;
    $requestedDirection = isset($r['direction']) && $r['direction'] === 'Inbound' ? 'inbound' : 'outbound';
    $directionDescription = $requestedDirection === 'inbound' ? 'Entrada' : 'Salida';
    $directionWord = $requestedDirection === 'inbound' ? 'entrante' : 'saliente';
    $activeIps = $requestedDirection === 'inbound' ? $ipsInbound : $ips;
    $isAllowed = ipwall_ip_allowed($ip, $activeIps);
    $block = ipwall_observed_block($ip);
    $blockCovered = ipwall_block_covered($block, $activeIps);
    $display = $domain !== '' ? $domain : $reverseDns;
    $displaySource = $domain !== '' ? $source : ($reverseDns !== '' ? 'PTR (inferido)' : '');
    $displayConfidence = $domain !== '' ? $confidence : ($reverseDns !== '' ? 35 : 0);
?>
<tr>
<td>
<?php if ($display !== ''): ?>
    <div class="domain"><?php echo h($display); ?></div>
    <?php if ($displaySource !== ''): ?><span class="badge"><?php echo h($displaySource); ?></span><?php endif; ?>
    <?php if ($displayConfidence > 0): ?><span class="badge <?php echo confidence_class($displayConfidence); ?>">Confianza <?php echo h(confidence_text($displayConfidence)); ?> · <?php echo (int)$displayConfidence; ?>%</span><?php endif; ?>
    <?php if ($domain === '' && $reverseDns !== ''): ?><div class="small">Hostname de infraestructura; el dominio solicitado no pudo confirmarse.</div><?php endif; ?>
    <?php if (count($candidates) > 1): ?>
    <details class="candidates"><summary><?php echo count($candidates); ?> dominios candidatos</summary><ul class="candidate-list">
        <?php foreach ($candidates as $candidate): ?><li><?php echo h($candidate); ?></li><?php endforeach; ?>
    </ul></details>
    <?php endif; ?>
<?php else: ?>
    <span class="muted">No identificado</span><div class="small">Sin señal DNS/PTR suficiente.</div>
<?php endif; ?>
</td>
<td class="appcell">
<?php if ($application !== ''): ?>
    <div class="appname"><?php echo h($application); ?></div>
    <div class="appmeta">
        <?php if ($applicationExe !== ''): ?><code><?php echo h($applicationExe); ?></code><?php endif; ?>
        <?php if ($processId > 0): ?> · PID <?php echo (int)$processId; ?><?php endif; ?>
    </div>
    <?php if ($applicationSource !== ''): ?><span class="badge"><?php echo h($applicationSource); ?></span><?php endif; ?>
    <?php if ($applicationConfidence > 0): ?><span class="badge <?php echo confidence_class($applicationConfidence); ?>">Confianza <?php echo h(confidence_text($applicationConfidence)); ?> · <?php echo (int)$applicationConfidence; ?>%</span><?php endif; ?>
    <?php if ($applicationPath !== ''): ?><details class="candidates"><summary>Ruta del proceso</summary><div class="apppath"><?php echo h($applicationPath); ?></div></details><?php endif; ?>
    <?php if (count($applicationCandidates) > 1): ?>
        <details class="candidates"><summary><?php echo count($applicationCandidates); ?> apps recientes</summary><ul class="candidate-list">
        <?php foreach ($applicationCandidates as $appCandidate): ?><li><?php echo h($appCandidate); ?></li><?php endforeach; ?>
        </ul></details>
    <?php endif; ?>
<?php else: ?>
    <span class="muted">No atribuido</span><div class="small">Sin evento WFP 5152/5157 atribuible.</div>
<?php endif; ?>
</td>
<td><code><?php echo h($ip); ?></code><div class="small">Tráfico: <b><?php echo h($directionDescription); ?></b></div><div class="small">Bloque <code><?php echo h($block); ?></code></div></td>
<td>
    <?php echo $reverseDns !== '' ? '<span class="ptr">'.h($reverseDns).'</span>' : '<span class="muted">Sin PTR</span>'; ?>
    <?php if ($provider !== ''): ?><div class="provider"><?php echo h($provider); ?></div><?php endif; ?>
</td>
<td><?php echo h($port); ?></td>
<td><?php echo h($proto); ?></td>
<td><?php echo $count; ?></td>
<td class="counts"><?php if ($firstUnix > 0): ?><time class="age" data-first-unix="<?php echo $firstUnix; ?>"><?php echo first_attempt_age($firstUnix, $nowUnix); ?></time><?php else: ?><span class="muted">Sin fecha</span><?php endif; ?></td>
<td class="small"><?php echo h($last); ?></td>
<td>
<?php if ($isAllowed): ?><span class="allowed">IP <?php echo h($directionWord); ?> permitida</span><?php endif; ?>
<div class="actionline">
<?php if (!$blockCovered): ?><form method="post"><input type="hidden" name="csrf" value="<?php echo h($csrfToken); ?>"><input type="hidden" name="action" value="allow_block"><input type="hidden" name="direction" value="<?php echo h($requestedDirection); ?>"><input type="hidden" name="block" value="<?php echo h($block); ?>"><button class="allow" type="submit">Permitir bloque <?php echo h($directionWord); ?></button></form><?php endif; ?>
<?php if (!$isAllowed): ?><form method="post"><input type="hidden" name="csrf" value="<?php echo h($csrfToken); ?>"><input type="hidden" name="action" value="allow"><input type="hidden" name="direction" value="<?php echo h($requestedDirection); ?>"><input type="hidden" name="ip" value="<?php echo h($ip); ?>"><button class="remove" type="submit">Permitir IP <?php echo h($directionWord); ?></button></form><?php endif; ?>
</div>
</td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
<?php endif; ?>
</details>
</div>
</div>

<div>
<div class="card">
<h2>Agregar IP o bloque CIDR</h2>
<form method="post"><input type="hidden" name="csrf" value="<?php echo h($csrfToken); ?>"><input type="hidden" name="action" value="add"><div class="row"><input type="text" name="ip" placeholder="142.250.10.0/24" required><select name="direction" aria-label="Dirección de tráfico"><option value="outbound">Saliente</option><option value="inbound">Entrante</option></select><button class="add" type="submit">Agregar</button></div></form>
<p class="small">Ejemplo IPv4: <code>142.250.10.0/24</code> (256 IP). IPv6: <code>2001:db8::/120</code> (256 IP). También acepta IP individuales. Límites: IPv4 /16–/32; IPv6 /64–/128.</p>
</div>

<div class="card">
<h2>Cómo interpreta el origen</h2>
<p class="small"><b>Origen del navegador</b>: cada IP proviene de un evento bloqueado WFP 5152 o 5157 con ejecutable de navegador. No se deduce la aplicación por coincidencias de IP, puerto o tiempo.</p>
<p class="small"><b>Límite</b>: Windows identifica el proceso, pero no la pestaña. Algunas conexiones en segundo plano iniciadas por el propio navegador también pueden aparecer; se excluyen las iniciadas por Windows y otras aplicaciones.</p>
<p class="small"><b>DNS reciente</b>: nombre consultado por Windows que resolvió a esa IP.</p>
<p class="small"><b>CNAME</b>: sigue alias de CDN para recuperar el dominio original.</p>
<p class="small"><b>PTR</b>: identifica infraestructura, pero <b>no</b> basta para asignar un bloque a YouTube o Facebook.</p>
<p class="small"><b>Redes CIDR</b>: agrupación práctica de direcciones, no una lista oficial de IP exclusivas de cada empresa.</p>
</div>

<div class="card">
<h2>Whitelist actual: IP y bloques</h2>
<?php if (count($ips) + count($ipsInbound) === 0): ?><p class="muted">Sin permisos de entrada ni de salida añadidos por IPWall.</p>
<?php else: ?><table><tbody>
<?php foreach (array('inbound' => $ipsInbound, 'outbound' => $ips) as $direction => $entries): ?>
<?php foreach ($entries as $allowedIp): ?><tr><td><code><?php echo h($allowedIp); ?></code><div class="small"><?php echo $direction === 'inbound' ? 'Entrante' : 'Saliente'; ?></div></td><td><form method="post"><input type="hidden" name="csrf" value="<?php echo h($csrfToken); ?>"><input type="hidden" name="action" value="remove"><input type="hidden" name="direction" value="<?php echo h($direction); ?>"><input type="hidden" name="ip" value="<?php echo h($allowedIp); ?>"><button class="remove">Quitar</button></form></td></tr><?php endforeach; ?>
<?php endforeach; ?>
</tbody></table><?php endif; ?>
</div>
</div>
</div>
</div>
</body></html>
