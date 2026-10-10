<?php
/* IPWall v4.6.1 - utilidades CIDR y agrupacion. Compatible con PHP 5.6+. */

function ipwall_valid_ip($value) {
    return is_string($value) && filter_var($value, FILTER_VALIDATE_IP) !== false;
}

function ipwall_mask_bytes($bytes, $prefix) {
    $length = strlen($bytes);
    $masked = '';
    for ($i = 0; $i < $length; $i++) {
        $bits = $prefix - $i * 8;
        if ($bits >= 8) {
            $masked .= $bytes[$i];
        } elseif ($bits <= 0) {
            $masked .= "\x00";
        } else {
            $mask = (255 << (8 - $bits)) & 255;
            $masked .= chr(ord($bytes[$i]) & $mask);
        }
    }
    return $masked;
}

/* Acepta IP simples o redes CIDR, siempre canonicas y con limites prudentes.
   Minimos: IPv4 /16, IPv6 /64. No admite redes /0 ni entradas ambiguas. */
function ipwall_parse_entry($raw) {
    $raw = trim((string)$raw);
    if ($raw === '' || substr_count($raw, '/') > 1) {
        throw new Exception('Introduce una IP o una red CIDR válida.');
    }
    $parts = explode('/', $raw);
    $address = $parts[0];
    if (!ipwall_valid_ip($address)) {
        throw new Exception('IP inválida: ' . $address);
    }
    $packed = inet_pton($address);
    if ($packed === false) throw new Exception('IP inválida.');
    $bits = strlen($packed) * 8;
    $hasPrefix = count($parts) === 2;
    $prefix = $bits;
    if ($hasPrefix) {
        if ($parts[1] === '' || !ctype_digit($parts[1]) || strlen($parts[1]) > 3) {
            throw new Exception('Prefijo CIDR inválido. Usa /24 para IPv4 o /120 para IPv6.');
        }
        $prefix = (int)$parts[1];
        $minimum = ($bits === 32) ? 16 : 64;
        if ($prefix < $minimum || $prefix > $bits) {
            throw new Exception('Red demasiado amplia o prefijo inválido. Límites: IPv4 /16 a /32; IPv6 /64 a /128.');
        }
    }
    $baseBytes = ipwall_mask_bytes($packed, $prefix);
    $network = inet_ntop($baseBytes);
    if ($network === false) throw new Exception('No se pudo interpretar la dirección.');
    $canonical = ($prefix === $bits) ? $network : ($network . '/' . $prefix);
    return array(
        'canonical' => $canonical,
        'bytes' => $baseBytes,
        'prefix' => $prefix,
        'bits' => $bits
    );
}

function ipwall_normalize_entry($raw) {
    $parsed = ipwall_parse_entry($raw);
    return $parsed['canonical'];
}

function ipwall_entry_contains_ip($entry, $ip) {
    try {
        $a = ipwall_parse_entry($entry);
        $b = ipwall_parse_entry($ip);
        return ($a['bits'] === $b['bits'] &&
            ipwall_mask_bytes($b['bytes'], $a['prefix']) === $a['bytes']);
    } catch (Exception $e) {
        return false;
    }
}

function ipwall_ip_allowed($ip, $whitelist) {
    foreach ($whitelist as $entry) {
        if (ipwall_entry_contains_ip($entry, $ip)) return true;
    }
    return false;
}

/* La entrada existente debe cubrir TODA la red, no solo una IP observada. */
function ipwall_block_covered($block, $whitelist) {
    try {
        $b = ipwall_parse_entry($block);
        foreach ($whitelist as $entry) {
            $a = ipwall_parse_entry($entry);
            if ($a['bits'] === $b['bits'] && $a['prefix'] <= $b['prefix'] &&
                ipwall_mask_bytes($b['bytes'], $a['prefix']) === $a['bytes']) {
                return true;
            }
        }
    } catch (Exception $e) {
        return false;
    }
    return false;
}

/* Agrupacion moderada: /24 (IPv4) o /120 (IPv6, 256 direcciones).
   Una red contiene potencialmente IPs de OTROS sitios; nunca se infiere
   que TODO el rango pertenece al sitio que origino el evento WFP. */
function ipwall_observed_block($ip) {
    if (!ipwall_valid_ip((string)$ip)) return '';
    $bits = strlen(inet_pton($ip)) * 8;
    return ipwall_normalize_entry($ip . (($bits === 32) ? '/24' : '/120'));
}

function ipwall_domain_is($domain, $suffix) {
    return $domain === $suffix ||
        (strlen($domain) > strlen($suffix) && substr($domain, -(strlen($suffix) + 1)) === '.' . $suffix);
}

/* En dominios propios se agrupan subdominios en su dominio principal.
   Servicios de alojamiento/CDN compartidos se mantienen por hostname para
   evitar unir webs ajenas solo porque usan la misma infraestructura. */
function ipwall_groupable_domain($host) {
    $shared = array(
        'cloudfront.net', 'amazonaws.com', 'cloudflare.net', 'azureedge.net',
        'akamaized.net', 'akamai.net', 'akamaiedge.net', 'edgekey.net',
        'fastly.net', 'fastlylb.net', 'cdn77.org', 'jsdelivr.net', 'unpkg.com',
        'googleapis.com', 'storage.googleapis.com', 'googleusercontent.com',
        'gvt1.com', 'githubusercontent.com', 'github.io', 'blogspot.com',
        'wordpress.com', 'pages.dev', 'workers.dev', 'vercel.app', 'netlify.app',
        'appspot.com', 'firebaseapp.com', 'web.app', 'herokuapp.com',
        'onrender.com', 'azurewebsites.net', 'cloudapp.net'
    );
    foreach ($shared as $sharedSuffix) {
        if (ipwall_domain_is($host, $sharedSuffix)) return $host;
    }
    $labels = explode('.', $host);
    $n = count($labels);
    if ($n < 3) return $host;
    $two = $labels[$n-2] . '.' . $labels[$n-1];
    $compound = array(
        'co.uk','org.uk','ac.uk','gov.uk','com.au','net.au','org.au',
        'co.nz','com.pe','com.mx','com.ar','com.br','com.co','com.ve',
        'co.jp','ne.jp','co.kr','co.in','com.tr','com.sg','com.my',
        'com.hk','co.za','com.tw','com.cn','com.ua'
    );
    if (in_array($two, $compound, true)) {
        return ($n >= 3) ? ($labels[$n-3] . '.' . $two) : $host;
    }
    return $two;
}

function ipwall_group_identity($r, $block) {
    $domain = isset($r['domain']) ? strtolower(trim((string)$r['domain'], " \t\n\r\0\x0B.")) : '';
    $confidence = isset($r['domain_confidence']) ? (int)$r['domain_confidence'] : 0;
    $source = isset($r['domain_source']) ? (string)$r['domain_source'] : '';
    /* PTR e infraestructura compartida NO prueban que el sitio sea YouTube o Facebook. */
    $validSource = in_array($source, array('DNS reciente', 'Caché DNS', 'CNAME'), true);
    if ($confidence < 80 || !$validSource || $domain === '' ||
        strlen($domain) > 253 || preg_match('/[^a-z0-9._-]/', $domain) || strpos($domain, '.') === false) {
        return array('key' => 'unknown:' . $block, 'label' => 'Sin identificar · ' . $block, 'kind' => 'Bloque sin dominio fiable');
    }
    foreach (array('youtube.com', 'youtube-nocookie.com', 'youtu.be', 'googlevideo.com', 'ytimg.com') as $suffix) {
        if (ipwall_domain_is($domain, $suffix)) {
            return array('key' => 'service:youtube', 'label' => 'YouTube', 'kind' => 'Servicio probable por DNS');
        }
    }
    if ($domain === 'youtubei.googleapis.com' || $domain === 'youtube.googleapis.com') {
        return array('key' => 'service:youtube', 'label' => 'YouTube', 'kind' => 'Servicio probable por DNS');
    }
    foreach (array('facebook.com', 'facebook.net', 'fbcdn.net', 'fbsbx.com', 'messenger.com') as $suffix) {
        if (ipwall_domain_is($domain, $suffix)) {
            return array('key' => 'service:facebook', 'label' => 'Facebook / Messenger', 'kind' => 'Servicio probable por DNS');
        }
    }
    $mainDomain = ipwall_groupable_domain($domain);
    return array('key' => 'domain:' . $mainDomain, 'label' => $mainDomain,
        'kind' => ($mainDomain === $domain) ? 'Dominio/hostname probable por DNS' : 'Dominio principal probable por DNS');
}

function ipwall_build_groups($requests, $outboundWhitelist, $inboundWhitelist) {
    $groups = array();
    foreach ($requests as $r) {
        if (!is_array($r) || !isset($r['ip']) || !ipwall_valid_ip((string)$r['ip'])) continue;
        $block = ipwall_observed_block((string)$r['ip']);
        if ($block === '') continue;
        $identity = ipwall_group_identity($r, $block);
        $key = $identity['key'];
        if (!isset($groups[$key])) {
            $groups[$key] = array(
                'key' => $key, 'label' => $identity['label'], 'kind' => $identity['kind'],
                'blocks' => array(), 'domains' => array(), 'ips' => array(),
                'events' => 0, 'first_seen_unix' => 0, 'last_seen_unix' => 0,
                'remaining_inbound' => 0, 'remaining_outbound' => 0
            );
        }
        if (!isset($groups[$key]['blocks'][$block])) {
            $groups[$key]['blocks'][$block] = array('ips' => array(), 'allowed_inbound' => false, 'allowed_outbound' => false);
        }
        $ip = (string)$r['ip'];
        $groups[$key]['blocks'][$block]['ips'][$ip] = true;
        $groups[$key]['ips'][$ip] = true;
        $groups[$key]['events'] += isset($r['count']) ? (int)$r['count'] : 1;
        $firstUnix = isset($r['first_seen_unix']) ? (int)$r['first_seen_unix'] : 0;
        if ($firstUnix > 0 && ($groups[$key]['first_seen_unix'] === 0 || $firstUnix < $groups[$key]['first_seen_unix'])) {
            $groups[$key]['first_seen_unix'] = $firstUnix;
        }
        $groups[$key]['last_seen_unix'] = max($groups[$key]['last_seen_unix'], isset($r['last_seen_unix']) ? (int)$r['last_seen_unix'] : 0);
        if (strncmp($key, 'unknown:', 8) !== 0 && !empty($r['domain'])) {
            $groups[$key]['domains'][(string)$r['domain']] = true;
        }
    }
    foreach ($groups as $key => $group) {
        ksort($groups[$key]['blocks'], SORT_NATURAL);
        foreach ($group['blocks'] as $block => $data) {
            $coveredIn = ipwall_block_covered($block, $inboundWhitelist);
            $coveredOut = ipwall_block_covered($block, $outboundWhitelist);
            $groups[$key]['blocks'][$block]['allowed_inbound'] = $coveredIn;
            $groups[$key]['blocks'][$block]['allowed_outbound'] = $coveredOut;
            if (!$coveredIn) $groups[$key]['remaining_inbound']++;
            if (!$coveredOut) $groups[$key]['remaining_outbound']++;
        }
    }
    uasort($groups, function($a, $b) {
        if ($a['last_seen_unix'] !== $b['last_seen_unix']) {
            return ($a['last_seen_unix'] > $b['last_seen_unix']) ? -1 : 1;
        }
        return strcasecmp($a['label'], $b['label']);
    });
    return $groups;
}
