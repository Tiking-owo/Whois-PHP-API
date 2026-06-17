<?php
/**
 * WHOIS-PHP 查询 API
 *
 * @author 皪澄_Tiking (GitHub: Tiking-owo)
 * @license MIT License
 * @copyright (c) 2026 Tiking-owo
 *
 * Full license text is available in the LICENSE file in the root directory.
 */

// 关闭 HTML 错误提示，只输出纯 JSON
ini_set('display_errors', 0); 
error_reporting(E_ALL);

// ==================[ CORS 跨域配置 ]==================
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    header("HTTP/1.1 200 OK");
    exit;
}
// =====================================================

header('Content-Type: application/json; charset=utf-8');

// ==================[ 核心配置：缓存与速率限制 ]==================
define('CACHE_DIR', sys_get_temp_dir() . '/whois_cache/'); // 缓存目录
define('LIMIT_DIR', sys_get_temp_dir() . '/whois_limit/'); // 限流目录
define('CACHE_TIME', 300);                                 // 缓存时间 (秒)
define('LIMIT_TIME', 2);                                   // 访问频率限制 (秒)

// 自动初始化必要的本地存储目录
if (!is_dir(CACHE_DIR)) @mkdir(CACHE_DIR, 0755, true);
if (!is_dir(LIMIT_DIR)) @mkdir(LIMIT_DIR, 0755, true);

// 获取客户端精准 IP
function get_client_ip() {
    $ip = '127.0.0.1';
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    return trim($ip);
}

// 实施 Rate Limit 速率限制
$client_ip = get_client_ip();
$ip_hash = md5($client_ip);
$limit_file = LIMIT_DIR . $ip_hash;
$now_time = time();

if (file_exists($limit_file)) {
    $last_time = intval(@file_get_contents($limit_file));
    if (($now_time - $last_time) < LIMIT_TIME) {
        http_response_code(429); // 返回 429 状态码
        echo json_encode([
            'status' => 0,
            'error' => 'Too many requests. Please query again after ' . LIMIT_TIME . ' seconds.'
        ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }
}
@file_put_contents($limit_file, $now_time); // 更新当前 IP 的最后访问时间
// ===============================================================

// 2. 获取并净化参数
$domain = isset($_GET['domain']) ? trim($_GET['domain']) : '';
$show_raw = isset($_GET['raw']) ? intval($_GET['raw']) : 0;

// 参数为空时的智能分流拦截
if (empty($domain)) {
    $accept = isset($_SERVER['HTTP_ACCEPT']) ? $_SERVER['HTTP_ACCEPT'] : '';
    if (strpos($accept, 'application/json') !== false) {
        echo json_encode([
            'status' => 0,
            'error' => 'Domain parameter is required.'
        ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    } 
    header("Location: https://whois.tiking.top/docs", true, 302);
    exit;
}

// 3. 解析域名与格式校验
$domain = strtolower($domain);
$parts = explode('.', $domain);
if (count($parts) < 2) {
    echo json_encode([
        'status' => 0,
        'error' => 'Invalid domain format.'
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}
$suffix = end($parts); 

// ==================[ 核心配置：读取本地数据缓存 ]==================
$domain_hash = md5($domain);
$cache_file = CACHE_DIR . $domain_hash;

if (file_exists($cache_file) && ($now_time - filemtime($cache_file)) < CACHE_TIME) {
    $cached_data = @file_get_contents($cache_file);
    if ($cached_data) {
        // 直接输出缓存的 JSON 字符串
        echo $cached_data;
        exit;
    }
}
// ===============================================================

// 4. 获取 WHOIS 服务器地址
$whois_server = get_whois_server($suffix);

// 5. 发送 Socket 请求获取原始数据
$raw_data = query_whois_socket($whois_server, $domain);

if (!$raw_data || strpos($raw_data, 'Error:') === 0) {
    echo json_encode([
        'status' => 0,
        'error' => 'Failed to connect to WHOIS server: ' . $whois_server
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

// 6. 解析原始数据
$parsed_info = parse_whois_text($raw_data, $suffix);

// 7. 计算生命周期与状态判定
$creation_days = 0;
$valid_days = 0;
$is_expire = 0;
$is_available = 1; 

$current_date = new DateTime();

if (!empty($parsed_info['creation_time']) && !empty($parsed_info['expiration_time'])) {
    $is_available = 0; 
    try {
        $create_date = new DateTime($parsed_info['creation_time']);
        $expire_date = new DateTime($parsed_info['expiration_time']);
        
        $creation_days = $create_date->diff($current_date)->days;
        
        if ($current_date > $expire_date) {
            $is_expire = 1;
            $valid_days = 0; 
        } else {
            $is_expire = 0;
            $valid_days = $current_date->diff($expire_date)->days;
        }
    } catch (Exception $e) {
        // 时间解析异常兜底
    }
} else {
    if (preg_implode_check(['no match', 'not found', 'free', 'available', 'no entries found', 'No match for'], $raw_data)) {
        $is_available = 1;
    } else {
        $is_available = 0; 
    }
}

// ==================[ 构件标准嵌套 JSON 响应体 ]==================
$response = [
    'status' => 1,
    'data'   => [
        'domain'        => $domain,
        'domain_suffix' => $suffix,
        'is_available'  => $is_available,
        'raw'           => $raw_data,
        'info'          => [
            'registrar_name'   => $parsed_info['registrar_name'],
            'registrant_name'  => $parsed_info['registrant_name'],
            'registrant_email' => $parsed_info['registrant_email'],
            'whois_server'     => $whois_server,
            'creation_time'    => $parsed_info['creation_time'],
            'expiration_time'  => $parsed_info['expiration_time'],
            'creation_days'    => $creation_days,
            'valid_days'       => $valid_days,
            'is_expire'        => $is_expire,
            'domain_status'    => $parsed_info['domain_status'],
            'name_server'      => $parsed_info['name_server']
        ]
    ]
];

$output_json = json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);

// 将成功获取的纯数据写入本地高速缓存文件
@file_put_contents($cache_file, $output_json);

echo $output_json;
exit;


/**
 * 辅助函数：根据后缀路由 WHOIS 服务器
 */
function get_whois_server($suffix) {
    $common_servers = [
        'com' => 'whois.verisign-grs.com',
        'net' => 'whois.verisign-grs.com',
        'cc'  => 'whois.nic.cc',
        'cn'  => 'whois.cnnic.cn',
        'org' => 'whois.pir.org',
        'info'=> 'whois.afilias.net',
        'biz' => 'whois.nic.biz',
        'top' => 'whois.nic.top',
        'xyz' => 'whois.nic.xyz',
        'hk'  => 'whois.hkirc.hk',
        'tw'  => 'whois.twnic.net.tw'
    ];
    
    if (isset($common_servers[$suffix])) {
        return $common_servers[$suffix];
    }
    
    $iana_raw = query_whois_socket('whois.iana.org', $suffix);
    if ($iana_raw && preg_match('/whois:\s+([^\s]+)/i', $iana_raw, $matches)) {
        return trim($matches[1]);
    }
    
    return "whois.nic." . $suffix;
}

/**
 * 辅助函数：通过 Socket 查询原生 WHOIS 文本
 */
function query_whois_socket($server, $query) {
    $fp = @fsockopen($server, 43, $errno, $errstr, 5);
    if (!$fp) {
        return "Error: $errstr ($errno)";
    }
    
    if ($server === 'whois.verisign-grs.com') {
        $query = "=" . $query; 
    }
    
    fwrite($fp, $query . "\r\n");
    $out = "";
    while (!feof($fp)) {
        $out .= fgets($fp, 4096);
    }
    fclose($fp);
    return $out;
}

function match_field($patterns, $text) {
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $text, $matches)) {
            if (isset($matches[1])) {
                return trim($matches[1]);
            }
        }
    }
    return "";
}

function match_field_multi($patterns, $text) {
    foreach ($patterns as $pattern) {
        if (preg_match_all($pattern, $text, $matches)) {
            if (!empty($matches[1])) {
                return array_map('trim', $matches[1]);
            }
        }
    }
    return [];
}

function preg_implode_check($keywords, $text) {
    foreach ($keywords as $word) {
        if (stripos($text, $word) !== false) return true;
    }
    return false;
}

/**
 * 核心 WHOIS 文本解析器
 */
function parse_whois_text($raw, $suffix) {
    $registrar_patterns = [
        '/Registrar:\s*(.*)/i',
        '/Sponsoring Registrar:\s*(.*)/i',
        '/Registrar Name:\s*(.*)/i'
    ];
    
    $creation_patterns = [
        '/Creation Date:\s*(.*)/i',
        '/Registration Time:\s*(.*)/i',
        '/Created On:\s*(.*)/i',
        '/Registered on:\s*(.*)/i'
    ];
    
    $expiration_patterns = [
        '/Registry Expiry Date:\s*(.*)/i',
        '/Registrar Registration Expiration Date:\s*(.*)/i',
        '/Expiration Time:\s*(.*)/i',
        '/Expiration Date:\s*(.*)/i',
        '/Expiry Date:\s*(.*)/i'
    ];
    
    $status_patterns = [
        '/Domain Status:\s*([^\s\r\n]*)/i',
        '/Status:\s*([^\s\r\n]*)/i'
    ];
    
    $ns_patterns = [
        '/Name Server:\s*([^\s\r\n]*)/i',
        '/Nserver:\s*([^\s\r\n]*)/i'
    ];

    $registrant_patterns = ['/Registrant Name:\s*(.*)/i', '/Registrant:\s*(.*)/i'];
    $email_patterns = ['/Registrant Contact Email:\s*(.*)/i', '/Registrant Email:\s*(.*)/i'];

    $creation_time = match_field($creation_patterns, $raw);
    $expiration_time = match_field($expiration_patterns, $raw);
    $registrar_name = match_field($registrar_patterns, $raw);
    $domain_status = match_field($status_patterns, $raw);
    $registrant_name = match_field($registrant_patterns, $raw);
    $registrant_email = match_field($email_patterns, $raw);
    
    $ns_array = match_field_multi($ns_patterns, $raw);
    
    if (!empty($creation_time)) {
        $date_part = explode('T', $creation_time)[0];
        $time_stamp = strtotime($date_part);
        $creation_time = $time_stamp ? date('Y-m-d H:i:s', $time_stamp) : "";
    }
    if (!empty($expiration_time)) {
        $date_part = explode('T', $expiration_time)[0];
        $time_stamp = strtotime($date_part);
        $expiration_time = $time_stamp ? date('Y-m-d H:i:s', $time_stamp) : "";
    }
    
    if (preg_implode_check(['REDACTED', 'Privacy', 'WhoisGuard', 'SuperPrivacy', 'Protected', 'grs-whois'], $registrant_name)) {
        $registrant_name = "";
    }
    if (preg_implode_check(['redacted', 'privacy', 'whoisguard', 'anonym'], $registrant_email)) {
        $registrant_email = "";
    }

    return [
        'registrar_name'  => $registrar_name ?: "",
        'creation_time'   => $creation_time ?: "",
        'expiration_time' => $expiration_time ?: "",
        'domain_status'   => $domain_status ? [$domain_status] : ["ok"], 
        'name_server'     => !empty($ns_array) ? array_unique(array_filter($ns_array)) : [], 
        'registrant_name' => $registrant_name ?: "",
        'registrant_email'=> $registrant_email ?: ""
    ];
}