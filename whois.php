<?php
// 关闭 HTML 错误提示，只输出纯 JSON
ini_set('display_errors', 0); 
error_reporting(E_ALL);

// ==================[ CORS 跨域配置 ]==================
// 允许所有域名异步访问（解决前端 Ajax/Fetch 跨域报错）
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");

// 处理浏览器的 OPTIONS 预检请求，直接返回 200 并退出
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    header("HTTP/1.1 200 OK");
    exit;
}
// =====================================================

header('Content-Type: application/json; charset=utf-8');

// 2. 获取并净化参数
$domain = isset($_GET['domain']) ? trim($_GET['domain']) : '';
$show_raw = isset($_GET['raw']) ? intval($_GET['raw']) : 0;

// data.error
if (empty($domain)) {
    // 获取浏览器的 Accept 请求头
    $accept = isset($_SERVER['HTTP_ACCEPT']) ? $_SERVER['HTTP_ACCEPT'] : '';

    // 请求头里包含 application/json，API 接口，返回 JSON
    if (strpos($accept, 'application/json') !== false) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'status' => 0,
            'error' => 'Domain parameter is required.'
        ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    } 
    
    // 302 重定向到文档页
    header("Location: https://whois.tiking.top/docs", true, 302);
    exit;
}

// 解析域名信息
$domain = strtolower($domain);
$parts = explode('.', $domain);
if (count($parts) < 2) {
    echo json_encode([
        'status' => 0,
        'error' => 'Invalid domain format.'
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}
$suffix = end($parts); // 获取域名后缀

// 获取 WHOIS 服务器地址
$whois_server = get_whois_server($suffix);

// 发送 Socket 请求获取原始数据
$raw_data = query_whois_socket($whois_server, $domain);

if (!$raw_data || strpos($raw_data, 'Error:') === 0) {
    echo json_encode([
        'status' => 0,
        'error' => 'Failed to connect to WHOIS server: ' . $whois_server
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

// 解析原始数据
$parsed_info = parse_whois_text($raw_data, $suffix);

// 计算及组合最终响应字典
$now = new DateTime();
$query_time = $now->format('Y-m-d H:i:s');

$creation_days = 0;
$valid_days = 0;
$is_expire = 0;
$is_available = 1; // 默认可注册

if (!empty($parsed_info['creation_time']) && !empty($parsed_info['expiration_time'])) {
    $is_available = 0; // 查到了创建和到期时间，说明已被注册
    
    try {
        $create_date = new DateTime($parsed_info['creation_time']);
        $expire_date = new DateTime($parsed_info['expiration_time']);
        
        // 计算天数
        $creation_days = $create_date->diff($now)->days;
        
        if ($now > $expire_date) {
            $is_expire = 1;
            $valid_days = 0; 
        } else {
            $is_expire = 0;
            $valid_days = $now->diff($expire_date)->days;
        }
    } catch (Exception $e) {
        // 时间解析异常兜底
    }
} else {
    // 额外未注册关键词判断
    if (preg_implode_check(['no match', 'not found', 'free', 'available', 'no entries found', 'No match for'], $raw_data)) {
        $is_available = 1;
    } else {
        $is_available = 0; 
    }
}

// ==================返回JSON格式==================
$response = [
    'status' => 1,
    'data'   => [
        'domain'        => $domain,
        'domain_suffix' => $suffix,
        'is_available'  => $is_available,
        'raw'           => $raw_data, // 前端 displayResults 直接读取了 data.raw
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


if ($show_raw !== 1) { unset($response['data']['raw']); }

echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
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
    
    // 如果不在预设内，直接通过 IANA 43端口查询该后缀官方去向
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
        $query = "=" . $query; // 针对 .com 实施精准无混淆查询
    }
    
    fwrite($fp, $query . "\r\n");
    $out = "";
    while (!feof($fp)) {
        $out .= fgets($fp, 4096);
    }
    fclose($fp);
    return $out;
}

/**
 * 单行正则安全匹配（提取第一个捕获组 [1] 并作防越界处理）
 */
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

/**
 * 多行正则安全匹配（提取 DNS 等多行重名数据，彻底修复 null 导致的 Fatal Error）
 */
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

/**
 * 辅助函数：批量关键词匹配
 */
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
    // 匹配规则配置
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
    
    // 前端要求 domain_status 传的是数组或带分隔的内容，此处提取原始文本
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

    // 提取纯文本
    $creation_time = match_field($creation_patterns, $raw);
    $expiration_time = match_field($expiration_patterns, $raw);
    $registrar_name = match_field($registrar_patterns, $raw);
    $domain_status = match_field($status_patterns, $raw);
    $registrant_name = match_field($registrant_patterns, $raw);
    $registrant_email = match_field($email_patterns, $raw);
    
    $ns_array = match_field_multi($ns_patterns, $raw);
    
    // 规范化时间格式 (仅抽取出前段 YYYY-MM-DD，防非标时区字符干扰)
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
    
    // 过滤各种注册保护下的无效隐私信息
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
        'domain_status'   => $domain_status ? [$domain_status] : ["ok"], // 包装成数组符合前端格式
        'name_server'     => !empty($ns_array) ? array_unique(array_filter($ns_array)) : [], // 数组格式对齐前端
        'registrant_name' => $registrant_name ?: "",
        'registrant_email'=> $registrant_email ?: ""
    ];
}