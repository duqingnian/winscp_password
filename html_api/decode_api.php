<?php
header("Content-Type: application/json");

define('PW_MAGIC', 0xA3);
define('PW_FLAG',  0xFF);

function dec_next_char(&$s) {
    $base = "0123456789ABCDEF";
    $a = strpos($base, $s[0]);
    $b = strpos($base, $s[1]);
    $s = substr($s, 2);
    return (~(($a << 4) + $b) ^ PW_MAGIC) & 0xFF;
}

function decrypt($hex, $key) {
    $pwd = $hex;
    $clearpwd = "";

    $flag = dec_next_char($pwd);

    if ($flag === PW_FLAG) {
        dec_next_char($pwd); // dummy
        $length = dec_next_char($pwd);
    } else {
        $length = $flag;
    }

    $offset = dec_next_char($pwd);
    $pwd = substr($pwd, $offset * 2);

    for ($i = 0; $i < $length; $i++) {
        $clearpwd .= chr(dec_next_char($pwd));
    }

    if ($flag === PW_FLAG) {
        if (substr($clearpwd, 0, strlen($key)) !== $key) {
            return "";
        }
        $clearpwd = substr($clearpwd, strlen($key));
    }

    return $clearpwd;
}

// 接收数据并处理
$enc = $_POST['data'] ?? '';
$key = 'root192.168.12.34';
$decrypted = decrypt($enc, $key);

echo json_encode([
  'decrypted' => $decrypted
]);
