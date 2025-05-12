<?php

define('PW_MAGIC', 0xA3);
define('PW_FLAG',  0xFF);

function enc_byte($b) {
    $enc = (~($b ^ PW_MAGIC)) & 0xFF;
    return strtoupper(str_pad(dechex($enc), 2, '0', STR_PAD_LEFT));
}

function dec_next_char(&$s) {
    if (strlen($s) < 2) return 0;
    $base = "0123456789ABCDEF";
    $a = strpos($base, $s[0]);
    $b = strpos($base, $s[1]);
    $s = substr($s, 2);
    return (~(($a << 4) + $b) ^ PW_MAGIC) & 0xFF;
}

function encrypt($password, $key) {
    $full = $key . $password;
    $result = '';

    $result .= enc_byte(PW_FLAG);             // flag
    $result .= enc_byte(0);                   // dummy
    $result .= enc_byte(strlen($full));       // length
    $result .= enc_byte(0);                   // offset = 0

    for ($i = 0; $i < strlen($full); $i++) {
        $result .= enc_byte(ord($full[$i]));
    }

    return $result;
}

function decrypt($pwd, $key) {
    $clearpwd = "";

    $flag = dec_next_char($pwd);
    if ($flag == PW_FLAG) {
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

    if ($flag == PW_FLAG) {
        if (substr($clearpwd, 0, strlen($key)) !== $key) {
            return "";
        }
        $clearpwd = substr($clearpwd, strlen($key));
    }
    return $clearpwd;
}

function generate_random($opt) {
    $charset = '';
    if ($opt['useLowercase']) $charset .= 'abcdefghijklmnopqrstuvwxyz';
    if ($opt['useUppercase']) $charset .= 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if ($opt['useDigits'])    $charset .= '0123456789';
    if ($opt['useSymbols'])   $charset .= '!@#$%^&*()-_=+[]{}|;:,.<>?';
    $charset .= $opt['extraChars'];

    $result = '';
    $max = strlen($charset) - 1;
    for ($i = 0; $i < $opt['length']; $i++) {
        $result .= $charset[random_int(0, $max)];
    }
    return $result;
}

function format_time($ts) {
    return date("Y-m-d H:i:s", $ts) . ':' . substr((string)(microtime(true) * 1000 % 1000 + 1000), 1, 3);
}

function format_duration($ms) {
    return floor($ms / 1000) . "s" . ($ms % 1000) . "ms";
}

// ====== Main Test ======
$user = "root";
$host = "192.168.12.34";
$key = $user . $host;

$opt = [
    'length' => 64,
    'useLowercase' => true,
    'useUppercase' => true,
    'useDigits' => true,
    'useSymbols' => true,
    'extraChars' => '#~-_'
];

$loopCount = 100;
$matchCount = 0;
$mismatchCount = 0;

$start = microtime(true);
echo "Start Time    : " . format_time(time()) . PHP_EOL;

for ($i = 1; $i <= $loopCount; $i++) {
    $password = generate_random($opt);
    $crypted = encrypt($password, $key);
    $plain = decrypt($crypted, $key);
    $match = ($password === $plain);
    if ($match) $matchCount++; else $mismatchCount++;

    echo "===== Test #$i =====\n";
    echo "Plain     : $password\n";
    echo "Encrypted : $crypted\n";
    echo "Decrypted : $plain\n";
    echo "Match     : " . ($match ? "......Yes" : "......No") . "\n\n";
    usleep(100000); // 100ms
}

$end = microtime(true);
$duration = intval(($end - $start) * 1000);
echo "End Time      : " . format_time(time()) . PHP_EOL;
echo "Total Duration: " . format_duration($duration) . PHP_EOL;
echo "Match Count   : $matchCount\n";
echo "Mismatch Count: $mismatchCount\n";
