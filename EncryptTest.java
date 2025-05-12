import java.text.SimpleDateFormat;
import java.util.*;

public class EncryptTest {
    private static final int PW_MAGIC = 0xA3;
    private static final int PW_FLAG = 0xFF;

    public static String encrypt(String password, String key) {
        String full = key + password;
        StringBuilder result = new StringBuilder();

        result.append(encByte(PW_FLAG)); // enc_flag
        result.append(encByte(0));       // dummy
        result.append(encByte(full.length())); // length
        result.append(encByte(0));       // offset = 0

        for (char ch : full.toCharArray()) {
            result.append(encByte((int) ch));
        }

        return result.toString();
    }

    public static String decrypt(String hex, String key) {
        StringBuilder pwd = new StringBuilder(hex);
        StringBuilder clear = new StringBuilder();

        int flag = decNextChar(pwd);
        int length;

        if (flag == PW_FLAG) {
            decNextChar(pwd); // dummy
            length = decNextChar(pwd);
        } else {
            length = flag;
        }

        int offset = decNextChar(pwd);
        for (int i = 0; i < offset * 2 && i < pwd.length(); i++) {
            pwd.deleteCharAt(0);
        }

        for (int i = 0; i < length; i++) {
            clear.append((char) decNextChar(pwd));
        }

        if (flag == PW_FLAG) {
            if (!clear.toString().startsWith(key)) {
                return "";
            }
            return clear.substring(key.length());
        }
        return clear.toString();
    }

    private static String encByte(int b) {
        int enc = ~(b ^ PW_MAGIC) & 0xFF;
        return String.format("%02X", enc);
    }

    private static int decNextChar(StringBuilder s) {
        if (s.length() < 2) return 0;
        String base = "0123456789ABCDEF";
        int a = base.indexOf(s.charAt(0));
        int b = base.indexOf(s.charAt(1));
        int val = ~((a << 4) + b ^ PW_MAGIC) & 0xFF;
        s.delete(0, 2);
        return val;
    }

    public static String generateRandom(RandomOption opt) {
        StringBuilder charset = new StringBuilder();
        if (opt.useLowercase) charset.append("abcdefghijklmnopqrstuvwxyz");
        if (opt.useUppercase) charset.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        if (opt.useDigits) charset.append("0123456789");
        if (opt.useSymbols) charset.append("!@#$%^&*()-_=+[]{}|;:,.<>?");
        charset.append(opt.extraChars);

        Random rand = new Random();
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < opt.length; i++) {
            int idx = rand.nextInt(charset.length());
            result.append(charset.charAt(idx));
        }
        return result.toString();
    }

    public static String formatNow(Date date) {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS").format(date);
    }

    public static String formatDuration(long millis) {
        return String.format("%ds%dms", millis / 1000, millis % 1000);
    }

    public static void main(String[] args) throws InterruptedException {
        String user = "root";
        String host = "192.168.12.34";
        String key = user + host;

        RandomOption opt = new RandomOption();
        opt.length = 64;
        opt.useLowercase = true;
        opt.useUppercase = true;
        opt.useDigits = true;
        opt.useSymbols = true;
        opt.extraChars = "#~-_";

        int matchCount = 0, mismatchCount = 0;
        int loopCount = 100;

        long startMillis = System.currentTimeMillis();
        System.out.println("Start Time    : " + formatNow(new Date(startMillis)));

        for (int i = 1; i <= loopCount; i++) {
            String password = generateRandom(opt);
            String crypted = encrypt(password, key);
            String plain = decrypt(crypted, key);
            boolean match = password.equals(plain);
            if (match) matchCount++;
            else mismatchCount++;

            System.out.println("===== Test #" + i + " =====");
            System.out.println("Plain     : " + password);
            System.out.println("Encrypted : " + crypted);
            System.out.println("Decrypted : " + plain);
            System.out.println("Match     : " + (match ? "......Yes" : "......No"));
            System.out.println();

            Thread.sleep(100); // 等效 sleep 100ms
        }

        long endMillis = System.currentTimeMillis();
        System.out.println("End Time      : " + formatNow(new Date(endMillis)));
        System.out.println("Total Duration: " + formatDuration(endMillis - startMillis));
        System.out.println("Match Count   : " + matchCount);
        System.out.println("Mismatch Count: " + mismatchCount);
    }

    // 支持配置的随机生成结构体
    static class RandomOption {
        int length = 16;
        boolean useLowercase = true;
        boolean useUppercase = true;
        boolean useDigits = true;
        boolean useSymbols = false;
        String extraChars = "";
    }
}
