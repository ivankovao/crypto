package HW01;

import java.security.SecureRandom;
import java.util.Random;
import java.util.Scanner;

public class DailyForecast {
    public static void main(String[] args) {
        String[] types = {"У вас сегодня будет удача в дела!", "Сегодня хороший день для саморазвития!"};
        Random basic = new Random();
        SecureRandom secure = new SecureRandom();

        Scanner scanner = new Scanner(System.in);
        String name = scanner.nextLine();
        while (scanner.hasNext()) {
            String type = scanner.nextLine();
            if (type.equals("stop")) {
                break;
            } else if (RandomType.BASIC.name().equalsIgnoreCase(type)) {
                System.out.println(name + ", " + types[basic.nextInt(types.length)]);
            } else if (RandomType.SECURE.name().equalsIgnoreCase(type)) {
                System.out.println(name + ", " + types[secure.nextInt(types.length)]);
            }
        }
    }
}
