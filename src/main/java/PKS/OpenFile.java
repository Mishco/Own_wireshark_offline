package PKS;

import java.io.File;
import java.util.Scanner;

/**
 *
 * @author Michal
 */
public class OpenFile {
    
    public static String open1(int a) {
        try {
            File text = new File("Ethernet.txt");  // typy ethernetu
            Scanner sc = new Scanner(text);
            int number = 0;
            while (sc.hasNextLine ()) {
                number = Integer.parseInt(sc.next().substring(2), 16);  // nacitanie hexa cisla
                String tmp = sc.nextLine();
                if (number == a) {
                    return tmp;
                }            
            }
        } catch (Exception e) {//Catch exception if any
            System.err.println("Error: " + e.getMessage());
        }
        return "nenaslo"; // v pripade ze dany protokol sa nenachadza v subore
        }
    
    public static String open2(int b) {
         try {
            File text = new File("ipProtocolNumbers.txt");
            Scanner sc = new Scanner(text);
            int number = 0;
            while (sc.hasNextLine()) {
                number = sc.nextInt();
                String description = sc.nextLine();
                if (number == b) {
                    return description;
                }
            }
        } catch (Exception e) {//Catch exception if any
            System.err.println("Error: " + e.getMessage());
        }
         return "nenaslo";
    }
    
    public static String openPorts(int c) {
        try {
            File text = new File("Ports.txt");
            Scanner sc= new Scanner(text);
            int num = 0;
            while(sc.hasNextLine()) {
                num = sc.nextInt();
                if (sc.hasNextLine()) {
                    String tmp = sc.nextLine();
                    if (num == c) {
                        return tmp;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        } 
        return "nenaslo";
    }
     public static String open3(int c) {
        try {
            File text = new File("Typeofethernet.txt");  // typy ethernetu
            Scanner sc = new Scanner(text);
            int number;
            while (sc.hasNextLine ()) {
                number = sc.nextInt();
                String tmp = sc.nextLine();
                if (number == c) {
                    return tmp;
                }            
            }
        } catch (Exception e) {//Catch exception if any
            System.err.println("Error: " + e.getMessage());
        }
        return "nenaslo"; // v pripade ze dany protokol sa nenachadza v subore
        }
     
     public static String openICMP(int d) {
        try {
            File text = new File("ICMP.txt");  // typy ethernetu
            Scanner sc = new Scanner(text);
            int number;
            while (sc.hasNextLine ()) {
                number = sc.nextInt();
                String tmp = sc.nextLine();
                if (number == d) {
                    return tmp;
                }            
            }
        } catch (Exception e) {//Catch exception if any
            System.err.println("Error: " + e.getMessage());
        }
        return "nenaslo"; // v pripade ze dany protokol sa nenachadza v subore
        }
}