package PKS;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;

/**
 * alt + shift + f ...zarovnanie kodu
 *
 * @author Michal
 */
public class ScanAllFrame {

    final int LEN_ADRESS = 12;
    final int SPACE = 5; //medzera ,ktoru vklada pri vypise MAC adresy
    final int MAX = 5000;
    final StringBuilder errBuf = new StringBuilder();   //na chybove hlasky
    static int number_of_frame = 0;
    static int onlineLength = 0;

    static StringBuilder com = new StringBuilder();

    static String IP_address_source = new String();
    static String IP_address_destion = new String();

    //dorobene
    static int sourcePort = 0;
    static int destinationPort = 0;

    @SuppressWarnings("Convert2Diamond")
    static ArrayList<Frame> zoznamRamcov = new ArrayList<Frame>();  //pole ramcov(objektov)
    static ArrayList<Comunication> zoznamKomunikacii = new ArrayList<Comunication>(); // pole komunikacii

    class Tftp {

        int dest_port;
        int source_port;
    }
    static ArrayList<Tftp> specZoznam = new ArrayList<Tftp>();

    int SpecialCommunication = 0;
    StringBuilder allComSpecial = new StringBuilder();

    int statitistic[] = new int[8];

    @SuppressWarnings("static-access")
    public ScanAllFrame(String fileName, int typeOfProtocol) {
        Pcap pcap = Pcap.openOffline(fileName, errBuf); // otvorenie suboru na citanie
        if (pcap == null) { // kontrola otvorenia suboru, ak by nastal problem vypise chybu a ukonci cely program
            System.err.printf("Error while opening file for capture: " + errBuf.toString());
            return;
        }
        for (int k = 0; k < 8; k++) {
            statitistic[k] = 0;
        }

        PcapHeader head = new PcapHeader(JMemory.POINTER); // ukazovatel na hlavicky ramcov
        JBuffer buf = new JBuffer(JMemory.POINTER);   // ukazovatel na udaje v ramci(ramec ako taky)

        String frames = new String();
        int count = 1; // pocet framov == retazcov

        String Network_Protocol = new String(); // TCP, UDP, ICMP
        String Transport_Protocol = new String(); // http
        int TftpPort = 0; // aj ked UDP moze mat nulty protocol rezervovany
        int ARP = 0;
        while (pcap.nextEx(head, buf) == pcap.NEXT_EX_OK) {
            List<Byte> byteList = new ArrayList<>();
            for (int k = 0; k < buf.size(); k++) {
                byteList.add(buf.getByte(k));
            }
            frames = bytelistToHEXString(byteList);
            // System.out.println(bytelistToHEXString(byteList));

            String str = new String(frames);

            char[] arrayOfChar = str.toCharArray(); // ulozi do pola znakov, s ktorymi s lepsie pracuje
            char[] tmp = new char[2];               // pomocne pole na ulozenie prvych MAC adries

            int[] number = new int[str.length() / 2]; // pomocne pole na cisla, vzdy nam staci polovicna velkost kvoli tomu ze 

            // obsahuje prepis celeho ramca na desiatkovu sustavu
            // number[];
            int j_dx = 0;
            int idx;
            for (idx = 0; idx < str.length(); idx += 2) { // prevod celeho ramca do desiatkovej sustavy
                tmp[0] = arrayOfChar[idx];
                tmp[1] = arrayOfChar[idx + 1];
                String temp_string = new String(tmp);
                number[j_dx] = Integer.parseInt(temp_string, 16); // prevod zo 16nastkovej sustavy na desiatkovu 
                j_dx++;
            }
// prva cast zadania
//------------------------------------------------------------------------------------------------------------------
            char[] dest_adress = new char[18];
            char[] sourc_adress = new char[18];
            int i;
            for (idx = i = 0; i < LEN_ADRESS + SPACE; idx++, i++) { //copy destination MAC address 
                if (i == 2 || i == 5 || i == 8 || i == 11 || i == 14) {
                    dest_adress[i] = ' '; //vlozi medzeru aby bol vypis prehladnejsi
                    i++;
                }
                dest_adress[i] = arrayOfChar[idx];
            }
            i = 0;
            for (idx = LEN_ADRESS; i < LEN_ADRESS + SPACE; idx++) { //copy source MAC address
                if (i == 2 || i == 5 || i == 8 || i == 11 || i == 14) {
                    sourc_adress[i] = ' ';
                    i++;
                }
                sourc_adress[i++] = arrayOfChar[idx];
            }

            String dest_MAC_adress = new String(dest_adress);
            String sourc_MAC_adress = new String(sourc_adress);

            char[] length = new char[4]; //na zistenie ci je ETHERNET II alebo 802.3
            length[0] = arrayOfChar[24];
            length[1] = arrayOfChar[25];
            length[2] = arrayOfChar[26];
            length[3] = arrayOfChar[27];

            String temp_string = new String(length);
            int ETH_NET = Integer.parseInt(temp_string, 16); //prevod zo 16 do 10 sustavy 
            int real_length = str.length() / 2; // skutocna dlzka Bytov je polovica ,kedze jeden Byte sa sklada z 8 bitov a tie sa zapisuju Dvoma znakmi

            //DOIMPLEMENTOVANE------------------
            char[] tmpPORT = new char[4];
            tmpPORT[0] = arrayOfChar[68];
            tmpPORT[1] = arrayOfChar[69];
            tmpPORT[2] = arrayOfChar[70];
            tmpPORT[3] = arrayOfChar[71];
            String S_Port = new String(tmpPORT);
            sourcePort = Integer.parseInt(S_Port, 16);

            tmpPORT[0] = arrayOfChar[72];
            tmpPORT[1] = arrayOfChar[73];
            tmpPORT[2] = arrayOfChar[74];
            tmpPORT[3] = arrayOfChar[75];
            String D_Port = new String(tmpPORT);
            destinationPort = Integer.parseInt(D_Port, 16);

            
            /*Pamatanie si IP adresy v kazdom ramci a ich vypisanie az na samotnom konci*/
            if (OpenFile.open1(ETH_NET).contains("Internet Protocol version 4 (IPv4)")) { // iba pre Internet IP(IPv4)

                //26 - 29 bajt vratane 
                IP_address_source = (number[26] + "." + number[27] + "." + number[28] + "." + number[29]);
                //30 - 33 bajt vratane
                IP_address_destion = (number[30] + "." + number[31] + "." + number[32] + "." + number[33]);

            } else { // ak nejde o rodinu Ethernet II a IPv4
                IP_address_destion = "_";
                IP_address_source = "_";
            }

            System.out.println("rámec " + count + "\ndĺžka rámca zachyteného paketovým drajverom - " + real_length + " B");
            if (real_length < 60) //ak je dlzka mensia potrebujeme minimalne 64 Bytov ktore sa budu prenasat
            {
                System.out.println("dľžka rámca prenášaného po médiu - 64 B");
                onlineLength = 64;
            } else { // inak pridame 4 Byte ku skutocnej velkosti
                System.out.println("dľžka rámca prenášaného po médiu - " + (real_length + 4) + " B");
                onlineLength = real_length + 4;
            }
            // ak by velkost bola mensia ako 1500 ide 802.3
            String typeOfFrame = new String();
            if (ETH_NET < 1501) {
                //System.out.print("IEEE 802.3");
                typeOfFrame = "IEEE 802.3";

                // 170(10) == AA musi byt hodnota na 
                if (OpenFile.open3(number[14]).contains("SNAP") && OpenFile.open3(number[15]).contains("SNAP")) {
                    //    System.out.println(" - SNAP");
                    typeOfFrame = typeOfFrame + " - SNAP";
                }
                // 255(10) == FF musi byt hodnota
                if (OpenFile.open3(number[14]).contains("RAW") && OpenFile.open3(number[15]).contains("RAW")) {
                    //  System.out.println(" - RAW");
                    typeOfFrame = typeOfFrame + " - RAW";
                } else {
                    // System.out.println(" - LLC");
                    typeOfFrame = typeOfFrame + " - LLC";
                }
            } else { // ake je to vacsie ako 1500 ide o udaj o velkosti a je to ETHERNET II
                //     System.out.println("Ethernet II ");
                typeOfFrame = "Ethernet II";
            }
           // System.out.println("Zdrojová MAC adresa: " + sourc_MAC_adress);
            // System.out.println("Cieľová MAC adresa: " + dest_MAC_adress);

            // prerobi hexa na vypis  
            StringBuilder tmpStr = giveSpaceBetweenChar(str);

            // System.out.println(tmpStr);    //vypise cely ramec
            // System.out.println();
//-----------------------------------------------------------------------------------------------------------------
            switch (typeOfProtocol) {
                case 0:
                    Network_Protocol = "TCP";
                    Transport_Protocol = "Hypertext Transfer Protocol (HTTP)";
                    break;
                case 1:
                    Network_Protocol = "TCP";
                    Transport_Protocol = "HTTPS (Hypertext Transfer Protocol over SSL/TLS";
                    break;
                case 2:
                    Network_Protocol = "TCP";
                    Transport_Protocol = "Telnet protocol—unencrypted text communications";
                    break;
                case 3:
                    Network_Protocol = "TCP";
                    Transport_Protocol = "Secure Shell (SSH)";
                    break;
                case 4:
                    Network_Protocol = "TCP";
                    Transport_Protocol = "FTP control (command)";
                    break;
                case 5:
                    Network_Protocol = "TCP";
                    Transport_Protocol = "FTP data transfer";
                    break;

                case 6:
                    Network_Protocol = "UDP";
                    Transport_Protocol = "Trivial File Transfer Protocol (TFTP)";
                    break;
                case 7:
                    Network_Protocol = "ICMP";
                    Transport_Protocol = "";
                    break; // specialny pripade riesi sa samostatne        
                case 8: //uplne specialny pripad   
                    Network_Protocol = "ARP";
                    Transport_Protocol = "ARP";
                    break;
            }

            // Transport_Protocol = "Hypertext Transfer Protocol (HTTP)";
// komunikacie postupne od http nizsie
            String IPsource = "";
            String IPdest = "";
            String Flag = "";

            if (!(Network_Protocol.equals("") && Transport_Protocol.equals(""))) {
                if (OpenFile.open1(ETH_NET).contains("Internet Protocol version 4 (IPv4)")) {
                    if (OpenFile.open2(number[23]).contains(Network_Protocol)) {

                        // zisti source port
                        // 34 + 35
                        char[] port = new char[4];
                        port[0] = arrayOfChar[68];
                        port[1] = arrayOfChar[69];
                        port[2] = arrayOfChar[70];
                        port[3] = arrayOfChar[71];
                        String tmpPort = new String(port);
                        int sourcePort = Integer.parseInt(tmpPort, 16);

                        // zistenie destination Port v TCP
                        port[0] = arrayOfChar[72];
                        port[1] = arrayOfChar[73];
                        port[2] = arrayOfChar[74];
                        port[3] = arrayOfChar[75];
                        String deP = new String(port);
                        int destination = Integer.parseInt(deP, 16);

                        // ICMP
                        if (Network_Protocol.equals("ICMP")) {
                            SpecialCommunication = 1;
                            System.out.print("\nICMP - ");
                            System.out.println(OpenFile.openICMP(number[34]));
                            allComSpecial.append("\nICMP");
                            allComSpecial.append(OpenFile.openICMP(number[34]) + "\n");

                            System.out.print("Klient: " + number[26] + "." + number[27] + "." + number[28] + "." + number[29]);
                            System.out.println("      Server: " + number[30] + "." + number[31] + "." + number[32] + "." + number[33]);

                            allComSpecial.append("Klient: " + number[26] + "." + number[27] + "." + number[28] + "." + number[29]);
                            allComSpecial.append("      Server: " + number[30] + "." + number[31] + "." + number[32] + "." + number[33] + "\n");

                            System.out.println("rámec " + count + "\ndlžka rámca zachyteného paketovým drajverom - " + real_length + " B");
                            allComSpecial.append("\nrámec " + count + "\ndlžka rámca zachyteného paketovým drajverom - " + real_length + " B\n");
                            if (real_length < 60) {
                                System.out.println("dlžka rámca prenášaného po médiu - 64 B");
                                allComSpecial.append("dlžka rámca prenášaného po médiu - 64 B\n");
                            } else {
                                System.out.println("dlžka rámca prenášaného po médiu - " + (real_length + 4) + " B");
                                allComSpecial.append("dlžka rámca prenášaného po médiu - " + (real_length + 4) + " B\n");
                            }
                            allComSpecial.append("Ethernet II \n");
                            allComSpecial.append("Zdrojová MAC adresa: " + sourc_MAC_adress);
                            allComSpecial.append("\nCieľová MAC adresa: " + dest_MAC_adress + "\n");

                            allComSpecial.append(tmpStr + "\n");
                            int actLENGTH = real_length;
                            if (actLENGTH > 0 && actLENGTH <= 19) {
                                statitistic[0]++;
                            }
                            if (actLENGTH >= 20 && actLENGTH <= 39) {
                                statitistic[1]++;
                            }
                            if (actLENGTH >= 40 && actLENGTH <= 79) {
                                statitistic[2]++;
                            }
                            if (actLENGTH >= 80 && actLENGTH <= 159) {
                                statitistic[3]++;
                            }
                            if (actLENGTH >= 160 && actLENGTH <= 319) {
                                statitistic[4]++;
                            }
                            if (actLENGTH >= 320 && actLENGTH <= 639) {
                                statitistic[5]++;
                            }
                            if (actLENGTH >= 640 && actLENGTH <= 1279) {
                                statitistic[6]++;
                            }
                            if (actLENGTH >= 1280 && actLENGTH <= 1539) {
                                statitistic[7]++;
                            }

                        } // end ICMP

                        if (OpenFile.openPorts(sourcePort).contains(Transport_Protocol) || OpenFile.openPorts(destination).contains(Transport_Protocol) || TftpPort == sourcePort || TftpPort == destination) {
//                          
                            //specialne vyriesene TFTP komunikacia
                            if (sourcePort == 69) {
                                TftpPort = destination;
                            }
                            if (destination == 69) {
                                TftpPort = sourcePort;
                            }
                            if (TftpPort == 0) {
                                for (i = 52; i < 60; i++) {
                                    IPsource += str.charAt(i);
                                }
                                for (i = 60; i < 68; i++) {
                                    IPdest += str.charAt(i);
                                }

                                int determine = 0;

                                Flag += arrayOfChar[94];
                                Flag += arrayOfChar[95];
                                int flag_int = Integer.parseInt(Flag, 16);
                                Flag = Integer.toBinaryString(flag_int);

                                char[] FlagEight = new char[8];
                                for (i = 0; i < 8; i++) //pole naplni 8 nulami
                                {
                                    FlagEight[i] = '0';
                                }

                                int d = 0;

                                for (i = (8 - Flag.length()); i < 8; i++) {
                                    FlagEight[i] = Flag.charAt(d);
                                    d++;
                                }

                                flag_int = 0;

                                if (FlagEight[7] == '1' && FlagEight[6] == '0' && FlagEight[5] == '0' && FlagEight[3] == '0') //FIN
                                {
                                    flag_int = 5;
                                }
                                if (FlagEight[7] == '0' && FlagEight[6] == '1' && FlagEight[5] == '0' && FlagEight[3] == '0') { // SYN
                                    flag_int = 1;
                                }

                                if (FlagEight[7] == '0' && FlagEight[6] == '0' && FlagEight[5] == '0' && FlagEight[3] == '1') { // ACK
                                    flag_int = 3;
                                }
                                if (FlagEight[7] == '1' && FlagEight[6] == '0' && FlagEight[5] == '0' && FlagEight[3] == '1') { // FIN, ACK
                                    flag_int = 4;
                                }

                                if (FlagEight[7] == '0' && FlagEight[6] == '1' && FlagEight[5] == '0' && FlagEight[3] == '1') { // SYN, ACK
                                    flag_int = 2;
                                }
                                if (FlagEight[7] == '0' && FlagEight[6] == '0' && FlagEight[5] == '1' && FlagEight[3] == '0') { // RST
                                    flag_int = 6;
                                }
                                //  real_length;    

                                if (zoznamKomunikacii.isEmpty()) { // ak je zoznam prazdny
                                    Comunication c = new Comunication();
                                    FrameComun f = new FrameComun(tmpStr, count);
                                    f.setStateOfFLAGS(flag_int);
                                    f.setLength(real_length);
                                    f.setDestination_MAC(dest_MAC_adress);
                                    f.setSource_MAC(sourc_MAC_adress);

                                    c.setNumber(number);
                                    c.setState("nic");
                                    c.setSource_port(sourcePort);
                                    c.setDestin_port(destination);
                                    c.setSource_adress(IPsource);
                                    c.setDestination_adress(IPdest);
                                    zoznamKomunikacii.add(c);
                                    zoznamKomunikacii.get(0).getFrames().add(f);

                                } else { // kontrola ci v zozname uz dana komunikacia nie je 
                                    for (i = 0; i < zoznamKomunikacii.size(); i++) {
                                        if (zoznamKomunikacii.get(i).getDestination_adress().equals(IPdest) || zoznamKomunikacii.get(i).getDestination_adress().equals(IPsource)) {
                                            if (zoznamKomunikacii.get(i).getSource_adress().equals(IPdest) || zoznamKomunikacii.get(i).getSource_adress().equals(IPsource)) {
                                                if ((zoznamKomunikacii.get(i).getDestin_port() == destination) || (zoznamKomunikacii.get(i).getDestin_port() == sourcePort)) {
                                                    if ((zoznamKomunikacii.get(i).getSource_port() == destination) || (zoznamKomunikacii.get(i).getSource_port() == sourcePort)) {
                                                        FrameComun f = new FrameComun(tmpStr, count);
                                                        f.setStateOfFLAGS(flag_int);
                                                        f.setLength(real_length);
                                                        f.setDestination_MAC(dest_MAC_adress);
                                                        f.setSource_MAC(sourc_MAC_adress);
                                                        zoznamKomunikacii.get(i).getFrames().add(f);
                                                        determine++;
                                                    }
                                                }
                                            }
                                        }
                                    } // koniec FOR
                                    if (determine == 0) {
                                        Comunication c = new Comunication();
                                        FrameComun f = new FrameComun(tmpStr, count);
                                        f.setStateOfFLAGS(flag_int);
                                        f.setLength(real_length);
                                        f.setDestination_MAC(dest_MAC_adress);
                                        f.setSource_MAC(sourc_MAC_adress);

                                        c.setNumber(number);
                                        c.setState("nic");
                                        c.setSource_port(sourcePort);
                                        c.setDestin_port(destination);
                                        c.setSource_adress(IPsource);
                                        c.setDestination_adress(IPdest);
                                        c.getFrames().add(f);
                                        zoznamKomunikacii.add(c);
                                    }
                                }
                            } else { // ide o TFTP komunikaciu 
// najme trace-15 ma TFTP ramce
                                // a vypisujem iba prvu komunikaciu 
                                // TftpPort; 
                                SpecialCommunication = 1;
                                if (specZoznam.isEmpty()) {
                                    Tftp tmpFTP = new Tftp();
                                    tmpFTP.dest_port = destination;
                                    tmpFTP.source_port = sourcePort;
                                    specZoznam.add(tmpFTP);

                                    allComSpecial.append("\nKomunikacia kompletna\n");
                                    allComSpecial.append("\nKlient: " + number[26] + "." + number[27] + "." + number[28] + "." + number[29] + " : " + sourcePort);
                                    allComSpecial.append("      Server: " + number[30] + "." + number[31] + "." + number[32] + "." + number[33] + " : " + destination + "\n");
                                    allComSpecial.append("\nrámec " + count + "\ndĺžka rámca zachyteného paketovým drajverom - " + real_length + " B");
                                    if (real_length < 60) //ak je dlzka mensia potrebujeme minimalne 64 Bytov ktore sa budu prenasat
                                    {
                                        System.out.println("dľžka rámca prenášaného po médiu - 64 B");
                                        allComSpecial.append("\ndľžka rámca prenášaného po médiu - 64 B");
                                    } else { // inak pridame 4 Byte ku skutocnej velkosti
                                        System.out.println("dľžka rámca prenášaného po médiu - " + (real_length + 4) + " B");
                                        allComSpecial.append("\ndľžka rámca prenášaného po médiu - " + (real_length + 4) + " B");
                                    }
                                    allComSpecial.append("\nEthernet II\n");
                                    allComSpecial.append(tmpStr);
                                } else {
                                    for (int j = 0; j < specZoznam.size(); j++) {
                                        if (specZoznam.get(j).dest_port == destination || specZoznam.get(j).source_port == destination
                                                || specZoznam.get(j).dest_port == sourcePort || specZoznam.get(j).source_port == sourcePort) {

                                            System.out.printf("UDP - TFTP\n");
                                            System.out.printf("Klient: " + number[26] + "." + number[27] + "." + number[28] + "." + number[29] + " : " + sourcePort);
                                            System.out.printf("      Server: " + number[30] + "." + number[31] + "." + number[32] + "." + number[33] + " : " + destination);

                                            //allComSpecial.append("\nKomunikacia kompletna\n");
                                            allComSpecial.append("\nKlient: " + number[26] + "." + number[27] + "." + number[28] + "." + number[29] + " : " + sourcePort);
                                            allComSpecial.append("      Server: " + number[30] + "." + number[31] + "." + number[32] + "." + number[33] + " : " + destination + "\n");
                                            allComSpecial.append("\nrámec " + count + "\ndĺžka rámca zachyteného paketovým drajverom - " + real_length + " B");

                                            System.out.println("\nrámec " + count + "\ndĺžka rámca zachyteného paketovým drajverom - " + real_length + " B");
                                            if (real_length < 60) //ak je dlzka mensia potrebujeme minimalne 64 Bytov ktore sa budu prenasat
                                            {
                                                System.out.println("dľžka rámca prenášaného po médiu - 64 B");
                                                allComSpecial.append("\ndľžka rámca prenášaného po médiu - 64 B");
                                            } else { // inak pridame 4 Byte ku skutocnej velkosti
                                                System.out.println("dľžka rámca prenášaného po médiu - " + (real_length + 4) + " B");
                                                allComSpecial.append("\ndľžka rámca prenášaného po médiu - " + (real_length + 4) + " B");
                                            }
                                            System.out.println("\nEthernet II\n");
                                            System.out.println("MAC adresy...........");
                                            allComSpecial.append("\nEthernet II\n");
                                            allComSpecial.append(tmpStr + "\n");
                                            int actLENGTH = real_length;
                                            if (actLENGTH > 0 && actLENGTH <= 19) {
                                                statitistic[0]++;
                                            }
                                            if (actLENGTH >= 20 && actLENGTH <= 39) {
                                                statitistic[1]++;
                                            }
                                            if (actLENGTH >= 40 && actLENGTH <= 79) {
                                                statitistic[2]++;
                                            }
                                            if (actLENGTH >= 80 && actLENGTH <= 159) {
                                                statitistic[3]++;
                                            }
                                            if (actLENGTH >= 160 && actLENGTH <= 319) {
                                                statitistic[4]++;
                                            }
                                            if (actLENGTH >= 320 && actLENGTH <= 639) {
                                                statitistic[5]++;
                                            }
                                            if (actLENGTH >= 640 && actLENGTH <= 1279) {
                                                statitistic[6]++;
                                            }
                                            if (actLENGTH >= 1280 && actLENGTH <= 1539) {
                                                statitistic[7]++;
                                            }
                                        }
                                    }

                                    //System.out.println(tmpStr);
                                }

                            }
                        }
                    }
                } else // IPv4
                //ARP komunikacie
                if (OpenFile.open1(ETH_NET).contains(Network_Protocol)) {
                    //System.out.println("ARP");
                    SpecialCommunication = 1;
                    //if (number[21] a number[22] )
                    char[] operat = new char[4];
                    operat[0] = arrayOfChar[40];
                    operat[1] = arrayOfChar[41];
                    operat[2] = arrayOfChar[42];
                    operat[3] = arrayOfChar[43];
                    String tmpOperat = new String(operat);
                    int Operation = Integer.parseInt(tmpOperat, 16);

                    if (Operation == 1) {
                        for (i = 56; i < 64; i++) {
                            IPsource += str.charAt(i);
                        }
                        for (i = 76; i < 84; i++) {
                            IPdest += str.charAt(i);
                        }
                        int determine = 0;
                        if (zoznamKomunikacii.isEmpty()) {
                            Comunication c = new Comunication();
                            FrameComun f = new FrameComun(tmpStr, count);
                            f.setLength(real_length);
                            f.setDestination_MAC(dest_MAC_adress);
                            f.setSource_MAC(sourc_MAC_adress);

                            c.setNumber(number);
                            c.setState("request");
                            c.setSource_adress(IPsource);
                            c.setDestination_adress(IPdest);
                            zoznamKomunikacii.add(c);
                            zoznamKomunikacii.get(0).getFrames().add(f);

                            System.out.printf("\nARP-Request " + Operation);
                            System.out.printf(" ,IP adresa: " + number[38] + "." + number[39] + "." + number[40] + "." + number[41] + "   ,MAC adresa: ???\n");
                            System.out.println("Zdrojová IP: " + number[28] + "." + number[29] + "." + number[30] + "." + number[31] + "    , Cieľová IP: " + number[38] + "." + number[39] + "." + number[40] + "." + number[41] + "\n");

                            // allComSpecial.append("ARP-Request \n");
                            // allComSpecial.append(" ,IP adresa: " + number[38] + "." + number[39] + "." + number[40] + "." + number[41] + "   ,MAC adresa: ???\n");
                            // allComSpecial.append("Zdrojová IP: " + number[28] + "." + number[29] + "." + number[30] + "." + number[31] + "    , Cieľová IP: " + number[38] + "." + number[39] + "." + number[40] + "." + number[41] + "\n");
                            System.out.println("rámec " + count + "\ndĺžka rámca zachyteného paketovým drajverom - " + real_length + " B");
                            // allComSpecial.append("rámec " + count + "\ndĺžka rámca zachyteného paketovým drajverom - " + real_length + " B\n");
                            if (real_length < 60) //ak je dlzka mensia potrebujeme minimalne 64 Bytov ktore sa budu prenasat
                            {
                                System.out.println("dľžka rámca prenášaného po médiu - 64 B");
                                //     allComSpecial.append("dľžka rámca prenášaného po médiu - 64 B\n");
                            } else { // inak pridame 4 Byte ku skutocnej velkosti
                                System.out.println("dľžka rámca prenášaného po médiu - " + (real_length + 4) + " B");
                                //     allComSpecial.append("dľžka rámca prenášaného po médiu - " + (real_length + 4) + " B\n");
                            }
                            System.out.println("Ethernet II");
                            System.out.println("Zdrojová MAC adresa: " + sourc_MAC_adress);
                            System.out.println("Cieľová MAC adresa: " + dest_MAC_adress + "\n");
                            System.out.println(tmpStr);

                            //   allComSpecial.append("Ethernet II\n");
                            //   allComSpecial.append("Zdrojová MAC adresa: " + sourc_MAC_adress);
                            //   allComSpecial.append("\nCieľová MAC adresa: " + dest_MAC_adress);
                            //   allComSpecial.append(tmpStr);
                        } else {
                            for (i = 0; i < zoznamKomunikacii.size(); i++) {
                                /*if (zoznamKomunikacii.get(i).getDestination_adress() == IPdest || zoznamKomunikacii.get(i).getSource_adress() == IPdest
                                 || zoznamKomunikacii.get(i).getDestination_adress() == IPsource || zoznamKomunikacii.get(i).getSource_adress() == IPsource) {*/
                                /*  FrameComun f = new FrameComun(tmpStr, count);
                                 f.setLength(real_length);
                                 f.setDestination_MAC(dest_MAC_adress);
                                 f.setSource_MAC(sourc_MAC_adress);
                                 zoznamKomunikacii.get(i).getFrames().add(f);
                                 determine++;
                                 */

                                /* allComSpecial.append("\nARP-Request \n");
                                 allComSpecial.append(" ,IP adresa: " + number[38] + "." + number[39] + "." + number[40] + "." + number[41] + "   ,MAC adresa: ???\n");
                                 allComSpecial.append("Zdrojová IP: " + number[28] + "." + number[29] + "." + number[30] + "." + number[31] + "    , Cieľová IP: " + number[38] + "." + number[39] + "." + number[40] + "." + number[41] + "\n");
                                 allComSpecial.append("rámec " + count + "\ndĺžka rámca zachyteného paketovým drajverom - " + real_length + " B\n");
                                 if (real_length < 60) //ak je dlzka mensia potrebujeme minimalne 64 Bytov ktore sa budu prenasat
                                 {
                                 allComSpecial.append("dľžka rámca prenášaného po médiu - 64 B\n");
                                 } else { // inak pridame 4 Byte ku skutocnej velkosti
                                 allComSpecial.append("dľžka rámca prenášaného po médiu - " + (real_length + 4) + " B\n");
                                 }
                                 allComSpecial.append("Ethernet II\n");
                                 allComSpecial.append("Zdrojová MAC adresa: " + sourc_MAC_adress);
                                 allComSpecial.append("\nCieľová MAC adresa: " + dest_MAC_adress);
                                 allComSpecial.append(tmpStr);*/
                                // }
                            }
                            if (determine == 0) {
                                Comunication c = new Comunication();
                                FrameComun f = new FrameComun(tmpStr, count);
                                f.setLength(real_length);
                                f.setDestination_MAC(dest_MAC_adress);
                                f.setSource_MAC(sourc_MAC_adress);

                                c.setNumber(number);
                                c.setState("request");
                                c.setSource_adress(IPsource);
                                c.setDestination_adress(IPdest);
                                c.getFrames().add(f);
                                zoznamKomunikacii.add(c);
                            }
                        }

                    } else if (Operation == 2) {
                        System.out.println("ARP - reply " + Operation);

                        for (i = 56; i < 64; i++) {
                            IPsource += str.charAt(i);
                        }
                        for (i = 76; i < 84; i++) {
                            IPdest += str.charAt(i);
                        }
                        //MAC adresy su zistene z vyssej casti programu
                        for (i = 0; i < zoznamKomunikacii.size(); i++) {
                            if (zoznamKomunikacii.get(i).getDestination_adress().equals(IPsource) && zoznamKomunikacii.get(i).getState().equals("request")) {

                                //pre kazdy ramec...mali by byt iba jeden
                                for (int x = 0; x < zoznamKomunikacii.get(i).getFrames().size(); x++) {
                                    if (zoznamKomunikacii.get(i).getFrames().get(x).getSource_MAC().equals(dest_MAC_adress)) {
                                        allComSpecial.append("\nARP-request");
                                        allComSpecial.append(" ,IP adresa: " + zoznamKomunikacii.get(i).getNumber()[38] + "." + zoznamKomunikacii.get(i).getNumber()[39] + "." + zoznamKomunikacii.get(i).getNumber()[40] + "." + zoznamKomunikacii.get(i).getNumber()[41] + "   ,MAC adresa: ??? " + "\n");
                                        allComSpecial.append("Zdrojová IP: " + zoznamKomunikacii.get(i).getNumber()[28] + "." + zoznamKomunikacii.get(i).getNumber()[29] + "." + zoznamKomunikacii.get(i).getNumber()[30] + "." + zoznamKomunikacii.get(i).getNumber()[31] + "    , Cieľová IP: "
                                                + +zoznamKomunikacii.get(i).getNumber()[38] + "." + zoznamKomunikacii.get(i).getNumber()[39] + "." + zoznamKomunikacii.get(i).getNumber()[40] + "." + zoznamKomunikacii.get(i).getNumber()[41] + "\n");

                                        allComSpecial.append("\nrámec " + zoznamKomunikacii.get(i).getFrames().get(x).getNumberOfFrame() + "\ndĺžka rámca zachyteného paketovým drajverom - " + zoznamKomunikacii.get(i).getFrames().get(x).getLength() + " B\n");
                                        if (zoznamKomunikacii.get(i).getFrames().get(x).getLength() < 60) //ak je dlzka mensia potrebujeme minimalne 64 Bytov ktore sa budu prenasat
                                        {
                                            allComSpecial.append("dľžka rámca prenášaného po médiu - 64 B\n");
                                        } else { // inak pridame 4 Byte ku skutocnej velkosti
                                            allComSpecial.append("dľžka rámca prenášaného po médiu - " + (zoznamKomunikacii.get(i).getFrames().get(x).getLength() + 4) + " B\n");
                                        }
                                        allComSpecial.append("Ethernet II\n");
                                        allComSpecial.append("Zdrojová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getSource_MAC());
                                        allComSpecial.append("\nCieľová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getDestination_MAC() + "\n");
                                        allComSpecial.append(zoznamKomunikacii.get(i).getFrames().get(x).getFrame() + "\n");

                                        //pridanie aktualnych udajov do comunikacie
                                        zoznamKomunikacii.get(i).setState("reply");
                                        FrameComun f = new FrameComun(tmpStr, count);
                                        f.setLength(real_length);
                                        f.setDestination_MAC(dest_MAC_adress);
                                        f.setSource_MAC(sourc_MAC_adress);
                                        zoznamKomunikacii.get(i).getFrames().add(f);

                                        //pre request
                                        int actLENGTH = zoznamKomunikacii.get(i).getFrames().get(x).getLength();
                                        if (actLENGTH > 0 && actLENGTH <= 19) {
                                            statitistic[0]++;
                                        }
                                        if (actLENGTH >= 20 && actLENGTH <= 39) {
                                            statitistic[1]++;
                                        }
                                        if (actLENGTH >= 40 && actLENGTH <= 79) {
                                            statitistic[2]++;
                                        }
                                        if (actLENGTH >= 80 && actLENGTH <= 159) {
                                            statitistic[3]++;
                                        }
                                        if (actLENGTH >= 160 && actLENGTH <= 319) {
                                            statitistic[4]++;
                                        }
                                        if (actLENGTH >= 320 && actLENGTH <= 639) {
                                            statitistic[5]++;
                                        }
                                        if (actLENGTH >= 640 && actLENGTH <= 1279) {
                                            statitistic[6]++;
                                        }
                                        if (actLENGTH >= 1280 && actLENGTH <= 1539) {
                                            statitistic[7]++;
                                        }

                                        //najdeny REPLY
                                        ARP++;
                                        System.out.printf("\nARP-reply ");
                                        System.out.printf(" ,IP adresa: " + number[38] + "." + number[39] + "." + number[40] + "." + number[41] + "   ,MAC adresa: " + sourc_MAC_adress + "\n");
                                        System.out.println("Zdrojová IP: " + number[28] + "." + number[29] + "." + number[30] + "." + number[31] + "    , Cieľová IP: " + number[38] + "." + number[39] + "." + number[40] + "." + number[41] + "\n");

                                        allComSpecial.append("\nARP-reply " + Operation);
                                        allComSpecial.append(" ,IP adresa: " + number[38] + "." + number[39] + "." + number[40] + "." + number[41] + "   ,MAC adresa: " + sourc_MAC_adress + "\n");
                                        allComSpecial.append("Zdrojová IP: " + number[28] + "." + number[29] + "." + number[30] + "." + number[31] + "    , Cieľová IP: " + number[38] + "." + number[39] + "." + number[40] + "." + number[41] + "\n");

                                        System.out.println("rámec " + count + "\ndĺžka rámca zachyteného paketovým drajverom - " + real_length + " B");
                                        allComSpecial.append("\nrámec " + count + "\ndĺžka rámca zachyteného paketovým drajverom - " + real_length + " B\n");
                                        if (real_length < 60) //ak je dlzka mensia potrebujeme minimalne 64 Bytov ktore sa budu prenasat
                                        {
                                            System.out.println("dľžka rámca prenášaného po médiu - 64 B");
                                            allComSpecial.append("dľžka rámca prenášaného po médiu - 64 B\n");
                                        } else { // inak pridame 4 Byte ku skutocnej velkosti
                                            System.out.println("dľžka rámca prenášaného po médiu - " + (real_length + 4) + " B");
                                            allComSpecial.append("dľžka rámca prenášaného po médiu - " + (real_length + 4) + " B\n");
                                        }
                                        System.out.println("Ethernet II");
                                        allComSpecial.append("Ethernet II\n");
                                        allComSpecial.append("Zdrojová MAC adresa: " + sourc_MAC_adress);
                                        allComSpecial.append("\nCieľová MAC adresa: " + dest_MAC_adress + "\n");
                                        allComSpecial.append(tmpStr + "\n");

                                        //pre reply
                                        actLENGTH = real_length;
                                        if (actLENGTH > 0 && actLENGTH <= 19) {
                                            statitistic[0]++;
                                        }
                                        if (actLENGTH >= 20 && actLENGTH <= 39) {
                                            statitistic[1]++;
                                        }
                                        if (actLENGTH >= 40 && actLENGTH <= 79) {
                                            statitistic[2]++;
                                        }
                                        if (actLENGTH >= 80 && actLENGTH <= 159) {
                                            statitistic[3]++;
                                        }
                                        if (actLENGTH >= 160 && actLENGTH <= 319) {
                                            statitistic[4]++;
                                        }
                                        if (actLENGTH >= 320 && actLENGTH <= 639) {
                                            statitistic[5]++;
                                        }
                                        if (actLENGTH >= 640 && actLENGTH <= 1279) {
                                            statitistic[6]++;
                                        }
                                        if (actLENGTH >= 1280 && actLENGTH <= 1539) {
                                            statitistic[7]++;
                                        }
                                    }
                                    // nenasiel reply a request dvojicu

                                }
                            }
                        }
                    }
                }
            }

            //ulozi vsetky udaje do zoznamu ramcov          
            Frame frame = new Frame();
            frame.setStringOfFrame(tmpStr);
            frame.setNumberOfFrame(count);
            frame.setLengthOfFrame(real_length); // bez 4 bajtov
            frame.setDestination_MAC(dest_MAC_adress);
            frame.setSource_MAC(sourc_MAC_adress);
            frame.setType(typeOfFrame);
            frame.setDestination_IP(IP_address_destion);
            frame.setSource_IP(IP_address_source);
            frame.getRm().add(frame);

            frame.setDestinationPort(destinationPort);
            frame.setSourcePort(sourcePort);
            

            zoznamRamcov.add(frame);

            count++; // dalsi ramec bude o jedna vacsii
            number_of_frame = count;

        } //WHILE END

        pcap.close(); //zatvorenie .pcap suboru

        com = allComSpecial;
//------------------------------------------------------------------------------------------------------------zatvorenie suborov a koniec while

        /*  int maxValue = 0;
         String maxIp = null;
         System.out.println("IP adresy vysielajucich uzlov: ");
         for (int i = 0; i < number_of_frame - 1; i++) {
         if (!(zoznamRamcov.get(i).getSource_IP().equals("_"))) {

         if (zoznamRamcov.get(i).getLengthOfFrame() > maxValue) {
         maxValue = zoznamRamcov.get(i).getLengthOfFrame();
         maxIp = zoznamRamcov.get(i).getSource_IP();
         }

         String tmp = new String(zoznamRamcov.get(i).getSource_IP());
         System.out.println(tmp);
         }
         }
         System.out.println("Adresa uzla s najäčším počtom odvysielaných bajtov: ");
         System.out.println(maxIp + "    " + maxValue + " bajtov");
         System.out.println("--------------------------------------\n");*/
        //-------------------------------------------------------------------------------------------------------------------
        //zistenie komunikacie
        if (SpecialCommunication == 0) {

            int a = 1;
            for (int i = 0; i < zoznamKomunikacii.size(); i++) {
                for (int x = 0; x < zoznamKomunikacii.get(i).getFrames().size(); x++) {
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 4 && (a == 6 || a == 5)) { // FIN ACK 
                        a = 7;
                    }
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 1) { // SYN
                        a = 2;
                    }
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 2 && a == 2) { // SYN ACK
                        a = 3;
                    }
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 3 && a == 3) { // ACK
                        a = 4;
                    }
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 4 && a == 4) { // FIN ACK
                        a = 5;
                    }
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 3 && a == 5) { // ACK
                        a = 6;
                    }
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 5 && a == 6) { // FIN
                        a = 7;
                    }
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 6 && (a == 4 || a == 5 || a == 6)) {
                        a = 10; // ak nastala chyba pojde o nekompletnu komunikaciu
                        zoznamKomunikacii.get(i).setState("nieje");
                    }
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 3 && a == 7) { // ACK
                        zoznamKomunikacii.get(i).setState("kompletna");
                    }

                }
            }
            a = 4;
            for (int i = 0; i < zoznamKomunikacii.size(); i++) {
                for (int x = 0; x < zoznamKomunikacii.get(i).getFrames().size(); x++) {
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 6 && zoznamKomunikacii.get(i).getState().equals("kompletna") != true && zoznamKomunikacii.get(i).getState().equals("nieje") != true) {
                        zoznamKomunikacii.get(i).setState("nekompletna"); // v pripade ze ukocenie nebolo spravne uz od zaciatku
                    }
                    if (zoznamKomunikacii.get(i).getState().equals("nic")) {
                        if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 4 && (a == 6 || a == 5)) { // FIN, ACK
                            a = 7;
                        }
                        if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 4 && a == 4) { // FIN ACK
                            a = 5;
                        }
                        if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 3 && a == 5) { // ACK
                            a = 6;
                        }
                        if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 5 && a == 6) { // FIN
                            a = 7;
                        }
                        if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 3 && a == 7) { // ACK
                            zoznamKomunikacii.get(i).setState("nekompletna");
                        }
                    }
                }
            }
            //POMOCNY VYPIS        
                     /*
             for (int i = 0; i < zoznamKomunikacii.size(); i++) {
             if (zoznamKomunikacii.get(i).getState().equals("nekompletna")) {
             System.out.println(zoznamKomunikacii.get(i).getState());
             for (int x = 0; x < zoznamKomunikacii.get(i).getFrames().size(); x++) {
             System.out.println("ramec: " + zoznamKomunikacii.get(i).getFrames().get(x).getNumberOfFrame() + "Flag: " + 
             zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS());
             System.out.println(zoznamKomunikacii.get(i).getFrames().get(x).getFrame());
             }   
             }
             }
             */
// REALNY VYPIS PRE KOMUNIKACIE TCP protokolu
            // a ich zapamatanie do StringBuilderu, ktory sa posiela dalej
            StringBuilder allCom = new StringBuilder();
            String typOfProtocol = new String(Transport_Protocol); // v prvom pripade

            for (int i = 0; i < zoznamKomunikacii.size(); i++) {
                if (zoznamKomunikacii.get(i).getState().equals("nekompletna") || zoznamKomunikacii.get(i).getState().equals("nic")) {
                    for (int x = 0; x < zoznamKomunikacii.get(i).getFrames().size(); x++) {
                        if (zoznamKomunikacii.get(i).getFrames().size() > 20) {

                            System.out.printf("Komunikacia 1. nekompletna\n");

                            if (x == 0) {

                                //    System.out.printf("Klient: " + zoznamKomunikacii.get(i).getNumber()[26] + "." + zoznamKomunikacii.get(i).getNumber()[27] + "." + zoznamKomunikacii.get(i).getNumber()[28] + "." + zoznamKomunikacii.get(i).getNumber()[29] + " : " + zoznamKomunikacii.get(i).getSource_port() + "  ");
                                //    System.out.printf("Server: " + zoznamKomunikacii.get(i).getNumber()[30] + "." + zoznamKomunikacii.get(i).getNumber()[31] + "." + zoznamKomunikacii.get(i).getNumber()[32] + "." + zoznamKomunikacii.get(i).getNumber()[33] + " : " + typOfProtocol + "(" + zoznamKomunikacii.get(i).getDestin_port() + ") \n");
                                allCom.append("Komunikacia 1. nekompletna\n");
                                allCom.append("Klient: " + zoznamKomunikacii.get(i).getNumber()[26] + "." + zoznamKomunikacii.get(i).getNumber()[27] + "." + zoznamKomunikacii.get(i).getNumber()[28] + "." + zoznamKomunikacii.get(i).getNumber()[29] + " : " + zoznamKomunikacii.get(i).getSource_port() + "     ");
                                allCom.append("Server: " + zoznamKomunikacii.get(i).getNumber()[30] + "." + zoznamKomunikacii.get(i).getNumber()[31] + "." + zoznamKomunikacii.get(i).getNumber()[32] + "." + zoznamKomunikacii.get(i).getNumber()[33] + " : " + typOfProtocol + "(" + zoznamKomunikacii.get(i).getDestin_port() + ") \n");
                            }

                            System.out.println("\nrámec: " + zoznamKomunikacii.get(i).getFrames().get(x).getNumberOfFrame() + "\ndlžka rámca zachyteného paketovým drajverom - " + zoznamKomunikacii.get(i).getFrames().get(x).getLength() + " B");
                            allCom.append("\nrámec: " + zoznamKomunikacii.get(i).getFrames().get(x).getNumberOfFrame() + "\ndlžka rámca zachyteného paketovým drajverom - " + zoznamKomunikacii.get(i).getFrames().get(x).getLength() + " B\n");
                            if (zoznamKomunikacii.get(i).getFrames().get(x).getLength() + 4 > 64) {
                                System.out.println("dlžka rámca prenášaného po médiu - " + (zoznamKomunikacii.get(i).getFrames().get(x).getLength() + 4) + " B");
                                allCom.append("dlžka rámca prenášaného po médiu - " + (zoznamKomunikacii.get(i).getFrames().get(x).getLength() + 4) + " B\n");
                            } else {
                                System.out.println("dlžka rámca prenášaného po médiu - 64 B");
                                allCom.append("dlžka rámca prenášaného po médiu - 64 B\n");
                            }
                            System.out.println("Ethernet II ");
                            System.out.println("Zdrojová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getSource_MAC());
                            System.out.println("Cieľová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getDestination_MAC());
                            System.out.println(zoznamKomunikacii.get(i).getFrames().get(x).getFrame());

                            allCom.append("Ethernet II \n" + "Zdrojová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getSource_MAC());
                            allCom.append("\nCieľová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getDestination_MAC() + "\n");
                            allCom.append(zoznamKomunikacii.get(i).getFrames().get(x).getFrame() + "\n");
                            if (x == 9) {
                                x = zoznamKomunikacii.get(i).getFrames().size() - 10;
                            }
                        } else {

                            System.out.println("Komunikacia nekompletna");

                            if (x == 0) {
                                //   System.out.printf("Klient: " + zoznamKomunikacii.get(i).getNumber()[26] + "." + zoznamKomunikacii.get(i).getNumber()[27] + "." + zoznamKomunikacii.get(i).getNumber()[28] + "." + zoznamKomunikacii.get(i).getNumber()[29] + " : " + zoznamKomunikacii.get(i).getSource_port() + "  ");
                                //   System.out.printf("Server: " + zoznamKomunikacii.get(i).getNumber()[30] + "." + zoznamKomunikacii.get(i).getNumber()[31] + "." + zoznamKomunikacii.get(i).getNumber()[32] + "." + zoznamKomunikacii.get(i).getNumber()[33] + " : " + typOfProtocol + "(" + zoznamKomunikacii.get(i).getDestin_port() + ") \n");

                                allCom.append("Komunikacia nekompletna\n");
                                allCom.append("Klient: " + zoznamKomunikacii.get(i).getNumber()[26] + "." + zoznamKomunikacii.get(i).getNumber()[27] + "." + zoznamKomunikacii.get(i).getNumber()[28] + "." + zoznamKomunikacii.get(i).getNumber()[29] + " : " + zoznamKomunikacii.get(i).getSource_port() + "    ");
                                allCom.append("Server: " + zoznamKomunikacii.get(i).getNumber()[30] + "." + zoznamKomunikacii.get(i).getNumber()[31] + "." + zoznamKomunikacii.get(i).getNumber()[32] + "." + zoznamKomunikacii.get(i).getNumber()[33] + " : " + typOfProtocol + "(" + zoznamKomunikacii.get(i).getDestin_port() + ") \n");

                            }
                            System.out.println("\nrámec: " + zoznamKomunikacii.get(i).getFrames().get(x).getNumberOfFrame() + "\ndlžka rámca zachyteného paketovým drajverom - " + zoznamKomunikacii.get(i).getFrames().get(x).getLength() + " B");
                            allCom.append("\nrámec: " + zoznamKomunikacii.get(i).getFrames().get(x).getNumberOfFrame() + "\ndlžka rámca zachyteného paketovým drajverom - " + zoznamKomunikacii.get(i).getFrames().get(x).getLength() + " B\n");
                            if (zoznamKomunikacii.get(i).getFrames().get(x).getLength() + 4 > 64) {
                                System.out.println("dlžka rámca prenášaného po médiu - " + (zoznamKomunikacii.get(i).getFrames().get(x).getLength() + 4) + " B");
                                allCom.append("dlžka rámca prenášaného po médiu - " + (zoznamKomunikacii.get(i).getFrames().get(x).getLength() + 4) + " B\n");
                            } else {
                                System.out.println("dlžka rámca prenášaného po médiu - 64 B");
                                allCom.append("dlžka rámca prenášaného po médiu - 64 B\n");
                            }
                            System.out.println("Ethernet II ");
                            System.out.println("Zdrojová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getSource_MAC());
                            System.out.println("Cieľová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getDestination_MAC());
                            System.out.println(zoznamKomunikacii.get(i).getFrames().get(x).getFrame());

                            allCom.append("Ethernet II \n" + "Zdrojová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getSource_MAC());
                            allCom.append("\nCieľová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getDestination_MAC() + "\n");
                            allCom.append(zoznamKomunikacii.get(i).getFrames().get(x).getFrame() + "\n");
                        }
                    }
                    i = zoznamKomunikacii.size();
                }
            }

            int r = 1; //vypise prvu kompletnu komunikaciu ktoru najde. r==1 tiez mozeme menit
            for (int i = 0; i < zoznamKomunikacii.size(); i++) {
                if (zoznamKomunikacii.get(i).getState().equals("kompletna")) {
                    if (r == 1) {

                        for (int x = 0; x < zoznamKomunikacii.get(i).getFrames().size(); x++) {
                            if (zoznamKomunikacii.get(i).getFrames().size() > 20) {

                                System.out.println("Komunikácia 1. kompletná");

                                if (x == 0) {
                                    System.out.printf("Klient: " + zoznamKomunikacii.get(i).getNumber()[26] + "." + zoznamKomunikacii.get(i).getNumber()[27] + "." + zoznamKomunikacii.get(i).getNumber()[28] + "." + zoznamKomunikacii.get(i).getNumber()[29] + " : " + zoznamKomunikacii.get(i).getSource_port() + "  ");
                                    System.out.printf("Server: " + zoznamKomunikacii.get(i).getNumber()[30] + "." + zoznamKomunikacii.get(i).getNumber()[31] + "." + zoznamKomunikacii.get(i).getNumber()[32] + "." + zoznamKomunikacii.get(i).getNumber()[33] + " : " + "http(" + zoznamKomunikacii.get(i).getDestin_port() + ") \n");

                                    allCom.append("\n-------------------------------------------------------------------------------------------------");
                                    allCom.append("\nKomunikácia 1. kompletná\n");
                                    allCom.append("Klient: " + zoznamKomunikacii.get(i).getNumber()[26] + "." + zoznamKomunikacii.get(i).getNumber()[27] + "." + zoznamKomunikacii.get(i).getNumber()[28] + "." + zoznamKomunikacii.get(i).getNumber()[29] + " : " + zoznamKomunikacii.get(i).getSource_port() + "    ");
                                    allCom.append("Server: " + zoznamKomunikacii.get(i).getNumber()[30] + "." + zoznamKomunikacii.get(i).getNumber()[31] + "." + zoznamKomunikacii.get(i).getNumber()[32] + "." + zoznamKomunikacii.get(i).getNumber()[33] + " : " + typOfProtocol + "(" + zoznamKomunikacii.get(i).getDestin_port() + ") \n");
                                }

                                System.out.println("\nrámec: " + zoznamKomunikacii.get(i).getFrames().get(x).getNumberOfFrame() + "\ndlžka rámca zachyteného paketovým drajverom - " + zoznamKomunikacii.get(i).getFrames().get(x).getLength() + " B");
                                allCom.append("\nrámec: " + zoznamKomunikacii.get(i).getFrames().get(x).getNumberOfFrame() + "\ndlžka rámca zachyteného paketovým drajverom - " + zoznamKomunikacii.get(i).getFrames().get(x).getLength() + " B\n");
                                if (zoznamKomunikacii.get(i).getFrames().get(x).getLength() + 4 > 64) {
                                    System.out.println("dlžka rámca prenášaného po médiu - " + (zoznamKomunikacii.get(i).getFrames().get(x).getLength() + 4) + " B");
                                    allCom.append("dlžka rámca prenášaného po médiu - " + (zoznamKomunikacii.get(i).getFrames().get(x).getLength() + 4) + " B\n");
                                } else {
                                    System.out.println("dlžka rámca prenášaného po médiu - 64 B");
                                    allCom.append("dlžka rámca prenášaného po médiu - 64 B\n");
                                }
                                System.out.println("Ethernet II ");
                                System.out.println("Zdrojová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getSource_MAC());
                                System.out.println("Cieľová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getDestination_MAC());
                                System.out.println(zoznamKomunikacii.get(i).getFrames().get(x).getFrame());

                                allCom.append("Ethernet II \n" + "Zdrojová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getSource_MAC());
                                allCom.append("\nCieľová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getDestination_MAC() + "\n");
                                allCom.append(zoznamKomunikacii.get(i).getFrames().get(x).getFrame() + "\n");

                                if (x == 9) {
                                    x = zoznamKomunikacii.get(i).getFrames().size() - 11;
                                }
                            } else {

                                System.out.println("Komunikácia 1. kompletná");

                                if (x == 0) {
                                    System.out.printf("Klient: " + zoznamKomunikacii.get(i).getNumber()[26] + "." + zoznamKomunikacii.get(i).getNumber()[27] + "." + zoznamKomunikacii.get(i).getNumber()[28] + "." + zoznamKomunikacii.get(i).getNumber()[29] + " : " + zoznamKomunikacii.get(i).getSource_port() + "  ");
                                    System.out.printf("Server: " + zoznamKomunikacii.get(i).getNumber()[30] + "." + zoznamKomunikacii.get(i).getNumber()[31] + "." + zoznamKomunikacii.get(i).getNumber()[32] + "." + zoznamKomunikacii.get(i).getNumber()[33] + " : " + "http(" + zoznamKomunikacii.get(i).getDestin_port() + ") \n");

                                    allCom.append("\n-------------------------------------------------------------------------------------------------");
                                    allCom.append("\nKomunikácia 1. kompletná\n");
                                    allCom.append("Klient: " + zoznamKomunikacii.get(i).getNumber()[26] + "." + zoznamKomunikacii.get(i).getNumber()[27] + "." + zoznamKomunikacii.get(i).getNumber()[28] + "." + zoznamKomunikacii.get(i).getNumber()[29] + " : " + zoznamKomunikacii.get(i).getSource_port() + "   ");
                                    allCom.append("Server: " + zoznamKomunikacii.get(i).getNumber()[30] + "." + zoznamKomunikacii.get(i).getNumber()[31] + "." + zoznamKomunikacii.get(i).getNumber()[32] + "." + zoznamKomunikacii.get(i).getNumber()[33] + " : " + typOfProtocol + "(" + zoznamKomunikacii.get(i).getDestin_port() + ") \n");

                                }
                                System.out.println("\nrámec: " + zoznamKomunikacii.get(i).getFrames().get(x).getNumberOfFrame() + "\ndlžka rámca zachyteného paketovým drajverom - " + zoznamKomunikacii.get(i).getFrames().get(x).getLength() + " B");
                                allCom.append("\nrámec: " + zoznamKomunikacii.get(i).getFrames().get(x).getNumberOfFrame() + "\ndlžka rámca zachyteného paketovým drajverom - " + zoznamKomunikacii.get(i).getFrames().get(x).getLength() + " B\n");
                                if (zoznamKomunikacii.get(i).getFrames().get(x).getLength() + 4 > 64) {
                                    System.out.println("dlžka rámca prenášaného po médiu - " + (zoznamKomunikacii.get(i).getFrames().get(x).getLength() + 4) + " B");
                                    allCom.append("dlžka rámca prenášaného po médiu - " + (zoznamKomunikacii.get(i).getFrames().get(x).getLength() + 4) + " B\n");
                                } else {
                                    System.out.println("dlžka rámca prenášaného po médiu - 64 B");
                                    allCom.append("dlžka rámca prenášaného po médiu - 64 B\n");
                                }
                                System.out.println("Ethernet II ");
                                System.out.println("Zdrojová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getSource_MAC());
                                System.out.println("Cieľová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getDestination_MAC());
                                System.out.println(zoznamKomunikacii.get(i).getFrames().get(x).getFrame());

                                allCom.append("Ethernet II \n" + "Zdrojová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getSource_MAC());
                                allCom.append("\nCieľová MAC adresa: " + zoznamKomunikacii.get(i).getFrames().get(x).getDestination_MAC() + "\n");
                                allCom.append(zoznamKomunikacii.get(i).getFrames().get(x).getFrame() + "\n");
                            }
                            int actLENGTH = zoznamKomunikacii.get(i).getFrames().get(x).getLength();
                            if (actLENGTH > 0 && actLENGTH <= 19) {
                                statitistic[0]++;
                            }
                            if (actLENGTH >= 20 && actLENGTH <= 39) {
                                statitistic[1]++;
                            }
                            if (actLENGTH >= 40 && actLENGTH <= 79) {
                                statitistic[2]++;
                            }
                            if (actLENGTH >= 80 && actLENGTH <= 159) {
                                statitistic[3]++;
                            }
                            if (actLENGTH >= 160 && actLENGTH <= 319) {
                                statitistic[4]++;
                            }
                            if (actLENGTH >= 320 && actLENGTH <= 639) {
                                statitistic[5]++;
                            }
                            if (actLENGTH >= 640 && actLENGTH <= 1279) {
                                statitistic[6]++;
                            }
                            if (actLENGTH >= 1280 && actLENGTH <= 1539) {
                                statitistic[7]++;
                            }

                        }
                        i = zoznamKomunikacii.size();
                    }
                    r++;
                }
            }
            if (SpecialCommunication == 0) {
                com = allCom; // prepise vsetky komunikacie sem 
            } else {
                com = allComSpecial;
            }
            //----------------------------------------------------------------------------------------------------------------------------------------------
// dodatok
            int g = 1;
            for (int i = 0; i < zoznamKomunikacii.size(); i++) {
                for (int x = 0; x < zoznamKomunikacii.get(i).getFrames().size(); x++) {
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 4 && (g == 6 || g == 5)) //FIN ACK		
                    {
                        g = 7;
                    }
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 1) //SYN
                    {
                        g = 2;
                    }
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 2 && g == 2) //SYN ACK			
                    {
                        g = 3;
                    }
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 3 && g == 3) //ACK
                    {
                        g = 4;
                    }
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 4 && g == 4) //FIN ACK			
                    {
                        g = 5;
                    }
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 3 && g == 5) //ACK			
                    {
                        g = 6;
                    }
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 5 && g == 6) //FIN			
                    {
                        g = 7;
                    }
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 6 && (g == 4 || g == 5 || g == 6)) {
                        zoznamKomunikacii.get(i).setState("nieje");
                        g = 10;
                    }
                    if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 3 && g == 7) //ACK			
                    {
                        zoznamKomunikacii.get(i).setState("kompletna");
                    }
                }
            }

            g = 4;

            for (int i = 0; i < zoznamKomunikacii.size(); i++) {
                for (int x = 0; x < zoznamKomunikacii.get(i).getFrames().size(); x++) {
                    if (zoznamKomunikacii.get(i).getState().equals("nic")) {
                        if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 4 && (g == 6 || g == 5)) //FIN ACK		
                        {
                            g = 7;
                        }
                        if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 4 && g == 4) //FIN ACK			
                        {
                            g = 5;
                        }
                        if (zoznamKomunikacii.get(i).getFrames().get(x).getStateOfFLAGS() == 3 && g == 7) //ACK			
                        {
                            zoznamKomunikacii.get(i).setState("nekompletnakoniec");
                        }
                    }
                }
            }
        } // Special komunikacia

    }

    // pomocne funkcie
//--------------------------------------------------------------------------------------------------------------------------------------------
// prepis na Hexa sustavu
    protected String bytelistToHEXString(List<Byte> byteList) {
        StringBuilder sb = new StringBuilder();
        for (Iterator<Byte> it = byteList.iterator(); it.hasNext();) {
            byte b = it.next();
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    //funkcia na vlozenie medzier do vypisu
    @SuppressWarnings("SuspiciousIndentAfterControlStatement")
    protected StringBuilder giveSpaceBetweenChar(String tmp) {
        int medzera = 0;
        int novyRiadok = 0;
        StringBuilder tmpStr = new StringBuilder(tmp);

        for (int j = 0; j < tmpStr.length(); j++) {

            if (1 == j % 3 && (novyRiadok != 0)) { // za kazdy druhy vloz medzeru
                tmpStr.insert(j + 1, ' ');
                medzera++;

            } else // 31 + 15
            if (medzera == 17) {
                medzera = 0;
                if (j + 3 < tmpStr.length()) { // pri konretnych paketoch mozne prekrocenie 
                    tmpStr.insert(j + 3, '\n');
                    novyRiadok = 2;
                }
            }
            if (medzera == 8) {
                tmpStr.insert(j + 1, "  ");
                medzera++;
            }
            novyRiadok--;
        }
        return tmpStr;
    }

    public String VypisKonkretnyRamec(int i) {
        String tmp = new String(zoznamRamcov.get(i).getStringOfFrame());
        int length = zoznamRamcov.get(i).getLengthOfFrame();
        int real_length = (length > 60) ? length + 4 : 64;

        tmp = "\nrámec " + zoznamRamcov.get(i).getNumberOfFrame()
                + "\ndĺžka rámca zachyteného paketovým drajverom - " + length + " B"
                + "\ndľžka rámca prenášaného po médiu - " + real_length + " B\n"
                + zoznamRamcov.get(i).getType() + "\n"
                + "Zdrojová MAC adresa: " + zoznamRamcov.get(i).getSource_MAC()
                + "\nCieľová MAC adresa: " + zoznamRamcov.get(i).getDestination_MAC()
                + "\n"
                + tmp;
        return tmp;
    }

    public int GetNumbersRamceSudajmi() {
        return number_of_frame;
    }

    public String GetIpAdress() {
        List<String> list = new ArrayList<String>();

        for (int i = 0; i < number_of_frame - 1; i++) {
            if (!(zoznamRamcov.get(i).getSource_IP().equals("_"))) {
                list.add(zoznamRamcov.get(i).getSource_IP() + "\n");
            }
        }
        List<String> newList = new ArrayList<String>(new HashSet<String>(list)); // hash table sa postara o uniq

        String tmp = new String();
        for (int i = 0; i < newList.size(); i++) {

            tmp = tmp + newList.get(i);
        }
        return tmp;
    }
//zistovat dohromady nie postupne

    public String getMaxIp() {
        int maxValue = 0;
        String maxIp = new String();

        class max {

            String IP;
            int value;
        }
        @SuppressWarnings("Convert2Diamond")
        ArrayList<max> tmp = new ArrayList<max>();

        for (int i = 0; i < number_of_frame - 1; i++) {
            if (!(zoznamRamcov.get(i).getSource_IP().equals("_"))) {
                int check = 0;
                if (tmp.isEmpty()) {
                    max temporary = new max();
                    temporary.IP = zoznamRamcov.get(i).getSource_IP();
                    temporary.value = zoznamRamcov.get(i).getLengthOfFrame();
                    tmp.add(temporary);
                }
                for (int j = 0; j < tmp.size(); j++) { //kontrola zhodnosti Ip adresy, teda ci uz hladanu adresu nasiel
                    if (zoznamRamcov.get(i).getSource_IP().equals(tmp.get(j).IP)) {
                        tmp.get(j).value += zoznamRamcov.get(i).getLengthOfFrame();
                        check++;
                    }
                }
                if (check == 0) {
                    max temporary = new max();
                    temporary.IP = zoznamRamcov.get(i).getSource_IP();
                    temporary.value = zoznamRamcov.get(i).getLengthOfFrame();
                    tmp.add(temporary);
                }
                // tmp.get(j).value += zoznamRamcov.get(i).getLengthOfFrame();
            }
        }
        //najde najvacsiu zo vsetkych
        for (int i = 0; i < tmp.size(); i++) {
            if (tmp.get(i).value > maxValue) {
                maxValue = tmp.get(i).value;
                maxIp = tmp.get(i).IP;
            }
        }
        String temp = (maxIp + "    " + maxValue + " bajtov");
        return temp;
    }

    public void FreeMemory() {
        zoznamRamcov.removeAll(zoznamRamcov);
        if (!(zoznamKomunikacii.isEmpty())) {
            zoznamKomunikacii.removeAll(zoznamKomunikacii);
        }
    }

    //funkcia na vyhladanie komunikacie medzi TCP portami, v konkretnych protokoloch
    // HTTP, HTTPS , TELNET, SSH, FTP-riadiaci , FTP - datovu
    // dostane jednu z tychto moznosti ak sa nachadza v subore z danou hodnotu spracuje a vypise vysledok vyhladanej komunikacie
    public StringBuilder DetectCommunicationPorts() {
        //plus statistika
        StringBuilder tmp = new StringBuilder(com);
        // kontrola vypisu, ak vsetky 0 nenasiel komunikaciu
        int sucet = 0;
        for (int k = 0; k < 8; k++) {
            sucet += statitistic[k];
        }
        if (sucet != 0) {
            com.append("\nŠtatistika dĺžky rámcov v bajtoch: \n0 - 19      " + statitistic[0]);
            com.append("\n20 - 39     " + statitistic[1]);
            com.append("\n40 - 79     " + statitistic[2]);
            com.append("\n80 - 159    " + statitistic[3]);
            com.append("\n160 - 319   " + statitistic[4]);
            com.append("\n320 - 639   " + statitistic[5]);
            com.append("\n640 - 1279  " + statitistic[6]);
            com.append("\n1280 - 1539 " + statitistic[7]);
        } else {
            return com;
        }
        return com;
    } //koniec celej funkcie na spracovanie comunikacii

    
    
    
/// DOIMPLEMTOVANE-----------------------------------------------------------------------------------------------------
    public int PocetSpecialRamcov(int x) {
        int count = 0;
        for (int i = 0; i < number_of_frame - 1; i++) {
            if (zoznamRamcov.get(i).getDestinationPort() == x || zoznamRamcov.get(i).getSourcePort() == x) {
                count++;
            }
        }
        return count;
    }
    
    public String SpecialneRamce(int x) {
        String allFrames = new String();
        String tempFrame = new String();
        for (int i = 0; i < number_of_frame - 1; i++) {
            if (zoznamRamcov.get(i).getDestinationPort() == x || zoznamRamcov.get(i).getSourcePort() == x ) {
                String tmp = new String(zoznamRamcov.get(i).getStringOfFrame());
                int length = zoznamRamcov.get(i).getLengthOfFrame();
                int real_length = (length > 60) ? length + 4 : 64;

                tempFrame = "\nrámec " + zoznamRamcov.get(i).getNumberOfFrame()
                        + "\ndĺžka rámca zachyteného paketovým drajverom - " + length + " B"
                        + "\ndľžka rámca prenášaného po médiu - " + real_length + " B\n"
                        + zoznamRamcov.get(i).getType() + "\n"
                        + "Zdrojová MAC adresa: " + zoznamRamcov.get(i).getSource_MAC()
                        + "\nCieľová MAC adresa: " + zoznamRamcov.get(i).getDestination_MAC()
                        + "\n"
                        + tmp + "\n";
                
                allFrames += tempFrame;
            }
        }
        return allFrames;
    }   
}