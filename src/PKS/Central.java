package PKS;

/**
 * @author Michal
 * @version 1.0
 * @since 16.3.2015
 */
import GUI.Analyzer;

public class Central {

    public static void main(String[] args) {

        //testovany subor v console 
        final String fileName = "vzorky_pcap_na_analyzu\\trace-1.pcap";
        // ScanAllFrame first = new ScanAllFrame(fileName,-1);

        // graficke rozhranie
        new Analyzer().setVisible(true);
    }
}
