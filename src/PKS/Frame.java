package PKS;

import java.util.ArrayList;

/**
 *
 * @author Michal
 */
public class Frame {

    ArrayList<Frame> rm = new ArrayList<Frame>();

    private StringBuilder frame; // text celeho ramca
    private int number_of_frame; // cislo ramca
    private int length_of_frame; // dlzka ramca
    private String type;         // typ ramca   
    private String Destination_MAC;
    private String Source_MAC;
    
    private String Source_IP;
    private String Destination_IP;
    
    
//DOROBENE
    private int SourcePort;
    private int DestinationPort;
    
    
    public int getSourcePort() {
        return SourcePort;
    }

    public void setSourcePort(int SourcePort) {
        this.SourcePort = SourcePort;
    }

    public int getDestinationPort() {
        return DestinationPort;
    }

    public void setDestinationPort(int DestinationPort) {
        this.DestinationPort = DestinationPort;
    }
    

   
    
    public String getSource_IP() {
        return Source_IP;
    }

    public void setSource_IP(String Source_IP) {
        this.Source_IP = Source_IP;
    }

    public String getDestination_IP() {
        return Destination_IP;
    }

    public void setDestination_IP(String Destination_IP) {
        this.Destination_IP = Destination_IP;
    }
    

    public void setType(String type) {
        this.type = type;
    }

    public void setDestination_MAC(String Destination_MAC) {
        this.Destination_MAC = Destination_MAC;
    }

    public void setSource_MAC(String Source_MAC) {
        this.Source_MAC = Source_MAC;
    }

    public String getType() {
        return type;
    }

    public String getDestination_MAC() {
        return Destination_MAC;
    }

    public String getSource_MAC() {
        return Source_MAC;
    }

    public int getNumberOfFrame() { //vrat cislo ramca
        return number_of_frame;
    }

    public void setNumberOfFrame(int number) { // nastav cislo ramca(poradie)
        this.number_of_frame = number;
    }

    public StringBuilder getStringOfFrame() { //vrat cely ramec
        return frame;
    }

    public void setStringOfFrame(StringBuilder frame) { // nastav String 
        this.frame = frame;
    }

    public int getLengthOfFrame() { //vrat dlzku ramca
        return length_of_frame;
    }

    public void setLengthOfFrame(int length) { // nastav dlzku ramca
        this.length_of_frame = length;
    }

    public ArrayList<Frame> getRm() {
        return rm;
    }

    public void setRm(ArrayList<Frame> rm) {
        this.rm = rm;
    }
}
