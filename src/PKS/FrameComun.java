package PKS;

/**
 *
 * @author Michal
 */
public class FrameComun {
    
    FrameComun (StringBuilder frame, int number) {
        this.numberOfFrame = number;
        this.frame = frame;
    }
    
    private int numberOfFrame;
    private StringBuilder frame;
    private int StateOfFLAGS;
    private int length;
    
    private String Destination_MAC;
    private String Source_MAC;
  
     public void setDestination_MAC(String Destination_MAC) {
        this.Destination_MAC = Destination_MAC;
    }

    public void setSource_MAC(String Source_MAC) {
        this.Source_MAC = Source_MAC;
    }
    
    public String getDestination_MAC() {
        return Destination_MAC;
    }

    public String getSource_MAC() {
        return Source_MAC;
    }
    public int getNumberOfFrame() {
        return numberOfFrame;
    }

    public void setNumberOfFrame(int numberOfFrame) {
        this.numberOfFrame = numberOfFrame;
    }

    public StringBuilder getFrame() {
        return frame;
    }

    public void setFrame(StringBuilder frame) {
        this.frame = frame;
    }

    public int getStateOfFLAGS() {
        return StateOfFLAGS;
    }

    public void setStateOfFLAGS(int StateOfFLAGS) {
        this.StateOfFLAGS = StateOfFLAGS;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }
}
