package PKS;

import java.util.ArrayList;

/**
 *
 * @author Michal
 * trieda na ukladanie akychkolvek komunikacii
 */
public class Comunication {
    private String state;
    private String source_adress;
    private String destination_adress;
    private int source_port;
    private int destin_port;
    int[] number;
    
    ArrayList<FrameComun> frames = new ArrayList<FrameComun>();

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getSource_adress() {
        return source_adress;
    }

    public void setSource_adress(String source_adress) {
        this.source_adress = source_adress;
    }

    public String getDestination_adress() {
        return destination_adress;
    }

    public void setDestination_adress(String destination_adress) {
        this.destination_adress = destination_adress;
    }

    public int getSource_port() {
        return source_port;
    }

    public void setSource_port(int source_port) {
        this.source_port = source_port;
    }

    public int getDestin_port() {
        return destin_port;
    }

    public void setDestin_port(int destin_port) {
        this.destin_port = destin_port;
    }

    public int[] getNumber() {
        return number;
    }

    public void setNumber(int[] number) {
        this.number = number;
    }

    public ArrayList<FrameComun> getFrames() {
        return frames;
    }

    public void setFrames(ArrayList<FrameComun> frames) {
        this.frames = frames;
    }
}
