import java.io.*;

/**
 * SecureData class representing the object that will be encrypted and transmitted.
 */
class SecureData implements Serializable {
    private static final long serialVersionUID = 1L;
    private String name;
    private String message;
    private double value;

    public SecureData(String name, String message, double value) {
        this.name = name;
        this.message = message;
        this.value = value;
    }

    @Override
    public String toString() {
        return "SecureData{name='" + name + "', message='" + message + "', value=" + value + "}";
    }
}
