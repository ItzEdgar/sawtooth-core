package sawtoothProcessorTest;

import sawtooth.sdk.processor.Utils;

import java.io.*;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class test {

    static String createAddress(String name){
        try{
            return Utils.hash512(name.getBytes("UTF-8")).substring(0, 64);
        } catch(Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args){
        File f = new File("./keys/adeus");
        try {
            new FileInputStream(f).read();
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("1234567890".matches("\\d{1,10}"));
    }
}
