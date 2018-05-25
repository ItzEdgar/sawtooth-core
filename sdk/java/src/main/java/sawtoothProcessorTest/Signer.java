package sawtoothProcessorTest;

import org.bitcoinj.core.ECKey;
import sawtooth.sdk.client.Signing;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;

public class Signer {

    private static String PPK_LOCATION = "./ppk";
    private static String PSK_LOCATION = "./psk";

    private ECKey privateKey;
    private String publicKey;

    public Signer(){
        try {
            byte[] ppkBytes = Files.readAllBytes(Paths.get(PPK_LOCATION));
            privateKey = ECKey.fromPrivate(ppkBytes);
            publicKey = Files.readAllLines(Paths.get(PSK_LOCATION)).get(0);

        } catch (IOException e) {
            this.privateKey = Signing.generatePrivateKey(new SecureRandom());
            this.publicKey = Signing.getPublicKey(privateKey);

            try {
                new FileOutputStream(PPK_LOCATION).write(privateKey.getPrivKeyBytes());
                new FileOutputStream(PSK_LOCATION).write(publicKey.getBytes());

            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
        }
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String sign(byte[] data){
        return Signing.sign(this.privateKey, data);
    }
}
