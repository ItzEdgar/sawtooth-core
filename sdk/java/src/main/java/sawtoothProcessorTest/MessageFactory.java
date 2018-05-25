package sawtoothProcessorTest;

import com.google.protobuf.ByteString;
import sawtooth.sdk.processor.Utils;
import sawtooth.sdk.protobuf.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * A Java implementation of the MessageFactory originally written in Pyhton
 */
public class MessageFactory {

    private String familyName, version;
    private List<String> namespaces;
    private Signer signer;

    public MessageFactory(String familyName, String version, ArrayList<String> namespaces){
        this.familyName = familyName;
        this.version = version;
        this.namespaces = namespaces;
        this.signer = new Signer();
    }

    public MessageFactory(String familyName, String version, String namespace){
        this.familyName = familyName;
        this.version = version;
        this.namespaces = Arrays.asList(namespace);
        this.signer = new Signer();
    }

    boolean isValidMerkleAddress(String address){
        return address.matches("[0-9a-f]{70}");
    }

    String namespace(){
        return namespaces.get(0);
    }

    static String sha512(ByteString context){
        return Utils.hash512(context.toByteArray());
    }

    String getPublicKey(){
        return signer.getPublicKey();
    }

    TpRegisterRequest createTpRegister(){
        return TpRegisterRequest
                .newBuilder()
                .setFamily(this.familyName)
                .addAllNamespaces(this.namespaces)
                .setVersion(this.version)
                .build();
    }

    TpProcessResponse createTpResponse(TpProcessResponse.Status status){
        return TpProcessResponse
                .newBuilder()
                .setStatus(status)
                .build();
    }

    TpProcessResponse createTpResponse(String status){
        TpProcessResponse.Status s;
        switch(status) {
            case "OK":
                s = TpProcessResponse.Status.OK;
                break;
            case "INVALID_TRANSACTION":
                s = TpProcessResponse.Status.INVALID_TRANSACTION;
                break;
            case "INTERNAL_ERROR":
                s = TpProcessResponse.Status.INTERNAL_ERROR;
                break;
            default:
                s = TpProcessResponse.Status.UNRECOGNIZED;
        }
        return TpProcessResponse
                .newBuilder()
                .setStatus(s)
                .build();
    }

    private TransactionHeader createTransactionHeader(ByteString payloadBytes, List<String> inputs, List<String> outputs,
                                       List<String> deps, boolean setNonce, String batcherPubKey){

        String nonce = setNonce? Long.toString(System.nanoTime()) : "";

        if(batcherPubKey == null || batcherPubKey.isEmpty())
            batcherPubKey = signer.getPublicKey();

        return TransactionHeader
                .newBuilder()
                .setFamilyName(this.familyName)
                .setFamilyVersion(this.version)
                .addAllInputs(inputs)
                .addAllOutputs(outputs)
                .setSignerPublicKey(signer.getPublicKey())
                .setBatcherPublicKey(batcherPubKey)
                .addAllDependencies(deps)
                .setPayloadSha512(sha512(payloadBytes))
                .setNonce(nonce)
                .build();
    }

    public Transaction createTransaction(ByteString payloadBytes, List<String> inputs, List<String> outputs,
                                  List<String> deps, String batcherPubKey){

        if(batcherPubKey == null || batcherPubKey.isEmpty())
            batcherPubKey = signer.getPublicKey();

        ByteString headerBytes = createTransactionHeader(payloadBytes, inputs, outputs, deps, true, batcherPubKey)
                .toByteString();
        String headerSignature = signer.sign(headerBytes.toByteArray());

        return Transaction
                .newBuilder()
                .setHeader(headerBytes)
                .setHeaderSignature(headerSignature)
                .setPayload(payloadBytes)
                .build();
    }

    void validateAddresses(Collection<String> addressess) throws InvalidMerkleAddressException {
        for(String addr : addressess)
            if(!isValidMerkleAddress(addr))
                throw new InvalidMerkleAddressException(addr + " is not a valid merkle trie address");
    }

    private class InvalidMerkleAddressException extends Exception{
        InvalidMerkleAddressException(String error){
            System.err.println("Error: " + error);
        }
    }

    TpProcessRequest createTpProcessRequest(ByteString payload, List<String> inputs, List<String> outputs,
                                            List<String> deps, boolean setNonce){

        TransactionHeader header = createTransactionHeader(payload, inputs, outputs, deps, setNonce, null);
        String headSignature = signer.sign(header.toByteArray());

        return TpProcessRequest
                .newBuilder()
                .setHeader(header)
                .setPayload(payload)
                .setSignature(headSignature)
                .build();
    }

    /**
     * Creates a Batch //Not anymore -> and wraps it around a BatchList
     * @param transactions List of transactions to add to the batch
     * @return Serialized BatchList (ByteString)
     */
    public Batch createBatch(List<Transaction> transactions){
        List<String> txHeaderSignatures = new ArrayList<>();
        for(Transaction t : transactions)
            txHeaderSignatures.add(t.getHeaderSignature());

        ByteString headerBytes = BatchHeader
                .newBuilder()
                .setSignerPublicKey(signer.getPublicKey())
                .addAllTransactionIds(txHeaderSignatures)
                .build()
                .toByteString();
        System.out.printf("signer: %s\n", signer.getPublicKey());

        String batchSignature = signer.sign(headerBytes.toByteArray());

        return Batch
                .newBuilder()
                .setHeader(headerBytes)
                .setHeaderSignature(batchSignature)
                .addAllTransactions(transactions)
                .build();
    }

    public ByteString createBatchList(List<Batch> batches){
        return BatchList
                .newBuilder()
                .addAllBatches(batches)
                .build()
                .toByteString();
    }

    TpStateGetRequest createGetRequest(List<String> addresses) throws InvalidMerkleAddressException {
        validateAddresses(addresses);

        return TpStateGetRequest
                .newBuilder()
                .addAllAddresses(addresses)
                .build();
    }

    TpStateGetResponse createGetResponse(Map<String, ByteString> addressDataMap) throws InvalidMerkleAddressException {
        validateAddresses(addressDataMap.keySet());

        List<TpStateEntry> entries = new ArrayList<>();
        for(String addr : addressDataMap.keySet())
            entries.add(TpStateEntry
                    .newBuilder()
                    .setAddress(addr)
                    .setData(addressDataMap.get(addr))
                    .build());

        return TpStateGetResponse
                .newBuilder()
                .addAllEntries(entries)
                .build();
    }

    TpStateSetRequest createSetRequest(Map<String, ByteString> addressDataMap) throws InvalidMerkleAddressException {
        validateAddresses(addressDataMap.keySet());

        List<TpStateEntry> entries = new ArrayList<>();
        for(String addr : addressDataMap.keySet())
            entries.add(TpStateEntry
                    .newBuilder()
                    .setAddress(addr)
                    .setData(addressDataMap.get(addr))
                    .build());
        return TpStateSetRequest
                .newBuilder()
                .addAllEntries(entries)
                .build();
    }

    TpStateSetResponse createSetResponse(List<String> addresses) throws InvalidMerkleAddressException {
        validateAddresses(addresses);
        return TpStateSetResponse
                .newBuilder()
                .addAllAddresses(addresses)
                .setStatus(TpStateSetResponse.Status.OK)
                .build();
    }

    TpStateDeleteRequest createDeleteRequest(List<String> addresses) throws InvalidMerkleAddressException {
        validateAddresses(addresses);
        return TpStateDeleteRequest
                .newBuilder()
                .addAllAddresses(addresses)
                .build();
    }

    TpStateDeleteResponse createDeleteResponse(List<String> addresses) throws InvalidMerkleAddressException {
        validateAddresses(addresses);
        return TpStateDeleteResponse
                .newBuilder()
                .addAllAddresses(addresses)
                .build();
    }

    TpEventAddRequest createAddEventRequest(String eventType, List<String[]> attributes, ByteString data){
        List<Event.Attribute> attributeList = new ArrayList<>();
        for(String[] attribute : attributes){
            attributeList.add(Event.Attribute
                    .newBuilder()
                    .setKey(attribute[0])
                    .setValue(attribute[1])
                    .build());
        }

        Event event = Event
                .newBuilder()
                .setEventType(eventType)
                .addAllAttributes(attributeList)
                .setData(data)
                .build();

        return TpEventAddRequest
                .newBuilder()
                .setEvent(event)
                .build();
    }

    TpEventAddResponse createAddEventResponse(){
        return TpEventAddResponse
                .newBuilder()
                .setStatus(TpEventAddResponse.Status.OK)
                .build();
    }
}
