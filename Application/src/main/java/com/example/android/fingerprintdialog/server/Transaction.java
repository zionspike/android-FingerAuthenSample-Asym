package com.example.android.fingerprintdialog.server;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Objects;

public class Transaction {

    /** The unique deviceID indentify an application */
    private String mDeviceID;

    /**
     * The random long value that will be also signed by the private key and verified in the server
     * that the same nonce can't be reused to prevent replay attacks.
     */
    private final Long mClientNonce;

    public Transaction(String deviceID, long clientNonce) {
        mDeviceID = deviceID;
        mClientNonce = clientNonce;
    }

    public String getUserDeviceID() {
        return mDeviceID;
    }

    public Long getNonce() {
        return mClientNonce;
    }


    public byte[] toByteArray() {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DataOutputStream dataOutputStream = null;
        try {
            dataOutputStream = new DataOutputStream(byteArrayOutputStream);
            dataOutputStream.writeLong(mClientNonce);
            dataOutputStream.writeUTF(mDeviceID);
            return byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            try {
                if (dataOutputStream != null) {
                    dataOutputStream.close();
                }
            } catch (IOException ignore) {
            }
            try {
                byteArrayOutputStream.close();
            } catch (IOException ignore) {
            }
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        Transaction that = (Transaction) o;
        return Objects.equals(mDeviceID, that.mDeviceID) && Objects.equals(mClientNonce, that.mClientNonce);
    }

    @Override
    public int hashCode() {
        return Objects.hash(mDeviceID, mClientNonce);
    }
}

