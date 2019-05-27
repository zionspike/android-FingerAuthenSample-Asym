/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.example.android.fingerprintdialog.server;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import android.util.Log;

/**
 * A fake backend implementation of {@link StoreBackend}.
 */
public class StoreBackendImpl implements StoreBackend {

    private final Map<String, PublicKey> mPublicKeys = new HashMap<>();
    private final Set<Transaction> mReceivedTransactions = new HashSet<>();
    private boolean allowEnroll = false;

    @Override
    public boolean verify(Transaction transaction, byte[] authenInfoSignature) {
//        Log.d("KAPI-DEBUG", "[+] Verifying with signature...");
        try {
            if (mReceivedTransactions.contains(transaction)) {
                // It verifies the equality of the transaction including the client nonce
                // So attackers can't do replay attacks.
                return false;
            }
            if (mPublicKeys.isEmpty()) {
                Log.d("KAPI-DEBUG", "[+] No entry on the server, please use the correct password and enroll your fingerprint");
                return false;
            }
            mReceivedTransactions.add(transaction);

            PublicKey publicKey = mPublicKeys.get(transaction.getUserDeviceID());
            Signature verificationFunction = Signature.getInstance("SHA256withECDSA");
            verificationFunction.initVerify(publicKey);
            verificationFunction.update(transaction.toByteArray());
            if (verificationFunction.verify(authenInfoSignature)) {
                // Transaction is verified with the public key associated with the user
                // Do some post purchase processing in the server
                Log.d("KAPI-DEBUG", "[+] Verifying with signature: " + authenInfoSignature.toString());
                return true;
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            // In a real world, better to send some error message to the user
        }
        return false;
    }

    @Override
    public boolean verify(Transaction transaction, String password) {
        // As this is just a sample, we always assume that the password is right.
        Log.d("KAPI-DEBUG", "[+] Verifying with password:" + transaction.getUserDeviceID() + ", " + transaction.getNonce() + " : " + password);
        if (password.equals("MOCK")){
            // Enrollment is allowed only when the correct password was supplied
            this.allowEnroll = true;
            return true;
        } else {
            return false;
        }
    }

    @Override
    public boolean enroll(String authenInfo, PublicKey publicKey) {
        if (publicKey != null && this.allowEnroll == true) {
            Log.d("KAPI-DEBUG", "[+] Enroll-internal: " + authenInfo + " : " + publicKey);
            mPublicKeys.put(authenInfo, publicKey);
            this.allowEnroll = false;
            return true;
        } else {
            Log.d("KAPI-DEBUG", "[+] Enrollment is not allowed, please supply the correct password once");
            return false;
        }
    }

}
