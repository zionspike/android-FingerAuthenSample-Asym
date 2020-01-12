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


package com.example.android.fingerprintdialog;

import android.app.KeyguardManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import com.example.android.fingerprintdialog.server.StoreBackend;
import com.example.android.fingerprintdialog.server.StoreBackendImpl;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;


/**
 * Main entry point for the sample, showing a "Login" and "Enroll Fingerprint" button. The user has
 * supply correct password which is hard coded as "MOCK". After successfully authenticate with the -
 * password the mock-up server will allow user to enroll fingerprints. After enrolling
 * the fingerprints the user can now use his fingerprints to login
 * - User can fallback to use password based authentication but it just hard-coded string for testing.
 * - When fingerprints have been enrolled to the mock-up server, if there is any changes e.g. new fignerprints
 * registered to the mobile, the application will notice changes and force user to login using password
 * based again.
 */
public class MainActivity extends AppCompatActivity {

    private static final String TAG = MainActivity.class.getSimpleName();

    private static final String DIALOG_FRAGMENT_TAG_FINGERPRINT = "fingerprintFragment";
    private static final String DIALOG_FRAGMENT_TAG_REGISTER = "registerFragment";

    // This is an example of authentication information, only device ID is not enough to secure
    // an authentication process.
    private static final String SECRET_MESSAGE = "3575a29d-807c-3cd0-8b5f-fa46c9ac07ee";

    private KeyStore mKeyStore;
    private SharedPreferences mSharedPreferences;

    private KeyPairGenerator mKeyPairGenerator;
    public static final String KEY_NAME = "KEY_LOGIN_ACTION";
    private Signature mSignature;
    public static StoreBackend mStoreBackend;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        mStoreBackend = new StoreBackendImpl();
        try {
            mKeyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to get an instance of KeyStore", e);
        }
        mSharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);

        KeyguardManager keyguardManager = getSystemService(KeyguardManager.class);
        FingerprintManager fingerprintManager = getSystemService(FingerprintManager.class);
        Button loginButton = findViewById(R.id.login_button);
        Button registerButton = findViewById(R.id.register_button);

        if (!keyguardManager.isKeyguardSecure()) {
            // Show a message that the user hasn't set up a fingerprint or lock screen.
            Toast.makeText(this,
                    "Secure lock screen hasn't set up.\n"
                            + "Go to 'Settings -> Security -> Fingerprint' to set up a fingerprint",
                    Toast.LENGTH_LONG).show();
            Log.d("KAPI-DEBUG","[+] Secure login screen hasn't set up. Go to 'Settings -> Security -> Fingerprint' to set up a fingerprint");
            loginButton.setEnabled(false);
            registerButton.setEnabled(false);
            return;
        }
        // Now the protection level of USE_FINGERPRINT permission is normal instead of dangerous.
        // See http://developer.android.com/reference/android/Manifest.permission.html#USE_FINGERPRINT
        // The line below prevents the false positive inspection from Android Studio
        // noinspection ResourceType
        if (!fingerprintManager.hasEnrolledFingerprints()) {
            // This happens when no fingerprints are registered.
            Toast.makeText(this,
                    "Go to 'Settings -> Security -> Fingerprint' and register at least one" +
                            " fingerprint",
                    Toast.LENGTH_LONG).show();
            Log.d("KAPI-DEBUG","[+] Go to 'Settings -> Security -> Fingerprint' and register at least one fingerprint");
            loginButton.setEnabled(false);
            registerButton.setEnabled(false);
            return;
        }
        createKeyPair();

        loginButton.setEnabled(true);
        loginButton.setOnClickListener(new LoginButtonClickListener());

        registerButton.setEnabled(true);
        registerButton.setOnClickListener(new RegisterButtonClickListener());
    }

    /**
     * Enrolls a user to the fake backend.
     */
    public void enroll(String authenInfo) {
        try {
            mKeyStore.load(null);
            PublicKey publicKey = mKeyStore.getCertificate(KEY_NAME).getPublicKey();

            // Provide the public key to the backend. In most cases, the key needs to be transmitted
            // to the backend over the network, for which Key.getEncoded provides a suitable wire
            // format (X.509 DER-encoded). The backend can then create a PublicKey instance from the
            // X.509 encoded form using KeyFactory.generatePublic. This conversion is also currently
            // needed on API Level 23 (Android M) due to a platform bug which prevents the use of
            // Android Keystore public keys when their private keys require user authentication.
            // This conversion creates a new public key which is not backed by Android Keystore and
            // thus is not affected by the bug.
            KeyFactory factory = KeyFactory.getInstance(publicKey.getAlgorithm());
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey.getEncoded());
            PublicKey verificationKey = factory.generatePublic(spec);

            // Enroll authentication information and public key to the server
            if(MainActivity.mStoreBackend.enroll(authenInfo, verificationKey)){
                Toast.makeText(this, "You can use your fingerpint to authenticate with server now", Toast.LENGTH_LONG).show();
            } else {
                Toast.makeText(this, "Enrollment is not allowed, please login once", Toast.LENGTH_LONG).show();
            }
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException |
                IOException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    // Kapi
    /**
     * Generates an asymmetric key pair in the Android Keystore. Every use of the private key must
     * be authorized by the user authenticating with fingerprint. Public key use is unrestricted.
     */
    public void createKeyPair() {
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            mKeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
        }
        try {
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder
            mKeyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(KEY_NAME,
                            KeyProperties.PURPOSE_SIGN)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                            // Require the user to authenticate with a fingerprint to authorize
                            // every use of the private key
                            .setUserAuthenticationRequired(true)

                            // This will notify the exception when a new finger is enrolled
                            // Mininum API version is 24
                            .setInvalidatedByBiometricEnrollment(true)
                            .build());
            mKeyPairGenerator.generateKeyPair();
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    public String getSecretMessage(){
        return SECRET_MESSAGE;
    }


    public void onSuccessfulLogin(byte[] signature) {
        showConfirmation(signature);
    }

    public void onLoginFailed() {
        Toast.makeText(this, R.string.login_fail, Toast.LENGTH_SHORT).show();
    }

    // Show confirmation, if fingerprint was used show crypto information.
    private void showConfirmation(byte[] encrypted) {
        findViewById(R.id.confirmation_message).setVisibility(View.VISIBLE);
        if (encrypted != null) {
            TextView v = findViewById(R.id.encrypted_message);
            v.setVisibility(View.VISIBLE);
            v.setText(Base64.encodeToString(encrypted, 0 /* flags */));
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();

        if (id == R.id.action_settings) {
            Intent intent = new Intent(this, SettingsActivity.class);
            startActivity(intent);
            return true;
        }
        return super.onOptionsItemSelected(item);
    }


    private class RegisterButtonClickListener implements View.OnClickListener {

        RegisterButtonClickListener() {
        }

        @Override
        public void onClick(View view) {
            RegisterDialogFragment mFragment = new RegisterDialogFragment();
            findViewById(R.id.confirmation_message).setVisibility(View.GONE);
            findViewById(R.id.encrypted_message).setVisibility(View.GONE);

            mFragment.setStage(RegisterDialogFragment.Stage.REGISTER);
            mFragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG_REGISTER);
        }
    }


    private class LoginButtonClickListener implements View.OnClickListener {

        LoginButtonClickListener() { }

        @Override
        public void onClick(View view) {
            FingerprintAuthenticationDialogFragment mFragment = new FingerprintAuthenticationDialogFragment();
            findViewById(R.id.confirmation_message).setVisibility(View.GONE);
            findViewById(R.id.encrypted_message).setVisibility(View.GONE);

            // Set up the crypto object for later. The object will be authenticated by use
            // of the fingerprint.
            if (initSignature()) {

                // Show the fingerprint dialog. The user has the option to use the fingerprint with
                // crypto, or you can fall back to using a server-side verified password.
                mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mSignature));
                boolean useFingerprintPreference = mSharedPreferences
                        .getBoolean(getString(R.string.use_fingerprint_to_authenticate_key),
                                true);
                if (useFingerprintPreference) {
                    mFragment.setStage(
                            FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT);
                } else {
                    mFragment.setStage(
                            FingerprintAuthenticationDialogFragment.Stage.PASSWORD);
                }
                mFragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG_FINGERPRINT);
            } else {
                // This happens if the lock screen has been disabled or or a fingerprint got
                // enrolled. Thus show the dialog to authenticate with their password first
                // and ask the user if they want to authenticate with fingerprints in the
                // future
                mFragment.setStage(
                        FingerprintAuthenticationDialogFragment.Stage.NEW_FINGERPRINT_ENROLLED);
                mFragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG_FINGERPRINT);
            }
        }

        /**
         * Initialize the {@link Signature} instance with the created key in the
         * {@link #createKeyPair()} method.
         *
         * @return {@code true} if initialization is successful, {@code false} if the lock screen has
         * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
         * the key was generated.
         */
        private boolean initSignature() {
            try {
                mKeyStore.load(null);
                PrivateKey key = (PrivateKey) mKeyStore.getKey(KEY_NAME, null);

                mSignature = Signature.getInstance("SHA256withECDSA");
                mSignature.initSign(key);
                return true;
            } catch (KeyPermanentlyInvalidatedException e) {
                // This exception occurs when new fingerprint has enrolled.
                // This allow the application to notice change
                return false;
            } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException
                    | NoSuchAlgorithmException | InvalidKeyException e) {
                throw new RuntimeException("Failed to init Cipher", e);
            }
        }
    }
}
