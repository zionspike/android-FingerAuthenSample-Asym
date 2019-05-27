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

import android.app.DialogFragment;
import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.util.Log;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.TextView;

import com.example.android.fingerprintdialog.server.StoreBackend;

/**
 * A dialog which uses fingerprint APIs to authenticate the user, and falls back to password
 * authentication if fingerprint is not available.
 */
public class RegisterDialogFragment extends DialogFragment
        implements TextView.OnEditorActionListener {

    private Button mCancelButton;
    private Button mSubmitDialogButton;
    private StoreBackend mStoreBackend;
    private View mBackupContent;
    private EditText mRegisterInfo;
    private CheckBox mUseFingerprintFutureCheckBox;
    private TextView mRegisterTextview;
    private TextView mNewFingerprintEnrolledTextView;

    private Stage mStage = Stage.REGISTER;

    private FingerprintManager.CryptoObject mCryptoObject;
    private FingerprintUiHelper mFingerprintUiHelper;
    private MainActivity mActivity;

    private InputMethodManager mInputMethodManager;
    private SharedPreferences mSharedPreferences;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Do not create a new Fragment when the Activity is re-created such as orientation changes.
        setRetainInstance(true);
        setStyle(DialogFragment.STYLE_NORMAL, android.R.style.Theme_Material_Light_Dialog);
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
            Bundle savedInstanceState) {
        getDialog().setTitle(getString(R.string.text_register));
        View v = inflater.inflate(R.layout.register_dialog_container, container, false);
        mCancelButton = (Button) v.findViewById(R.id.cancel_button);
        mCancelButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                dismiss();
            }
        });
        mSubmitDialogButton = (Button) v.findViewById(R.id.submit_dialog_button);
        mSubmitDialogButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.d("KAPI-DEBUG", "[+] Click on submit dialog button");
                mActivity = (MainActivity) getActivity();
                Log.d("KAPI-DEBUG", "[+] Creating key pair...");
                mActivity.createKeyPair();
                Log.d("KAPI-DEBUG","[+] Enroll by Register: " + mActivity.getSecretMessage());
                mActivity.enroll(mActivity.getSecretMessage());
                dismiss();
            }
        });
        mCancelButton.setText(R.string.cancel);
        mSubmitDialogButton.setText(R.string.submit_info);

        mSubmitDialogButton.setVisibility(View.VISIBLE);
        mCancelButton.setVisibility(View.VISIBLE);

        return v;
    }

    @Override
    public void onResume() {
        super.onResume();
    }

    public void setStage(Stage stage) {
        mStage = stage;
    }

    @Override
    public void onPause() {
        super.onPause();
    }

    @Override
    public void onAttach(Context context) {
        super.onAttach(context);
    }


    @Override
    public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
        if (actionId == EditorInfo.IME_ACTION_GO) {
//            verifyPassword();
            return true;
        }
        return false;
    }

    /**
     * Enumeration to indicate which authentication method the user is trying to authenticate with.
     */
    public enum Stage {
        REGISTER
    }
}
