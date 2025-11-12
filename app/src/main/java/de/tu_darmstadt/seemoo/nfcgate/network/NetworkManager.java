package de.tu_darmstadt.seemoo.nfcgate.network;

import android.content.SharedPreferences;
import androidx.preference.PreferenceManager;
import android.util.Log;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import de.tu_darmstadt.seemoo.nfcgate.gui.MainActivity;
import de.tu_darmstadt.seemoo.nfcgate.network.auth.Auth;
import de.tu_darmstadt.seemoo.nfcgate.network.c2s.C2S;
import de.tu_darmstadt.seemoo.nfcgate.network.data.NetworkStatus;
import de.tu_darmstadt.seemoo.nfcgate.network.threading.ReceiveThread;
import de.tu_darmstadt.seemoo.nfcgate.util.NfcComm;

import static de.tu_darmstadt.seemoo.nfcgate.network.c2s.C2S.ServerData.Opcode;

public class NetworkManager implements ServerConnection.Callback {
    private static final String TAG = "NetworkManager";

    public interface Callback {
        void onReceive(NfcComm data);
        void onNetworkStatus(NetworkStatus status);
        void onAuthenticationError(String message);
    }

    // references
    private final MainActivity mActivity;
    private ServerConnection mConnection;
    private final Callback mCallback;
    private AuthenticationManager mAuthManager;

    // preference data
    private String mHostname;
    private int mPort, mSessionNumber;

    public NetworkManager(MainActivity activity, Callback cb) {
        mActivity = activity;
        mCallback = cb;
        mAuthManager = new AuthenticationManager(activity);
    }

    public void connect() {
        // read fresh preference data
        loadPreferenceData();

        // reset authentication state
        mAuthManager = new AuthenticationManager(mActivity);

        // disconnect old connection
        if (mConnection != null)
            disconnect();

        // establish connection
        boolean tlsEnabled = PreferenceManager.getDefaultSharedPreferences(mActivity)
                .getBoolean("tls", false);
        mConnection = new ServerConnection(mHostname, mPort, tlsEnabled)
                .setCallback(this)
                .connect();

        // If authentication is enabled, wait for auth challenge before sending handshake
        // Otherwise, queue initial handshake message immediately
        if (!mAuthManager.isEnabled()) {
            sendServer(Opcode.OP_SYN, null);
        } else {
            Log.d(TAG, "Authentication enabled, waiting for server challenge");
            onNetworkStatus(NetworkStatus.AUTH_IN_PROGRESS);
        }
    }

    public void disconnect() {
        if (mConnection != null) {
            sendServer(Opcode.OP_FIN, null);
            mConnection.sync();
            mConnection.disconnect();
        }
        if (mAuthManager != null) {
            mAuthManager.reset();
        }
    }

    public void send(NfcComm data) {
        // queue data message
        sendServer(Opcode.OP_PSH, data.toByteArray());
    }

    @Override
    public void onReceive(int messageType, byte[] data) {
        Log.d(TAG, "onReceive: messageType=" + messageType + ", data.length=" + (data != null ? data.length : 0));
        // Handle authentication messages (type 255)
        if (messageType == ReceiveThread.AUTH_MESSAGE_TYPE) {
            handleAuthMessage(data);
            return;
        }

        // For normal messages, check authentication status if required
        if (mAuthManager.isEnabled() && !mAuthManager.isAuthenticated()) {
            Log.w(TAG, "Received data before authentication complete, ignoring");
            return;
        }

        // Parse and handle normal server data
        final C2S.ServerData serverData;
        try {
            serverData = C2S.ServerData.parseFrom(data);
        } catch (InvalidProtocolBufferException e) {
            Log.e(TAG, "Message parsing failed", e);
            return;
        }

        Log.v(TAG, "Got message "+serverData.getOpcode().toString());
        switch (serverData.getOpcode()) {
            case OP_SYN:
                // empty syn message indicates our peer has just connected
                onNetworkStatus(NetworkStatus.PARTNER_CONNECT);
                // return ack
                sendServer(Opcode.OP_ACK, null);

                break;
            case OP_ACK:
                // empty ack message indicates our peer was already connected
                onNetworkStatus(NetworkStatus.PARTNER_CONNECT);

                break;
            case OP_FIN:
                // our peer has disconnected
                onNetworkStatus(NetworkStatus.PARTNER_LEFT);
                mConnection.disconnect();

                break;
            case OP_PSH:
                // pass data to callback
                mCallback.onReceive(new NfcComm(serverData.getData().toByteArray()));

                break;
        }
    }

    /**
     * Handle authentication protocol messages
     */
    private void handleAuthMessage(byte[] data) {
        // Try parsing as AuthChallenge first
        try {
            Auth.AuthChallenge challenge = Auth.AuthChallenge.parseFrom(data);
            if (!challenge.getNonce().isEmpty()) {
                handleAuthChallenge(challenge);
                return;
            }
        } catch (InvalidProtocolBufferException e) {
            Log.e(TAG, "Failed to parse AuthChallenge");
        }

        // Try parsing as AuthResult
        try {
            Auth.AuthResult result = Auth.AuthResult.parseFrom(data);
            handleAuthResult(result);
        } catch (InvalidProtocolBufferException e) {
            Log.e(TAG, "Failed to parse AuthResult");
            mCallback.onAuthenticationError("Invalid authentication message received");
        }
    }

    /**
     * Handle authentication challenge from server
     */
    private void handleAuthChallenge(Auth.AuthChallenge challenge) {
        if (!mAuthManager.isEnabled()) {
            Log.w(TAG, "Received auth challenge but authentication not enabled locally");
            mCallback.onAuthenticationError("Server requires authentication. Please enable authentication in settings.");
            mConnection.disconnect();
            return;
        }

        try {
            // Create response with HMAC
            Auth.AuthResponse response = mAuthManager.createResponse(challenge.getNonce());
            // Send auth response
            mConnection.sendAuthMessage(response.toByteArray());
        } catch (Exception e) {
            Log.e(TAG, "Failed to create auth response", e);
            mCallback.onAuthenticationError("Failed to create authentication response: " + e.getMessage());
            mConnection.disconnect();
        }
    }

    /**
     * Handle authentication result from server
     */
    private void handleAuthResult(Auth.AuthResult result) {
        if (result.getSuccess()) {
            // Authentication successful
            mAuthManager.setAuthenticated(result.getSessionId());
            onNetworkStatus(NetworkStatus.AUTH_SUCCESS);
            
            // Send the initial handshake message
            sendServer(Opcode.OP_SYN, null);
            
            Log.i(TAG, "Authentication successful");
        } else {
            // Authentication failed
            String reason = result.getReason();
            Log.e(TAG, "Authentication failed");
            
            String userMessage = AuthenticationManager.getUserFriendlyMessage(reason);
            mCallback.onAuthenticationError(userMessage);
            
            onNetworkStatus(NetworkStatus.ERROR_AUTH_FAILED);
            mConnection.disconnect();
        }
    }

    @Override
    public void onNetworkStatus(NetworkStatus status) {
        mCallback.onNetworkStatus(status);
    }

    private void loadPreferenceData() {
        // read data from shared prefs
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(mActivity);
        mHostname = prefs.getString("host", null);
        mPort = Integer.parseInt(prefs.getString("port", "0"));
        mSessionNumber = Integer.parseInt(prefs.getString("session", "0"));
    }

    private void sendServer(Opcode opcode, byte[] data) {
        mConnection.send(mSessionNumber,
                C2S.ServerData.newBuilder()
                    .setOpcode(opcode)
                    .setData(data == null ? ByteString.EMPTY : ByteString.copyFrom(data))
                    .build()
                    .toByteArray());
    }
}
