package de.tu_darmstadt.seemoo.nfcgate.network;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Log;

import androidx.preference.PreferenceManager;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import de.tu_darmstadt.seemoo.nfcgate.network.auth.Auth;

/**
 * Manages authentication state and HMAC computation for server authentication
 */
public class AuthenticationManager {
    private static final String TAG = "AuthenticationManager";
    private static final String PREF_ENABLE_AUTH = "pref_enable_authentication";
    private static final String PREF_AUTH_SECRET = "pref_auth_secret";
    private static final String PREF_AUTH_CLIENT_ID = "pref_auth_client_id";

    private final String secret;
    private final String clientId;
    private final boolean enabled;

    private boolean isAuthenticated = false;
    private String sessionId = null;

    public AuthenticationManager(Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        this.enabled = prefs.getBoolean(PREF_ENABLE_AUTH, false);
        this.secret = prefs.getString(PREF_AUTH_SECRET, "");
        String savedClientId = prefs.getString(PREF_AUTH_CLIENT_ID, "");
        
        // Use device model as default client ID if not set
        this.clientId = (savedClientId != null && !savedClientId.isEmpty()) 
            ? savedClientId 
            : Build.MODEL.replaceAll("\\s+", "_");

        Log.d(TAG, "AuthenticationManager initialized");
    }

    /**
     * Check if authentication is enabled and properly configured
     */
    public boolean isEnabled() {
        return enabled && !secret.isEmpty();
    }

    /**
     * Check if authentication handshake was successful
     */
    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    /**
     * Get the current session ID (if authenticated)
     */
    public String getSessionId() {
        return sessionId;
    }

    /**
     * Create an AuthResponse for the given challenge nonce
     */
    public Auth.AuthResponse createResponse(String nonce) {
        if (!isEnabled()) {
            throw new IllegalStateException("Cannot create auth response when authentication is disabled");
        }

        String hmac = computeHMAC(secret, nonce);
        
        return Auth.AuthResponse.newBuilder()
                .setClientId(clientId)
                .setHmac(hmac)
                .build();
    }

    /**
     * Mark authentication as successful and store session ID
     */
    public void setAuthenticated(String sessionId) {
        this.isAuthenticated = true;
        this.sessionId = sessionId;
        Log.i(TAG, "Authentication successful");
    }

    /**
     * Reset authentication state
     */
    public void reset() {
        this.isAuthenticated = false;
        this.sessionId = null;
        Log.d(TAG, "Authentication state reset");
    }

    /**
     * Compute HMAC-SHA256 of the message using the shared secret
     */
    private String computeHMAC(String secret, String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(
                secret.getBytes(StandardCharsets.UTF_8),
                "HmacSHA256"
            );
            mac.init(keySpec);
            byte[] hmacBytes = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hmacBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Log.e(TAG, "Failed to compute HMAC", e);
            throw new RuntimeException("Failed to compute HMAC", e);
        }
    }

    /**
     * Convert byte array to lowercase hexadecimal string
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    /**
     * Error message for authentication failure reason
     */
    public static String getUserFriendlyMessage(String reason) {
        if (reason == null || reason.isEmpty()) {
            return "Authentication failed";
        }

        switch (reason) {
            case "invalid_hmac":
                return "Secret mismatch. Please check your shared secret matches the server.";
            case "timeout_or_invalid_response":
                return "Authentication timeout. Please try again.";
            case "rate_limit_exceeded":
                return "Too many failed attempts. Please wait and try again.";
            default:
                return "Authentication failed: " + reason;
        }
    }
}
