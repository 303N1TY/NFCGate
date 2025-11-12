package de.tu_darmstadt.seemoo.nfcgate.network.threading;

import android.util.Log;

import java.io.DataInputStream;
import java.io.IOException;

import de.tu_darmstadt.seemoo.nfcgate.network.data.NetworkStatus;
import de.tu_darmstadt.seemoo.nfcgate.network.ServerConnection;

public class ReceiveThread extends BaseThread {
    private static final String TAG = "ReceiveThread";
    public static final int MAX_RECEIVE_BYTES = 100*1024*1024;
    public static final int AUTH_MESSAGE_TYPE = 255;

    // references
    private DataInputStream mReadStream;

    /**
     * Waits on sendQueue and sends the data over the specified stream
     */
    public ReceiveThread(ServerConnection connection) {
        super(connection);
    }

    @Override
    void initThread() throws IOException {
        mReadStream = new DataInputStream(mSocket.getInputStream());
    }

    /**
     * Tries to receive and process one message from the stream.
     */
    @Override
    void runInternal() throws IOException {
        // block and wait for the 4 byte length prefix
        int length = mReadStream.readInt();
        Log.v(TAG, "Got message of " + length + " bytes");

        if (length > MAX_RECEIVE_BYTES)
            throw new IOException("Invalid protocol length prefix received");

        // read the message type/session byte
        int messageType = mReadStream.readUnsignedByte();
        
        // adjust data length (already read 1 byte for type)
        int dataLength = length - 1;
        
        // block and wait for actual data
        byte[] data = new byte[dataLength];
        mReadStream.readFully(data);

        // deliver data with message type
        mConnection.onReceive(messageType, data);
    }

    @Override
    void onError(Exception e) {
        Log.e(TAG, "Receive onError", e);
        super.onError(e);
    }
}
