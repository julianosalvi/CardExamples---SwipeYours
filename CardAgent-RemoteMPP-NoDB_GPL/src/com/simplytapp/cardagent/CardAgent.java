/**
 * This file is part of CardAgent-RemoteMPP-NoDB which is card agent implementation 
 * of M Remote-SE Mobile PayP for SimplyTapp mobile platform.
 * Copyright 2014 SimplyTapp, Inc.
 * 
 * CardAgent-RemoteMPP-NoDB is free software: you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License, or 
 * (at your option) any later version.
 * 
 * CardAgent-RemoteMPP-NoDB is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License 
 * along with CardAgent-RemoteMPP-NoDB.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.simplytapp.cardagent;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayDeque;
import java.util.Arrays;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

import javax.crypto.spec.SecretKeySpec;

import android.util.Log;

import com.simplytapp.cardagent.remotempp.crypto.CryptogramGeneration;
import com.simplytapp.cardagent.remotempp.crypto.DataDecryption;
import com.simplytapp.cardagent.remotempp.crypto.OfflineDataAuthentication;
import com.simplytapp.virtualcard.Agent;
import com.simplytapp.virtualcard.ApprovalData;
import com.simplytapp.virtualcard.CardAgentConnector;
import com.simplytapp.virtualcard.TransceiveData;
import com.st.mmpp.data.CardProfile;
import com.st.mmpp.data.PaymentTokenPayloadSingleUseKey;

/**
 * Implementation of Card Agent based on Remote-SE Mobile PayP - 
 * MPP Remote-SE Lite June 2013 - v1.1.
 * 
 * This version does not support local database and does not require entering 
 * mobile PIN before every transaction.
 * 
 * @author SimplyTapp, Inc.
 * @version 1.2 GPL
 */
public final class CardAgent extends Agent {

    private static final String LOG_TAG = CardAgent.class.getSimpleName();

    private static final long serialVersionUID = 1L;

    // Remote Management Information definitions.
    private static final byte RMI_VERSION_MASK               = (byte) 0xE0;
    private static final byte RMI_VERSION                    = (byte) 0x60;
    private static final byte RMI_FUNCTION_MASK              = (byte) 0x1F;
    private static final byte RMI_FUNCTION_PTP_CP            = (byte) 0x01;
    private static final byte RMI_FUNCTION_PTP_SUK           = (byte) 0x02;
    private static final byte RMI_FUNCTION_MOBILE_CHECK      = (byte) 0x1C;
    private static final byte RMI_FUNCTION_MOBILE_PIN_CHANGE = (byte) 0x1D;
    private static final byte RMI_FUNCTION_DEACTIVATE        = (byte) 0x1E;  // Proprietary
    private static final byte RMI_FUNCTION_REMOTE_WIPE       = (byte) 0x1F;
    private static final byte RMI_FORMAT_DISPLAY             = (byte) 0x01;

    // Supported APDU commands.
    private static final byte INS_SELECT = (byte) 0xA4;
    private static final byte INS_GPO    = (byte) 0xA8;
    private static final byte INS_RR     = (byte) 0xB2;
    private static final byte INS_CCC    = (byte) 0x2A;
    private static final byte INS_GENAC  = (byte) 0xAE;

    // APDU state definitions.
    private static final byte APDU_SENT         = (byte) 0x00;
    private static final byte APDU_SENDING      = (byte) 0x01;
    private static final byte APDU_SENDING_LAST = (byte) 0x02;

    // Transaction state definitions.
    private static final byte TRANSACTION_START  = (byte) 0x00;
    private static final byte TRANSACTION_SELECT = (byte) 0x01;
    private static final byte TRANSACTION_GPO    = (byte) 0x02;
    private static final byte TRANSACTION_RR     = (byte) 0x03;
    private static final byte TRANSACTION_AC     = (byte) 0x04;

    // M Payment AID
    private static final byte[] MC_PAYMENT_AID = {
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x04, (byte) 0x10, (byte) 0x10
    };

    //================================================================
    // APDUs to communicate with remote card applet.
    //================================================================
    private static final byte[] APDU_SELECT_CARDAPPLET = { 
        (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x07, 
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x04, (byte) 0x10, (byte) 0x10, 
        (byte) 0x00
    };

    // NOTE: Use extended APDU format.
    private static final byte[] APDU_GET_CARDPROFILE = {
        (byte) 0x80, (byte) 0x80, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00
    };

    // NOTE: P1=0x01 indicates Mobile PIN not used.
    private static final byte[] APDU_GET_PTPSUK = {
        (byte) 0x80, (byte) 0x82, (byte) 0x01, (byte) 0x00, (byte) 0x00
    };

    private static final byte[] APDU_GET_MOBILE_KEY = {
        (byte) 0x80, (byte) 0x84, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };
    //================================================================

    private static final byte[] ZEROS = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    private transient byte apduState = APDU_SENT;

    private transient byte transactionState = TRANSACTION_START;

    private transient boolean selected = false;
    private transient boolean transactionFailed = false;
    private transient boolean transactionStartFailed = false;
    private transient boolean twoTap = false;
    private transient boolean disabled = false;
    private transient boolean terminated = false;

    // Threads to access remote card applet.
    private transient Thread tGetCardProfile;
    private transient Thread tGetPtpSuk;

    private static final int MAX_CONNECT_RETRY = 3;
    private transient int connectRetryCounter;

    private CardProfile cardProfile;
    private ArrayDeque<PaymentTokenPayloadSingleUseKey> arrayPtpSuk;

    private byte[] pdolData;

    // POS Cardholder Interaction Information (Tag 'DF4B') stores indicators.
    private static final byte OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_1 = (byte) 0;
    private static final byte OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_2 = (byte) (OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_1 + 1); // 1
    private static final byte OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_3 = (byte) (OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_2 + 1); // 2
    private static final byte SIZE_POS_CARDHOLDER_INTERACTION_INFO          = (byte) (OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_3 + 1); // 3
    private byte[] posCardholderInteractionInfo;

    // PPMS Transaction Details (Tag 'DF4E') keeps track of magstripe transaction details.
    private static final byte OFFSET_PPMS_TRANSACTION_DETAILS_VERSION_NUMBER = (byte) 0;
    private static final byte OFFSET_PPMS_TRANSACTION_DETAILS_ATC            = (byte) (OFFSET_PPMS_TRANSACTION_DETAILS_VERSION_NUMBER + 1); // 1
    private static final byte OFFSET_PPMS_TRANSACTION_DETAILS_CID            = (byte) (OFFSET_PPMS_TRANSACTION_DETAILS_ATC + 2);            // 3
    private static final byte OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_1     = (byte) (OFFSET_PPMS_TRANSACTION_DETAILS_CID + 1);            // 4
    private static final byte OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_2     = (byte) (OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_1 + 1);     // 5
    private static final byte OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_3     = (byte) (OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_2 + 1);     // 6
    private static final byte SIZE_PPMS_TRANSACTION_DETAILS                  = (byte) (OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_3 + 1);     // 7
    private byte[] ppmsTransactionDetails;

    // Transaction Context (Tag 'DF52') to support two-tap transaction.
    // TODO: MPP Remote-SE Lite specification indicates length is 15, not 13.
    private static final byte OFFSET_TRANSACTION_CONTEXT_CONTEXT_DEFINED     = (byte) 0;
    private static final byte OFFSET_TRANSACTION_CONTEXT_CONTEXT_CURRENCY    = (byte) (OFFSET_TRANSACTION_CONTEXT_CONTEXT_DEFINED + 1);     // 1
    private static final byte OFFSET_TRANSACTION_CONTEXT_CONTEXT_AMOUNT      = (byte) (OFFSET_TRANSACTION_CONTEXT_CONTEXT_CURRENCY + 2);    // 3
    private static final byte OFFSET_TRANSACTION_CONTEXT_ACK_STATUS          = (byte) (OFFSET_TRANSACTION_CONTEXT_CONTEXT_AMOUNT + 6);      // 9
    private static final byte OFFSET_TRANSACTION_CONTEXT_PIN_STATUS          = (byte) (OFFSET_TRANSACTION_CONTEXT_ACK_STATUS + 1);          // 10
    private static final byte OFFSET_TRANSACTION_CONTEXT_LS_EXCEEDED         = (byte) (OFFSET_TRANSACTION_CONTEXT_PIN_STATUS + 1);          // 11
    private static final byte OFFSET_TRANSACTION_CONTEXT_CONFLICTING_CONTEXT = (byte) (OFFSET_TRANSACTION_CONTEXT_LS_EXCEEDED + 1);         // 12
    private static final byte SIZE_TRANSACTION_CONTEXT                       = (byte) (OFFSET_TRANSACTION_CONTEXT_CONFLICTING_CONTEXT + 1); // 13
    private byte[] transactionContext;

    private boolean pinVerificationSuccessful;

    private transient SecretKeySpec mKey;

    private transient long transactionStartTime;

    public CardAgent() {
        allowNfcTransactions();
        allowSoftTransactions();
        denySocketTransactions();

        setAidCategory("payment");
        //setAidCategory(AID_CATEGORY_PAYMENT);
        try {
            registerAid(MC_PAYMENT_AID);
        }
        catch (IOException e) {
        }

        this.posCardholderInteractionInfo = new byte[SIZE_POS_CARDHOLDER_INTERACTION_INFO];
        this.ppmsTransactionDetails = new byte[SIZE_PPMS_TRANSACTION_DETAILS];
        this.transactionContext = new byte[SIZE_TRANSACTION_CONTEXT];
    }

    public static void install(CardAgentConnector cardAgentConnector) {
        new CardAgent().register(cardAgentConnector);
    }

    /* 
     * Similar to MPP Remote-SE Lite interface:
     * initialize(CardProfile)
     * Used to initialize the payment component with a Card Profile.
     * 
     * (non-Javadoc)
     * @see com.simplytapp.virtualcard.Agent#create()
     */
    @Override
    public void create() {
        // Retrieve Card Profile when card is created.
        this.connectRetryCounter = 0;
        getCardProfile();
    }

    // Called when press "Pay" button (for Activate On Touch) or when selecting Card Always Activated setting.
    @Override
    public void activated() {
        //Log.i(LOG_TAG, "activated");

        if (this.tGetCardProfile != null) {
            // Block until 'tGetCardProfile' thread has stopped before performing transaction checks.
            blockCondition(true, false, 100, "activated");

            // Provide enough time for message generated in 'tGetCardProfile' thread to be displayed on screen. 
            try {
                Thread.sleep(3000);
            }
            catch (InterruptedException e) {
            }
        }

        performTransactionChecks(true);
    }

    private void performTransactionChecks(boolean activating) {
        if ((this.cardProfile == null) || 
            (this.arrayPtpSuk == null) || 
            (this.arrayPtpSuk.size() == 0)) {
            // If transaction started, set flag immediately so 'process' method can check flag in time.  
            if (!activating) {
                this.transactionStartFailed = true;
            }

            // NOTE: Kludge to delay processing so message can be posted.
            try {
                Thread.sleep(100);
            }
            catch (InterruptedException e) {
            }

            try {
                if (this.terminated) {
                    postMessage("Account is Terminated", false, null);
                }
                else if (this.disabled) {
                    postMessage("Account is Disabled", false, null);
                }
                else if ((this.cardProfile == null) || (this.arrayPtpSuk == null)) {
                    postMessage("Missing Card Data\nPlease Check Connection is Available and Refresh Card", false, null);
                }
                else {
                    postMessage("No More PTP_SUK to\nPerform Transactions\nAttempting to Get More PTP_SUK...", false, null);
                }
            }
            catch (IOException e) {
            }
        }
    }

    // Called when press "DONE" button or back (for Activate On Touch setting) or when deselecting Card Always Activated setting.
    @Override
    public void deactivated() {
    }

    @Override
    public void disconnected() {
    }

    @Override
    public void sentApdu() {
        // Check if last APDU sent.
        if (this.apduState == APDU_SENDING_LAST) {
            // Reset parameter.
            this.selected = false;

            if (APDU.getCurrentAPDU().getTransactionSuccess()) {
                // DEBUG
                long transactionStopTime = System.currentTimeMillis();
                Log.i(LOG_TAG, "Transaction Timestamp=" + transactionStopTime + 
                               " Elapsed=" + (transactionStopTime - this.transactionStartTime) + "ms");
            }
        }

        this.apduState = APDU_SENT;
    }

    /* 
     * Called when first acceptable Selected APDU (contained in aid_list.xml) is received.
     * 
     * Similar to MPP Remote-SE Lite interface:
     * start(AbstractSingleKey)
     * Used to enable the support of a Mobile PayP Transaction flow.
     * 
     * (non-Javadoc)
     * @see com.simplytapp.virtualcard.Agent#transactionStarted()
     */
    @Override
    public void transactionStarted() {
        // DEBUG
        this.transactionStartTime = System.currentTimeMillis();
        Log.i(LOG_TAG, "transactionStarted Timestamp=" + this.transactionStartTime);

        // NOTE: Workaround for testing only.
        this.pinVerificationSuccessful = true;

        // Perform transaction checks.
        performTransactionChecks(false);
    }

    /* 
     * Similar to MPP Remote-SE Lite interface:
     * stop()
     * Used to finish the transaction and destroy the CardProfile and AbstractSingleUseKey objects.
     * 
     * (non-Javadoc)
     * @see com.simplytapp.virtualcard.Agent#transactionFinished()
     */
    @Override
    public void transactionFinished() {
        // Reset parameters.
        this.selected = false;
        // If 'transactFailed' remains 'true' in subsequent transaction, it will continue to generate errors in 'process' method.
        this.transactionFailed = false;

        this.apduState = APDU_SENT;

        if (!this.twoTap) {
            // Reset transaction data.
            this.pdolData = null;
            Arrays.fill(this.posCardholderInteractionInfo, (byte) 0x00);
            Arrays.fill(this.ppmsTransactionDetails, (byte) 0x00);
            Arrays.fill(this.transactionContext, (byte) 0x00);

            // Provision additional PTP_SUK if minimum threshold is reached.
            this.connectRetryCounter = 0;
            getPtpSuk(true);
        }
        this.twoTap = false;

        // Update the state of the class.
        try {
            saveState();
        }
        catch (IOException e) {
        }
    }

    @Override
    public void messageApproval(boolean approved, 
                                ApprovalData approvalData) {
        Log.i(LOG_TAG, "messageApproval");
    }

    @Override
    public void messageFromRemoteCard(String msg) {
        Log.i(LOG_TAG, "messageFromRemoteCard: " + msg);

        // Block until there is no thread accessing remote card applet before processing remote message.
        blockCondition(true, true, 50, "messageFromRemoteCard");

        if (this.mKey == null) {
            Log.e(LOG_TAG, "Missing mKey to decrypt notification message.");
            return;
        }

        try {
            // Decrypt notification message using the Mobile Key.
            byte[] msgData = DataDecryption.decryptRemoteMessage(this.mKey, DataUtil.stringToCompressedByteArray(msg));

            //Log.i(LOG_TAG, "messageFromRemoteCard decrypted: " + DataUtil.byteArrayToHexString(msgData));

            if ((msgData == null) || 
                (msgData.length != 15) || 
                ((msgData[0] & RMI_VERSION_MASK) != RMI_VERSION) || 
                ((msgData[1] & RMI_VERSION_MASK) != RMI_VERSION)) {
                Log.e(LOG_TAG, "Invalid Remote Notification msg=" + DataUtil.byteArrayToHexString(msgData));

                return;
            }

            byte remoteNotificationFunction = (byte) (msgData[0] & RMI_FUNCTION_MASK);
            if (remoteNotificationFunction == RMI_FUNCTION_PTP_CP) {
                this.cardProfile = null;
                this.arrayPtpSuk = null;

                // NOTE: Kludge to delay processing in case there is STBridge connection.
                try {
                    Thread.sleep(100);
                    if ((msgData[1] & RMI_FORMAT_DISPLAY) == RMI_FORMAT_DISPLAY) {
                        if (this.disabled) {
                            postMessage("Account Has Been Enabled\nUpdating Card", false, null);
                        }
                        else {
                            postMessage("Card Data Has Changed\nUpdating Card", false, null);
                        }
                    }
                    Thread.sleep(500);
                }
                catch (Exception e) {
                }

                this.connectRetryCounter = 0;
                getCardProfile();
            }
            else if (remoteNotificationFunction == RMI_FUNCTION_PTP_SUK) {
                // NOTE: Kludge to delay processing in case there is STBridge connection.
                try {
                    Thread.sleep(100);
                    if ((msgData[1] & RMI_FORMAT_DISPLAY) == RMI_FORMAT_DISPLAY) {
                        postMessage("Updating PTP_SUK", false, null);
                    }
                    Thread.sleep(500);
                }
                catch (Exception e) {
                }

                // Provision additional PTP_SUK.
                this.connectRetryCounter = 0;
                getPtpSuk(false);
            }
            else if (remoteNotificationFunction == RMI_FUNCTION_MOBILE_CHECK) {
                Log.e(LOG_TAG, "RMI_FUNCTION_MOBILE_CHECK Unsupported");
            }
            else if (remoteNotificationFunction == RMI_FUNCTION_MOBILE_PIN_CHANGE) {
                Log.e(LOG_TAG, "RMI_FUNCTION_MOBILE_PIN_CHANGE Unsupported");
            }
            else if (remoteNotificationFunction == RMI_FUNCTION_DEACTIVATE) {
                this.disabled = true;

                this.cardProfile = null;
                this.arrayPtpSuk = null;

                if ((msgData[1] & RMI_FORMAT_DISPLAY) == RMI_FORMAT_DISPLAY) {
                    try {
                        postMessage("Account Has Been Disabled", false, null);
                    }
                    catch (IOException e) {
                    }
                }
            }
            else if (remoteNotificationFunction == RMI_FUNCTION_REMOTE_WIPE) {
                this.terminated = true;
                this.disabled = true;

                this.cardProfile = null;
                this.arrayPtpSuk = null;

                if ((msgData[1] & RMI_FORMAT_DISPLAY) == RMI_FORMAT_DISPLAY) {
                    try {
                        postMessage("Account Has Been Terminated", false, null);
                    }
                    catch (IOException e) {
                    }
                }
            }
            else {
                Log.e(LOG_TAG, "Unknown RMI Function msg=" + DataUtil.byteArrayToHexString(msgData));
            }
        }
        catch (Exception e) {
            Log.e(LOG_TAG, "messageFromRemoteCard Exception Log", e);
        }
    }

    /*
     * Similar to MPP Remote-SE Lite interface:
     * transceive(C-APDU)
     * Used to send a C-APDU to the payment component.
     * Returns R-APDU + SW or SW.
     * 
     * (non-Javadoc)
     * @see com.simplytapp.virtualcard.Agent#process(javacard.framework.APDU)
     */
    @Override
    public void process(APDU apdu) throws ISOException {
        while (this.apduState != APDU_SENT) {  // wait for previous one to complete (thread safe)
            try {
                Thread.sleep(1);
            }
            catch (InterruptedException e) {
            }

            try {
                if (getTransactionFinished()) {
                    this.apduState = APDU_SENDING_LAST;
                    throw new ISOException(ISO7816.SW_UNKNOWN);
                }
            }
            catch (IOException e) {
            }
        }

        // Check if transaction has already failed.
        if (this.transactionFailed) {
            this.apduState = APDU_SENDING_LAST;
            throw new ISOException(ISO7816.SW_UNKNOWN);
        }

        // Check if APDU protocol is allowed.
        byte protocol = APDU.getProtocol();
        if ((protocol != APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A) && 
            (protocol != APDU.PROTOCOL_MEDIA_SOFT)) {
            sendApduCFailure();
        }

        // Check if transaction initialization checks has failed.
        if (this.transactionStartFailed) {
            this.transactionStartFailed = false;
            sendApduCFailure(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        byte[] apduBuffer = apdu.getBuffer();
        byte claByte = apduBuffer[ISO7816.OFFSET_CLA];
        byte insByte = apduBuffer[ISO7816.OFFSET_INS];

        // Process C-APDU.
        if (claByte == ISO7816.CLA_ISO7816) {
            if (insByte == INS_SELECT) {  // Select
                // Receive C-APDU data.
                short apduAidLength = apdu.setIncomingAndReceive();

                // DEBUG
                Log.v(LOG_TAG, "C-APDU: " + DataUtil.byteArrayToHexString(apduBuffer, 0, apduAidLength + 6));

                // Check if Lc=[number of data bytes read].
                // Check if Le=0x00.
                if ((apduAidLength != apdu.getIncomingLength())  || 
                    (apdu.setOutgoing() != (short) 256)) {
                    sendApduCFailure(ISO7816.SW_WRONG_LENGTH);
                }

                ByteBuffer apduByteBuffer = ByteBuffer.wrap(apduBuffer);

                // Check if P1=0x04 and P2=0x00.
                if (apduByteBuffer.getShort(ISO7816.OFFSET_P1) != (short) 0x0400) {
                    sendApduCFailure(ISO7816.SW_INCORRECT_P1P2);
                }

                this.selected = false;
                // Check if matching AID.
                byte[] aid = this.cardProfile.getAid();
                if ((aid != null) && 
                    (aid.length == apduAidLength) && 
                    Arrays.equals(aid, Arrays.copyOfRange(apduBuffer, ISO7816.OFFSET_CDATA, ISO7816.OFFSET_CDATA + apduAidLength))) {
                    // Select, matching AID.

                    // Build response.
                    apduByteBuffer.put(PayPConstants.TAG_FCI_TEMPLATE);
                    // Skip FCI template length.
                    apduByteBuffer.put((byte) 0);
                    apduByteBuffer.put(PayPConstants.TAG_DF_NAME);
                    apduByteBuffer.put((byte) this.cardProfile.getAid().length);
                    apduByteBuffer.put(this.cardProfile.getAid());
                    apduByteBuffer.put(this.cardProfile.getTagA5Data());
                    // Set FCI template length.
                    apduByteBuffer.put(1, (byte) (apduByteBuffer.position() - 2));

                    this.selected = true;
                }
                else {
                    byte[] ppseAid = this.cardProfile.getAidPpse();
                    if ((ppseAid != null) && 
                        (ppseAid.length == apduAidLength) && 
                        Arrays.equals(ppseAid, Arrays.copyOfRange(apduBuffer, ISO7816.OFFSET_CDATA, ISO7816.OFFSET_CDATA + apduAidLength))) {
                        // Select, PPSE AID.

                        // Build response.
                        apduByteBuffer.put(this.cardProfile.getPpseResponse());
                    }
                    else {
                        sendApduCFailure(ISO7816.SW_FILE_NOT_FOUND);
                    }
                }

                this.apduState = APDU_SENDING;

                this.transactionState = TRANSACTION_SELECT;

                // DEBUG
                Log.v(LOG_TAG, "R-APDU: " + DataUtil.byteArrayToHexString(apduBuffer, 0, apduByteBuffer.position()) + "9000");

                apdu.setOutgoingLength((short) apduByteBuffer.position());
                apdu.sendBytes((short) 0, (short) apduByteBuffer.position());
            }
            else if (insByte == INS_RR) {  // Read Record
                if ((this.transactionState != TRANSACTION_GPO) && 
                    (this.transactionState != TRANSACTION_RR)) {
                    Log.e(LOG_TAG, "Transaction Failure: Out-of-order transaction flow.");
                    sendApduCFailure(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                else if (this.selected) {
                    try {
                        readRecord(apdu);

                        this.transactionState = TRANSACTION_RR;
                    }
                    catch (ISOException isoe) {
                        sendApduCFailure(isoe.getReason());
                    }
                }
                else {
                    sendApduCFailure();
                }
            }
            else {
                sendApduCFailure(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        }
        else if (claByte == (byte) 0x80) {
            if (insByte == INS_GPO) {  // Get Processing Options
                if (this.transactionState != TRANSACTION_SELECT) {
                    Log.e(LOG_TAG, "Transaction Failure: Out-of-order transaction flow.");
                    sendApduCFailure(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                else if (this.selected) {
                    try {
                        getProcessingOptions(apdu);

                        this.transactionState = TRANSACTION_GPO;
                    }
                    catch (ISOException isoe) {
                        sendApduCFailure(isoe.getReason());
                    }
                }
                else {
                    sendApduCFailure();
                }
            }
            else if (insByte == INS_CCC) {  // Compute Cryptographic Checksum
                if (this.transactionState != TRANSACTION_RR) {
                    Log.e(LOG_TAG, "Transaction Failure: Out-of-order transaction flow.");
                    sendApduCFailure(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                else if (this.selected) {
                    try {
                        computeCryptographicChecksum(apdu);

                        this.transactionState = TRANSACTION_AC;
                    }
                    catch (ISOException isoe) {
                        sendApduCFailure(isoe.getReason());
                    }
                }
                else {
                    sendApduCFailure();
                }
            }
            else if (insByte == INS_GENAC) {  // Generate AC
                if (this.transactionState != TRANSACTION_RR) {
                    Log.e(LOG_TAG, "Transaction Failure: Out-of-order transaction flow.");
                    sendApduCFailure(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                else if (this.selected) {
                    try {
                        generateAc(apdu);

                        this.transactionState = TRANSACTION_AC;
                    }
                    catch (ISOException isoe) {
                        sendApduCFailure(isoe.getReason());
                    }
                }
                else {
                    sendApduCFailure();
                }
            }
            else {
                // DEBUG
                Log.v(LOG_TAG, "C-APDU Header: " + DataUtil.byteArrayToHexString(apduBuffer, 0, 5));

                sendApduCFailure(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        }
        else {
            // DEBUG
            Log.v(LOG_TAG, "C-APDU Header: " + DataUtil.byteArrayToHexString(apduBuffer, 0, 5));

            sendApduCFailure(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    /**
     * Handle Get Processing Options command.
     * 
     * @param apdu
     *            the incoming <code>APDU</code> object
     * @throws ISOException
     */
    private void getProcessingOptions(APDU apdu) throws ISOException {
        byte[] apduBuffer = apdu.getBuffer();

        // DEBUG
        Log.v(LOG_TAG, "C-APDU Header: " + DataUtil.byteArrayToHexString(apduBuffer, 0, 5));

        ByteBuffer apduByteBuffer = ByteBuffer.wrap(apduBuffer);

        // Check if P1=0x00 and P2=0x00.
        if (apduByteBuffer.getShort(ISO7816.OFFSET_P1) != (short) 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Check if Lc=[number of data bytes read].
        // Check if Lc=3.
        // Check if Le=0x00.
        short len = apdu.setIncomingAndReceive();

        // DEBUG
        Log.v(LOG_TAG, "C-APDU: " + DataUtil.byteArrayToHexString(apduBuffer, 0, len + 6));

        if ((len != (short) (apduBuffer[ISO7816.OFFSET_LC] & (short) 0x00FF)) || 
            (len != (short) 3) || 
            (apdu.setOutgoing() != (short) 256)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Check PDOL data.
        apduByteBuffer.position(ISO7816.OFFSET_CDATA);
        if (apduByteBuffer.getShort() != (short) 0x8301) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte terminalType = apduByteBuffer.get();
        // Check if terminal type is offline only.
        if ((terminalType == (byte) 0x13) || 
            (terminalType == (byte) 0x16) || 
            (terminalType == (byte) 0x23) || 
            (terminalType == (byte) 0x26) || 
            (terminalType == (byte) 0x36)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        this.pdolData = new byte[1];
        this.pdolData[0] = terminalType;

        apduByteBuffer.rewind();
        // Build response.
        apduByteBuffer.put(PayPConstants.TAG_RESPONSE_MESSAGE_TEMPLATE);
        // Skip response message template length.
        apduByteBuffer.put((byte) 0);
        // Skip response message template length.
        // Append data elements in response:
        // '82' [2] Application Interchange Profile
        // '94' [var.] Application File Locator
        apduByteBuffer.put(PayPConstants.TAG_AIP);
        apduByteBuffer.put((byte) this.cardProfile.getAip().length);
        apduByteBuffer.put(this.cardProfile.getAip());
        apduByteBuffer.put(PayPConstants.TAG_AFL);
        apduByteBuffer.put((byte) this.cardProfile.getAfl().length);
        apduByteBuffer.put(this.cardProfile.getAfl());
        int rdataLength = apduByteBuffer.position();
        // Set response template message length.
        apduByteBuffer.put(1, (byte) (rdataLength - 2));

        this.apduState = APDU_SENDING;

        // DEBUG
        Log.v(LOG_TAG, "R-APDU: " + DataUtil.byteArrayToHexString(apduBuffer, 0, rdataLength) + "9000");

        apdu.setOutgoingLength((short) rdataLength);
        apdu.sendBytes((short) 0, (short) rdataLength);
    }

    /**
     * Handle Read Record command.
     * 
     * @param apdu
     *            the incoming <code>APDU</code> object
     */
    private void readRecord(APDU apdu) throws ISOException {
        byte[] apduBuffer = apdu.getBuffer();

        // DEBUG
        Log.v(LOG_TAG, "C-APDU: " + DataUtil.byteArrayToHexString(apduBuffer, 0, 5));

        short recordNumber = (short) (apduBuffer[ISO7816.OFFSET_P1] & (short) 0x00FF);
        byte sfi = (byte) ((short) (apduBuffer[ISO7816.OFFSET_P2] & (short) 0x00F8) >> (byte) 3);

        // Check P1/P2.
        if ((recordNumber == (short) 0x0000) || 
            ((apduBuffer[ISO7816.OFFSET_P2] & (byte) 0x07) != (byte) 0x04)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Check if Lc is not present.
        // Check if Le=0x00.
        if ((apdu.setIncomingAndReceive() != (short) 0) || 
            (apdu.setOutgoing() != (short) 256)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte[] recordData = null;
        if (sfi == (byte) 0x01) {
            if (recordNumber == (byte) 0x01) {
                recordData = this.cardProfile.getSfi1Record1();
            }
        }
        else if (sfi == (byte) 0x02) {
            if (recordNumber == (byte) 0x01) {
                recordData = this.cardProfile.getSfi2Record1();
            }
            else if (recordNumber == (byte) 0x02) {
                recordData = this.cardProfile.getSfi2Record2();
            }
            else if (recordNumber == (byte) 0x03) {
                recordData = this.cardProfile.getSfi2Record3();
            }
        }
        else {
            // SFI not found.
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        if (recordData == null) {
            // SFI found, record number not found.
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }

        short rdataLength = (short) recordData.length;
        System.arraycopy(recordData, 0, apduBuffer, 0, rdataLength);

        if (apduBuffer[(byte) 0] == PayPConstants.TAG_READ_RECORD_RESPONSE_MESSAGE_TEMPLATE) {
            // EMV file, check if record is referenced in AFL.

            byte[] afl = this.cardProfile.getAfl();
            short aflDataOffset = 0;
            while (aflDataOffset < afl.length) {
                if ((sfi == (byte) ((short) (afl[aflDataOffset] & (short) 0x00F8) >> (byte) 3)) && 
                    (recordNumber >= (short) (afl[(short) (aflDataOffset + (byte) 1)] & (short) 0x00FF)) && 
                    (recordNumber <= (short) (afl[(short) (aflDataOffset + (byte) 2)] & (short) 0x00FF))) {
                    // Record is referenced in AFL.
                    break;
                }

                aflDataOffset += (byte) 4;
            }
            if (aflDataOffset >= afl.length) {
                // Record is not referenced in AFL.
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }

        this.apduState = APDU_SENDING;

        // DEBUG
        Log.v(LOG_TAG, "R-APDU: " + DataUtil.byteArrayToHexString(apduBuffer, 0, rdataLength) + "9000");

        apdu.setOutgoingLength(rdataLength);
        apdu.sendBytes((short) 0, rdataLength);
    }

    /**
     * Handle Compute Cryptographic Checksum command.
     * 
     * @param apdu
     *            the incoming <code>APDU</code> object
     * @throws ISOException
     */
    private void computeCryptographicChecksum(APDU apdu) throws ISOException {
        byte[] apduBuffer = apdu.getBuffer();

        // DEBUG
        Log.v(LOG_TAG, "C-APDU Header: " + DataUtil.byteArrayToHexString(apduBuffer, 0, 5));

        ByteBuffer apduByteBuffer = ByteBuffer.wrap(apduBuffer);

        // Check if P1=0x8E and P2=0x80.
        if (apduByteBuffer.getShort(ISO7816.OFFSET_P1) != (short) 0x8E80) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Check if Lc=[number of data bytes read].
        // Check if Lc=16.
        // Check if Le=0x00.
        short cdataLength = apdu.setIncomingAndReceive();

        // DEBUG
        Log.v(LOG_TAG, "C-APDU: " + DataUtil.byteArrayToHexString(apduBuffer, 0, cdataLength + 6));

        if ((cdataLength != (short) (apduBuffer[ISO7816.OFFSET_LC] & (short) 0x00FF)) || 
            (cdataLength != (short) 16) || 
            (apdu.setOutgoing() != (short) 256)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // IF 'Compute Cryptographic Checksum' in Application Control = Compute Cryptographic Checksum not supported
        if ((this.cardProfile.getApplicationControl()[2] & 
             PayPConstants.APPLICATION_CONTROL_BYTE_3_BIT_CCC_SUPPORTED) == (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] unpredictableNumber = new byte[PayPConstants.LENGTH_UNPREDICTABLE_NUMBER];
        byte[] amountAuthorized = new byte[PayPConstants.LENGTH_AMOUNT];
        // Retrieve transaction related data.
        /*
        Unpredictable Number := Transaction Related Data[1 : 4]
        Mobile Support Indicator := Transaction Related Data[5]
        Amount, Authorized (Numeric) := Transaction Related Data[6 : 12]
        Transaction Currency Code := Transaction Related Data[12 : 13]
        Terminal Country Code := Transaction Related Data[14 : 15]
        Terminal Type := Transaction Related Data[16]
        */
        apduByteBuffer.position(ISO7816.OFFSET_CDATA);
        apduByteBuffer.get(unpredictableNumber);
        byte mobileSupportIndicator = apduByteBuffer.get();
        apduByteBuffer.get(amountAuthorized);
        short transactionCurrencyCode = apduByteBuffer.getShort();
        short terminalCountryCode = apduByteBuffer.getShort();
        byte terminalType = apduByteBuffer.get();

        // Check if terminal type is offline only.
        if ((terminalType == (byte) 0x13) || 
            (terminalType == (byte) 0x16) || 
            (terminalType == (byte) 0x23) || 
            (terminalType == (byte) 0x26) || 
            (terminalType == (byte) 0x36)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // IF Terminal Country Code = CRM Country Code
        if (terminalCountryCode == this.cardProfile.getCrmCountryCode()) {
            // Set 'Domestic Transaction' in PPMS Card Verification Results
            this.ppmsTransactionDetails[OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_2] |= PayPConstants.PPMS_CVR_BYTE_2_BIT_DOMESTIC_TRANSACTION;
        }
        else {
            // Set 'International Transaction' in PPMS Card Verification Results
            this.ppmsTransactionDetails[OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_2] |= PayPConstants.PPMS_CVR_BYTE_2_BIT_INTERNATIONAL_TRANSACTION;
        }

        // ***  Mobile CVM (Cardholder Verification Method) ***

        boolean skipCRM = false;
        boolean accept = false;

        ByteBuffer transactionContextByteBuffer = ByteBuffer.wrap(this.transactionContext);
        byte tcContextDefined = this.transactionContext[OFFSET_TRANSACTION_CONTEXT_CONTEXT_DEFINED];
        // IF Transaction Context.Context Defined = Magstripe first tap present OR 
        //    Transaction Context.Context Defined = First tap present
        if ((tcContextDefined == PayPConstants.TRANSACTION_CONTEXT_CONTEXT_DEFINED_MAGSTRIPE_FIRST_TAP) || 
            (tcContextDefined == PayPConstants.TRANSACTION_CONTEXT_CONTEXT_DEFINED_FIRST_TAP)) {
            // IF (Transaction Context.Context Currency = Transaction Currency Code) AND
            //    (Transaction Context.Context Amount = Amount, Authorized (Numeric)) AND
            //    (Transaction Context.Context Defined = Magstripe first tap present)
            if ((transactionContextByteBuffer.getShort(OFFSET_TRANSACTION_CONTEXT_CONTEXT_CURRENCY) == transactionCurrencyCode) && 
                (Arrays.equals(amountAuthorized, Arrays.copyOfRange(this.transactionContext, 
                                                                    OFFSET_TRANSACTION_CONTEXT_CONTEXT_AMOUNT, 
                                                                    OFFSET_TRANSACTION_CONTEXT_CONTEXT_AMOUNT + PayPConstants.LENGTH_AMOUNT))) && 
                (tcContextDefined == PayPConstants.TRANSACTION_CONTEXT_CONTEXT_DEFINED_MAGSTRIPE_FIRST_TAP)) {
                // *** Second Tap ***

                // IF Transaction Context.ACK Status = ACK locked
                if (this.transactionContext[OFFSET_TRANSACTION_CONTEXT_ACK_STATUS] == PayPConstants.TRANSACTION_CONTEXT_ACK_STATUS_ACK_LOCKED) {
                    // Set 'ACK Required' in POS Cardholder Interaction Information
                    this.posCardholderInteractionInfo[OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_2] |= PayPConstants.POS_CARDHOLDER_INTERACTION_INFO_BYTE_2_BIT_ACK_REQUIRED;
                    // Set 'CVM Required Is Not Satisfied' in PPMS Card Verification Results
                    this.ppmsTransactionDetails[OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_2] |= PayPConstants.PPMS_CVR_BYTE_2_BIT_CVM_REQUIRED_IS_NOT_SATISFIED;
                }

                // IF Transaction Context.PIN Status = PIN locked
                if (this.transactionContext[OFFSET_TRANSACTION_CONTEXT_PIN_STATUS] == PayPConstants.TRANSACTION_CONTEXT_PIN_STATUS_PIN_LOCKED) {
                    // Set 'PIN Required' in POS Cardholder Interaction Information
                    this.posCardholderInteractionInfo[OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_2] |= PayPConstants.POS_CARDHOLDER_INTERACTION_INFO_BYTE_2_BIT_PIN_REQUIRED;
                    // Set 'CVM Required Is Not Satisfied' in PPMS Card Verification Results
                    this.ppmsTransactionDetails[OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_2] |= PayPConstants.PPMS_CVR_BYTE_2_BIT_CVM_REQUIRED_IS_NOT_SATISFIED;
                }

                // Perform CRM.
                // 'skipCRM' is already initialized to 'false'.
            }
            else {
                // *** Context Conflict ***

                // Transaction Context.Context Defined := Invalidated context
                this.transactionContext[OFFSET_TRANSACTION_CONTEXT_CONTEXT_DEFINED] = PayPConstants.TRANSACTION_CONTEXT_CONTEXT_DEFINED_INVALIDATED_CONTEXT;
                // Transaction Context.ACK Status := No ACK
                this.transactionContext[OFFSET_TRANSACTION_CONTEXT_ACK_STATUS] = PayPConstants.TRANSACTION_CONTEXT_ACK_STATUS_NO_ACK;
                // Transaction Context.PIN Status := No PIN
                this.transactionContext[OFFSET_TRANSACTION_CONTEXT_PIN_STATUS] = PayPConstants.TRANSACTION_CONTEXT_PIN_STATUS_NO_PIN;
                // Transaction Context.Conflicting Context := Context is conflicting
                this.transactionContext[OFFSET_TRANSACTION_CONTEXT_CONFLICTING_CONTEXT] = PayPConstants.TRUE;

                // Set 'Context Is Conflicting' in POS Cardholder Interaction Information
                this.posCardholderInteractionInfo[OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_2] |= PayPConstants.POS_CARDHOLDER_INTERACTION_INFO_BYTE_2_BIT_CONTEXT_CONFLICTING;

                // Do not perform CRM.
                skipCRM = true;

                // Decline.
                // 'accept' is already initialized to 'false'.
            }
        }
        else {
            // *** First Tap ***

            // Transaction Context.Context Defined := Magstripe first tap present
            this.transactionContext[OFFSET_TRANSACTION_CONTEXT_CONTEXT_DEFINED] = PayPConstants.TRANSACTION_CONTEXT_CONTEXT_DEFINED_MAGSTRIPE_FIRST_TAP;
            // Transaction Context.Context Currency := Transaction Currency Code
            transactionContextByteBuffer.putShort(OFFSET_TRANSACTION_CONTEXT_CONTEXT_CURRENCY, transactionCurrencyCode);
            // Transaction Context.Context Amount := Amount, Authorized (Numeric)
            System.arraycopy(amountAuthorized, 0, 
                             this.transactionContext, OFFSET_TRANSACTION_CONTEXT_CONTEXT_AMOUNT, PayPConstants.LENGTH_AMOUNT);
            // Transaction Context.ACK Status := No ACK
            this.transactionContext[OFFSET_TRANSACTION_CONTEXT_ACK_STATUS] = PayPConstants.TRANSACTION_CONTEXT_ACK_STATUS_NO_ACK;
            // Transaction Context.PIN Status := No PIN
            this.transactionContext[OFFSET_TRANSACTION_CONTEXT_PIN_STATUS] = PayPConstants.TRANSACTION_CONTEXT_PIN_STATUS_NO_PIN;
            // Transaction Context.L&S Exceeded := Lost & Stolen counters not exceeded
            this.transactionContext[OFFSET_TRANSACTION_CONTEXT_LS_EXCEEDED] = PayPConstants.FALSE;
            // Transaction Context.Conflicting Context := Context is not conflicting
            this.transactionContext[OFFSET_TRANSACTION_CONTEXT_CONFLICTING_CONTEXT] = PayPConstants.FALSE;

            // IF 'PIN Pre-entry Allowed' in Magstripe CVM Issuer Options is set AND 
            //    'Offline PIN Verification Successful' in PIN Verification Status is set
            if (((this.cardProfile.getMagstripeCvmIssuerOptions() & PayPConstants.CVM_ISSUER_BIT_PIN_PRE_ENTRY_ALLOWED) != (byte) 0x00) && 
                this.pinVerificationSuccessful) {
                // Transaction Context.PIN Status := PIN entered
                this.transactionContext[OFFSET_TRANSACTION_CONTEXT_PIN_STATUS] = PayPConstants.TRANSACTION_CONTEXT_PIN_STATUS_PIN_ENTERED;
            }
            else {
                // Set 'PIN Required' in POS Cardholder Interaction Information
                this.posCardholderInteractionInfo[OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_2] |= PayPConstants.POS_CARDHOLDER_INTERACTION_INFO_BYTE_2_BIT_PIN_REQUIRED;
                // Transaction Context.PIN Status := PIN locked
                this.transactionContext[OFFSET_TRANSACTION_CONTEXT_PIN_STATUS] = PayPConstants.TRANSACTION_CONTEXT_PIN_STATUS_PIN_LOCKED;
                // Set 'CVM Required Is Not Satisfied' in PPMS Card Verification Results
                this.ppmsTransactionDetails[OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_2] |= PayPConstants.PPMS_CVR_BYTE_2_BIT_CVM_REQUIRED_IS_NOT_SATISFIED;
            }

            // Perform CRM.
            // 'skipCRM' is already initialized to 'false'.
        }

        if (!skipCRM) {
            // Continue same processing for First Tap and Second Tap.

            // IF ('Reader supports Mobile' is set in Mobile Support Indicator AND 
            //     'Offline PIN required by reader' is set in Mobile Support Indicator AND 
            //     Transaction Context.PIN Status != PIN Entered)
            if (((mobileSupportIndicator & PayPConstants.MOBILE_SUPPORT_INDICATOR_BIT_READER_SUPPORTS_MOBILE) != (byte) 0x00) && 
                ((mobileSupportIndicator & PayPConstants.MOBILE_SUPPORT_INDICATOR_BIT_OFFLINE_PIN_REQUIRED_READER) != (byte) 0x00) && 
                (this.transactionContext[OFFSET_TRANSACTION_CONTEXT_PIN_STATUS] != PayPConstants.TRANSACTION_CONTEXT_PIN_STATUS_PIN_ENTERED)) {
                // Transaction Context.PIN Status := PIN locked
                this.transactionContext[OFFSET_TRANSACTION_CONTEXT_PIN_STATUS] = PayPConstants.TRANSACTION_CONTEXT_PIN_STATUS_PIN_LOCKED;
                // Set 'PIN Required' in POS Cardholder Interaction Information
                this.posCardholderInteractionInfo[OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_2] |= PayPConstants.POS_CARDHOLDER_INTERACTION_INFO_BYTE_2_BIT_PIN_REQUIRED;
                // Set 'CVM Required Is Not Satisfied' in PPMS Card Verification Results
                // Set 'Terminal Erroneously Considers Offline PIN OK' in PPMS Card Verification Results
                this.ppmsTransactionDetails[OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_2] |= (byte) (PayPConstants.PPMS_CVR_BYTE_2_BIT_CVM_REQUIRED_IS_NOT_SATISFIED | 
                                                                                                   PayPConstants.PPMS_CVR_BYTE_2_BIT_TERMINAL_ERRONEOUSLY_CONSIDERS_OFFLINE_PIN_OK);
            }

            // IF Transaction Context.PIN Status = PIN Entered
            if (this.transactionContext[OFFSET_TRANSACTION_CONTEXT_PIN_STATUS] == PayPConstants.TRANSACTION_CONTEXT_PIN_STATUS_PIN_ENTERED) {
                // Set 'Offline PIN Verification Successful' in PPMS Card Verification Results
                this.ppmsTransactionDetails[OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_1] |= PayPConstants.PPMS_CVR_BYTE_1_BIT_OFFLINE_PIN_VERIFICATION_SUCCESSFUL;
            }

            // *** CRM (Card Risk Management) ***

            // IF (PPMS Card Verification Results[2-3] AND Card Issuer Action Code - Decline On PPMS) = '0000'
            if (((this.cardProfile.getCiacDeclinePpms()[0] & this.ppmsTransactionDetails[OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_2]) == (byte) 0x00) && 
                ((this.cardProfile.getCiacDeclinePpms()[1] & this.ppmsTransactionDetails[OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_3]) == (byte) 0x00)) {
                // Accept.
                accept = true;
            }
            // else Decline ('accept' is already initialized to 'false').
        }
        else {
            // Continue processing for Context Conflict.

            // checkAccsCntrsLimitsSetPPMSCVR(apdu);
        }

        // Perform same processing for Accept and Decline.

        PaymentTokenPayloadSingleUseKey ptpSuk = this.arrayPtpSuk.removeFirst();

        // Reset 'Offline PIN Verification Successful' in PIN Verification Status
        this.pinVerificationSuccessful = false;

        // PPMS Transaction Details := '01' | ATC | PPMS Cryptogram Information Data | PPMS Card Verification Results
        this.ppmsTransactionDetails[OFFSET_PPMS_TRANSACTION_DETAILS_VERSION_NUMBER] = (byte) 0x01;
        ByteBuffer.wrap(this.ppmsTransactionDetails).putShort(OFFSET_PPMS_TRANSACTION_DETAILS_ATC, ptpSuk.getAtc());

        boolean transactionSuccess = false;
        if (accept) {
            // *** Accept ***

            // Transaction Context.Context Defined := Previous transaction
            this.transactionContext[OFFSET_TRANSACTION_CONTEXT_CONTEXT_DEFINED] = PayPConstants.TRANSACTION_CONTEXT_CONTEXT_DEFINED_PREVIOUS_CONTEXT;

            // 'Transaction Outcome' in PPMS Cryptogram Information Data := Transaction sent online
            this.ppmsTransactionDetails[OFFSET_PPMS_TRANSACTION_DETAILS_CID] = PayPConstants.PPMS_CID_TRANSACTION_SENT_ONLINE;

            // IF 'Reader supports Mobile' is set in Mobile Support Indicator
            if ((mobileSupportIndicator & PayPConstants.MOBILE_SUPPORT_INDICATOR_BIT_READER_SUPPORTS_MOBILE) != (byte) 0x00) {
                // Set Offline PIN verification successful in POS Cardholder Interaction Information
                this.posCardholderInteractionInfo[OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_2] |= PayPConstants.POS_CARDHOLDER_INTERACTION_INFO_BYTE_2_BIT_OFFLINE_PIN_VERIFICATION_SUCCESSFUL;
            }

            // Generate PIN CVC3Track1.
            byte[] pinCvc3Track1 = CryptogramGeneration.generateCvc3(ptpSuk, 
                                                                     this.cardProfile.getPinIvCvc3Track1(), 
                                                                     unpredictableNumber);
            // Generate PIN CVC3Track2.
            byte[] pinCvc3Track2 = CryptogramGeneration.generateCvc3(ptpSuk, 
                                                                     this.cardProfile.getPinIvCvc3Track2(), 
                                                                     unpredictableNumber);
            if ((pinCvc3Track1 == null) || (pinCvc3Track2 == null)) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            apduByteBuffer.rewind();
            // Build response.
            apduByteBuffer.put(PayPConstants.TAG_RESPONSE_MESSAGE_TEMPLATE);
            // IF 'Reader supports Mobile' is set in Mobile Support Indicator
            if ((mobileSupportIndicator & PayPConstants.MOBILE_SUPPORT_INDICATOR_BIT_READER_SUPPORTS_MOBILE) != (byte) 0x00) {
                apduByteBuffer.put((byte) 21);
            }
            else {
                apduByteBuffer.put((byte) 15);
            }
            // Append common data elements in response:
            // '9F61' [2] PIN CVC3track2
            // '9F60' [2] PIN CVC3Track1
            // '9F36' [2] ATC
            apduByteBuffer.putShort(PayPConstants.TAG_CVC3_TRACK2);
            apduByteBuffer.put((byte) 2);
            apduByteBuffer.put(pinCvc3Track2, pinCvc3Track2.length - 2, 2);
            apduByteBuffer.putShort(PayPConstants.TAG_CVC3_TRACK1);
            apduByteBuffer.put((byte) 2);
            apduByteBuffer.put(pinCvc3Track1, pinCvc3Track1.length - 2, 2);
            apduByteBuffer.putShort(PayPConstants.TAG_APPLICATION_TRANSACTION_COUNTER);
            apduByteBuffer.put((byte) 2);
            apduByteBuffer.putShort(ptpSuk.getAtc());
            if ((mobileSupportIndicator & PayPConstants.MOBILE_SUPPORT_INDICATOR_BIT_READER_SUPPORTS_MOBILE) != (byte) 0x00) {
                // Append new terminal data element in response:
                // 'DF4B' [3] POS Cardholder Interaction Information
                apduByteBuffer.putShort(PayPConstants.TAG_POS_CARDHOLDER_INTERACTION_INFO);
                apduByteBuffer.put((byte) this.posCardholderInteractionInfo.length);
                apduByteBuffer.put(this.posCardholderInteractionInfo);
            }

            transactionSuccess = true;
        }
        else {
            // *** Decline ***

            // IF Transaction Context.Context Defined != Invalidated context AND
            //    'CVM Required Is Not Satisfied' in PPMS CVR is not set
            if ((this.transactionContext[OFFSET_TRANSACTION_CONTEXT_CONTEXT_DEFINED] != 
                 PayPConstants.TRANSACTION_CONTEXT_CONTEXT_DEFINED_INVALIDATED_CONTEXT) && 
                ((this.ppmsTransactionDetails[OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_2] & PayPConstants.PPMS_CVR_BYTE_2_BIT_CVM_REQUIRED_IS_NOT_SATISFIED) == 
                 (byte) 0x00)) {
                // Transaction Context.Context Defined := Previous transaction
                this.transactionContext[OFFSET_TRANSACTION_CONTEXT_CONTEXT_DEFINED] = PayPConstants.TRANSACTION_CONTEXT_CONTEXT_DEFINED_PREVIOUS_CONTEXT;
            }

            // 'Transaction Outcome' in PPMS Cryptogram Information Data := Transaction declined
            this.ppmsTransactionDetails[OFFSET_PPMS_TRANSACTION_DETAILS_CID] = PayPConstants.PPMS_CID_TRANSACTION_DECLINED;

            // IF 'Reader supports Mobile' is set in Mobile Support Indicator
            if ((mobileSupportIndicator & PayPConstants.MOBILE_SUPPORT_INDICATOR_BIT_READER_SUPPORTS_MOBILE) != (byte) 0x00) {
                apduByteBuffer.rewind();
                // Build response.
                apduByteBuffer.put(PayPConstants.TAG_RESPONSE_MESSAGE_TEMPLATE);
                apduByteBuffer.put((byte) 9);
                // Append data elements in response:
                // '9F36' [2] ATC
                // 'DF4B' [3] POS Cardholder Interaction Information
                apduByteBuffer.putShort(PayPConstants.TAG_APPLICATION_TRANSACTION_COUNTER);
                apduByteBuffer.put((byte) 2);
                // (ATC - 1) is used as the ATC returned in the CCC command.
                apduByteBuffer.putShort((short) (ptpSuk.getAtc() - 1));
                apduByteBuffer.putShort(PayPConstants.TAG_POS_CARDHOLDER_INTERACTION_INFO);
                apduByteBuffer.put((byte) this.posCardholderInteractionInfo.length);
                apduByteBuffer.put(this.posCardholderInteractionInfo);

                this.twoTap = true;

                // NOTE: This triggers generic "transaction failure" dialog in UI.
                try {
                    transactionFailure();
                }
                catch (IOException e) {
                }
            }
            else {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        }

        this.apduState = APDU_SENDING_LAST;

        // DEBUG
        Log.v(LOG_TAG, "R-APDU: " + DataUtil.byteArrayToHexString(apduBuffer, 0, apduByteBuffer.position()) + "9000");

        apdu.setOutgoingLength((short) apduByteBuffer.position());
        apdu.sendBytes((short) 0, (short) apduByteBuffer.position());

        if (transactionSuccess) {
            // Success triggers a successful transaction.
            apdu.setTransactionSuccess();
        }
    }

    /**
     * Handle Generate Application Cryptogram command.
     * 
     * @param apdu
     *            the incoming <code>APDU</code> object
     * @throws ISOException
     */
    private void generateAc(APDU apdu) throws ISOException {
        byte[] apduBuffer = apdu.getBuffer();

        // DEBUG
        Log.v(LOG_TAG, "C-APDU Header: " + DataUtil.byteArrayToHexString(apduBuffer, 0, 5));

        ByteBuffer apduByteBuffer = ByteBuffer.wrap(apduBuffer);

        byte cryptogramType = (byte) (apduBuffer[ISO7816.OFFSET_P1] & PayPConstants.GENERATE_AC_P1_CRYPTOGRAM_TYPE);
        boolean cdaRequested = ((apduBuffer[ISO7816.OFFSET_P1] & PayPConstants.FIRST_GENERATE_AC_P1_BIT_CDA_REQUESTED) == 
                                PayPConstants.FIRST_GENERATE_AC_P1_BIT_CDA_REQUESTED);

        // Validate cryptogram type.
        // Validate P1.
        if ((cryptogramType == PayPConstants.GENERATE_AC_P1_CRYPTOGRAM_TYPE_RFU) || 
            ((apduBuffer[ISO7816.OFFSET_P1] & (byte) 0x2F) != (byte) 0x00)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Check if P2=0x00.
        if (apduBuffer[ISO7816.OFFSET_P2] != (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short cdataLength = apdu.setIncomingAndReceive();

        // DEBUG
        Log.v(LOG_TAG, "C-APDU: " + DataUtil.byteArrayToHexString(apduBuffer, 0, cdataLength + 6));

        // Check if Lc=[number of data bytes read].
        // Check if Lc>=43.
        // Check if Lc=[CDOL1 Related Data Length].
        // Check if Le=0x00.
        if ((cdataLength != (short) (apduBuffer[ISO7816.OFFSET_LC] & (short) 0x00FF)) || 
            (cdataLength < (short) 43) || 
            (cdataLength != this.cardProfile.getCdol1RelatedDataLength()) || 
            (apdu.setOutgoing() != (short) 256)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Initialize Cryptogram Information Data to unknown value.
        byte cid = (byte) 0xFF;

        byte[] amountAuthorized = new byte[PayPConstants.LENGTH_AMOUNT];
        byte[] amountOther = new byte[PayPConstants.LENGTH_AMOUNT];
        byte[] tvr = new byte[PayPConstants.LENGTH_TVR];
        byte[] transactionDate = new byte[PayPConstants.LENGTH_TRANSACTION_DATE];
        byte[] unpredictableNumber = new byte[PayPConstants.LENGTH_UNPREDICTABLE_NUMBER];
        byte[] iccDynamicNumberTerminal = new byte[PayPConstants.LENGTH_ICC_DYNAMIC_NUMBER_TERMINAL];
        byte[] cvmResults = new byte[PayPConstants.LENGTH_CVM_RESULTS];
        // Save transaction related data.
        /*
        CDOL1 Related Data := Transaction Related Data
        Amount, Authorized (Numeric) := Transaction Related Data[1 : 6]
        Amount, Other (Numeric) := Transaction Related Data[7 : 12]
        Terminal Country Code := Transaction Related Data[13 : 14]
        Terminal Verification Results := Transaction Related Data[15 : 19]
        Transaction Currency Code := Transaction Related Data[20 : 21]
        Transaction Date := Transaction Related Data[22 : 24]
        Transaction Type := Transaction Related Data[25]
        Unpredictable Number := Transaction Related Data[26 : 29]
        Terminal Type := Transaction Related Data[30]
        Data Authentication Code := Transaction Related Data[31 : 32]
        ICC Dynamic Number (Terminal) := Transaction Related Data[33 : 40]
        CVM Results := Transaction Related Data[41 : 43]
        CDOL1 Extension := Transaction Related Data[44 : CDOL 1 Related Data Length]
        Note: CDOL1 Extension may be empty
        */
        byte[] cdol1RelatedData = Arrays.copyOfRange(apduBuffer, 
                                                     ISO7816.OFFSET_CDATA, 
                                                     ISO7816.OFFSET_CDATA + cdataLength);
        apduByteBuffer.position(ISO7816.OFFSET_CDATA);
        apduByteBuffer.get(amountAuthorized);
        apduByteBuffer.get(amountOther);
        short terminalCountryCode = apduByteBuffer.getShort();
        apduByteBuffer.get(tvr);
        short transactionCurrencyCode = apduByteBuffer.getShort();
        apduByteBuffer.get(transactionDate);
        byte transactionType = apduByteBuffer.get();
        apduByteBuffer.get(unpredictableNumber);
        byte terminalType = apduByteBuffer.get();
        short dataAuthenticationCode = apduByteBuffer.getShort();
        apduByteBuffer.get(iccDynamicNumberTerminal);
        apduByteBuffer.get(cvmResults);

        byte[] cvr = new byte[PayPConstants.LENGTH_CVR];

        // IF Terminal Country Code = CRM Country Code
        if (terminalCountryCode == this.cardProfile.getCrmCountryCode()) {
            // Set 'Domestic Transaction' in Card Verification Results
            cvr[3] |= PayPConstants.CVR_BYTE_4_BIT_DOMESTIC_TRANSACTION;
        }
        else {
            // Set 'International Transaction' in Card Verification Results
            cvr[3] |= PayPConstants.CVR_BYTE_4_BIT_INTERNATIONAL_TRANSACTION;
        }

        // IF 'Additional Check Table' in Application Control is set
        if ((this.cardProfile.getApplicationControl()[1] & PayPConstants.APPLICATION_CONTROL_BYTE_2_BIT_ACTIVATE_ADDITIONAL_CHECK_TABLE) == 
            PayPConstants.APPLICATION_CONTROL_BYTE_2_BIT_ACTIVATE_ADDITIONAL_CHECK_TABLE) {
            //processAddCheckTable();
        }

        // ***  Mobile CVM (Cardholder Verification Method) ***

        boolean skipCRM = false;

        ByteBuffer transactionContextByteBuffer = ByteBuffer.wrap(this.transactionContext);
        byte tcContextDefined = this.transactionContext[OFFSET_TRANSACTION_CONTEXT_CONTEXT_DEFINED];
        // IF Transaction Context.Context Defined = First tap present OR 
        //    Transaction Context.Context Defined = Magstripe first tap present
        if ((tcContextDefined == PayPConstants.TRANSACTION_CONTEXT_CONTEXT_DEFINED_FIRST_TAP) || 
            (tcContextDefined == PayPConstants.TRANSACTION_CONTEXT_CONTEXT_DEFINED_MAGSTRIPE_FIRST_TAP)) {
            // IF (Transaction Context.Context Currency = Transaction Currency Code) AND
            //    (Transaction Context.Context Amount = Amount, Authorized (Numeric)) AND
            //    (Transaction Context.Context Defined = First tap present)
            if ((transactionContextByteBuffer.getShort(OFFSET_TRANSACTION_CONTEXT_CONTEXT_CURRENCY) == transactionCurrencyCode) && 
                (Arrays.equals(amountAuthorized, Arrays.copyOfRange(this.transactionContext, 
                                                                    OFFSET_TRANSACTION_CONTEXT_CONTEXT_AMOUNT, 
                                                                    OFFSET_TRANSACTION_CONTEXT_CONTEXT_AMOUNT + PayPConstants.LENGTH_AMOUNT))) && 
                (tcContextDefined == PayPConstants.TRANSACTION_CONTEXT_CONTEXT_DEFINED_FIRST_TAP)) {
                // *** Second Tap ***

                // IF Transaction Context.PIN Status = PIN locked
                if (this.transactionContext[OFFSET_TRANSACTION_CONTEXT_PIN_STATUS] == PayPConstants.TRANSACTION_CONTEXT_PIN_STATUS_PIN_LOCKED) {
                    // Set 'PIN Required' in POS Cardholder Interaction Information
                    this.posCardholderInteractionInfo[OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_2] |= PayPConstants.POS_CARDHOLDER_INTERACTION_INFO_BYTE_2_BIT_PIN_REQUIRED;
                    // Set 'CVM Required Is Not Satisfied' in Card Verification Results
                    cvr[5] |= PayPConstants.CVR_BYTE_6_BIT_CVM_REQUIRED_IS_NOT_SATISFIED;
                }

                // Perform CRM.
                // 'skipCRM' is already initialized to 'false'.
            }
            else {
                // *** Context Conflict ***

                // Transaction Context.Context Defined := Invalidated context
                this.transactionContext[OFFSET_TRANSACTION_CONTEXT_CONTEXT_DEFINED] = PayPConstants.TRANSACTION_CONTEXT_CONTEXT_DEFINED_INVALIDATED_CONTEXT;
                // Transaction Context.ACK Status := No ACK
                this.transactionContext[OFFSET_TRANSACTION_CONTEXT_ACK_STATUS] = PayPConstants.TRANSACTION_CONTEXT_ACK_STATUS_NO_ACK;
                // Transaction Context.PIN Status := No PIN
                this.transactionContext[OFFSET_TRANSACTION_CONTEXT_PIN_STATUS] = PayPConstants.TRANSACTION_CONTEXT_PIN_STATUS_NO_PIN;
                // Transaction Context.Conflicting Context := Context is conflicting
                this.transactionContext[OFFSET_TRANSACTION_CONTEXT_CONFLICTING_CONTEXT] = PayPConstants.TRUE;

                // Set 'Context Is Conflicting' in POS Cardholder Interaction Information
                this.posCardholderInteractionInfo[OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_2] |= PayPConstants.POS_CARDHOLDER_INTERACTION_INFO_BYTE_2_BIT_CONTEXT_CONFLICTING;

                // AAC decided.
                cryptogramType = PayPConstants.GENERATE_AC_P1_CRYPTOGRAM_TYPE_AAC;

                // Do not perform CRM.
                skipCRM = true;
            }
        }
        else {
            // *** First Tap ***

            // Transaction Context.Context Defined := First tap present
            this.transactionContext[OFFSET_TRANSACTION_CONTEXT_CONTEXT_DEFINED] = PayPConstants.TRANSACTION_CONTEXT_CONTEXT_DEFINED_FIRST_TAP;
            // Transaction Context.Context Currency := Transaction Currency Code
            transactionContextByteBuffer.putShort(OFFSET_TRANSACTION_CONTEXT_CONTEXT_CURRENCY, transactionCurrencyCode);
            // Transaction Context.Context Amount := Amount, Authorized (Numeric)
            System.arraycopy(amountAuthorized, 0, 
                             this.transactionContext, OFFSET_TRANSACTION_CONTEXT_CONTEXT_AMOUNT, PayPConstants.LENGTH_AMOUNT);
            // Transaction Context.ACK Status := No ACK
            this.transactionContext[OFFSET_TRANSACTION_CONTEXT_ACK_STATUS] = PayPConstants.TRANSACTION_CONTEXT_ACK_STATUS_NO_ACK;
            // Transaction Context.PIN Status := No PIN
            this.transactionContext[OFFSET_TRANSACTION_CONTEXT_PIN_STATUS] = PayPConstants.TRANSACTION_CONTEXT_PIN_STATUS_NO_PIN;
            // Transaction Context.L&S Exceeded := Lost & Stolen counters not exceeded
            this.transactionContext[OFFSET_TRANSACTION_CONTEXT_LS_EXCEEDED] = PayPConstants.FALSE;
            // Transaction Context.Conflicting Context := Context is not conflicting
            this.transactionContext[OFFSET_TRANSACTION_CONTEXT_CONFLICTING_CONTEXT] = PayPConstants.FALSE;

            // IF 'PIN Pre-entry Allowed' in MChip CVM Issuer Options is set AND 
            //    'Offline PIN Verification Successful' in PIN Verification Status is set
            if (((this.cardProfile.getMchipCvmIssuerOptions() & PayPConstants.CVM_ISSUER_BIT_PIN_PRE_ENTRY_ALLOWED) != (byte) 0x00) && 
                this.pinVerificationSuccessful) {
                // Transaction Context.PIN Status := PIN entered
                this.transactionContext[OFFSET_TRANSACTION_CONTEXT_PIN_STATUS] = PayPConstants.TRANSACTION_CONTEXT_PIN_STATUS_PIN_ENTERED;
            }
            else {
                // Set 'PIN Required' in POS Cardholder Interaction Information
                this.posCardholderInteractionInfo[OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_2] |= PayPConstants.POS_CARDHOLDER_INTERACTION_INFO_BYTE_2_BIT_PIN_REQUIRED;
                // Transaction Context.PIN Status := PIN locked
                this.transactionContext[OFFSET_TRANSACTION_CONTEXT_PIN_STATUS] = PayPConstants.TRANSACTION_CONTEXT_PIN_STATUS_PIN_LOCKED;
                // Set 'CVM Required Is Not Satisfied' in Card Verification Results
                cvr[5] |= PayPConstants.CVR_BYTE_6_BIT_CVM_REQUIRED_IS_NOT_SATISFIED;
            }

            // Perform CRM.
            // 'skipCRM' is already initialized to 'false'.
        }

        if (!skipCRM) {
            // Continue same processing for First Tap and Second Tap.

            // IF (CVM Results [1][6 : 1] = 000001b OR CVM Results [1][6 : 1] = 000100b) AND
            //    CVM Results [3] = '02' AND 
            //    (Transaction Context.PIN Status != PIN Entered))
            byte cvmResultsByte1Bits1to6 = (byte) (cvmResults[0] & (byte) 0x3F);
            if (((cvmResultsByte1Bits1to6 == (byte) 0x01) || (cvmResultsByte1Bits1to6 == (byte) 0x04)) && 
                (cvmResults[2] == (byte) 0x02) && 
                (this.transactionContext[OFFSET_TRANSACTION_CONTEXT_PIN_STATUS] != PayPConstants.TRANSACTION_CONTEXT_PIN_STATUS_PIN_ENTERED)) {
                // Transaction Context.PIN Status := PIN locked
                this.transactionContext[OFFSET_TRANSACTION_CONTEXT_PIN_STATUS] = PayPConstants.TRANSACTION_CONTEXT_PIN_STATUS_PIN_LOCKED;
                // Set 'PIN Required' in POS Cardholder Interaction Information
                this.posCardholderInteractionInfo[OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_2] |= PayPConstants.POS_CARDHOLDER_INTERACTION_INFO_BYTE_2_BIT_PIN_REQUIRED;
                // Set 'CVM Required Is Not Satisfied' in Card Verification Results
                cvr[5] |= PayPConstants.CVR_BYTE_6_BIT_CVM_REQUIRED_IS_NOT_SATISFIED;
                // Set 'Terminal Erroneously Considers Offline PIN OK' in Card Verification Results
                cvr[3] |= PayPConstants.CVR_BYTE_4_BIT_TERMINAL_ERRONEOUSLY_CONSIDERS_OFFLINE_PIN_OK;
            }

            // IF Transaction Context.PIN Status = PIN Entered
            if (this.transactionContext[OFFSET_TRANSACTION_CONTEXT_PIN_STATUS] == PayPConstants.TRANSACTION_CONTEXT_PIN_STATUS_PIN_ENTERED) {
                // Set 'Offline PIN Verification Successful' in Card Verification Results
                cvr[0] |= PayPConstants.CVR_BYTE_1_BIT_OFFLINE_PIN_VERIFICATION_SUCCESSFUL;
            }

            // *** CRM (Card Risk Management) ***

            if (cryptogramType == PayPConstants.GENERATE_AC_P1_CRYPTOGRAM_TYPE_ARQC) {
                // *** ARQC Requested ***

                // IF ('CVR Decisional Part' in Card Verification Results AND Card Issuer Action Code - Decline On ARQC) != '000000'
                if (((cvr[3] & this.cardProfile.getCiacDeclineOnlineCapable()[0]) != (byte) 0x00) || 
                    ((cvr[4] & this.cardProfile.getCiacDeclineOnlineCapable()[1]) != (byte) 0x00) || 
                    ((cvr[5] & this.cardProfile.getCiacDeclineOnlineCapable()[2]) != (byte) 0x00)) {
                    // AAC processing.
                    cryptogramType = PayPConstants.GENERATE_AC_P1_CRYPTOGRAM_TYPE_AAC;
                }
                // else continue ARQC processing.
            }
            else if (cryptogramType == PayPConstants.GENERATE_AC_P1_CRYPTOGRAM_TYPE_TC) {
                // *** TC Requested ***

                // Check if terminal type is offline only.
                if ((terminalType == (byte) 0x13) || 
                    (terminalType == (byte) 0x16) || 
                    (terminalType == (byte) 0x23) || 
                    (terminalType == (byte) 0x26) || 
                    (terminalType == (byte) 0x36)) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }

                // IF ('CVR Decisional Part' in Card Verification Results AND Card Issuer Action Code - Go Online) != '000000'
                if (((cvr[3] & this.cardProfile.getCiacDeclineOnlineCapable()[0]) != (byte) 0x00) || 
                    ((cvr[4] & this.cardProfile.getCiacDeclineOnlineCapable()[1]) != (byte) 0x00) || 
                    ((cvr[5] & this.cardProfile.getCiacDeclineOnlineCapable()[2]) != (byte) 0x00)) {
                    // AAC processing.
                    cryptogramType = PayPConstants.GENERATE_AC_P1_CRYPTOGRAM_TYPE_AAC;
                }
                else {
                    // ARQC processing.
                    cryptogramType = PayPConstants.GENERATE_AC_P1_CRYPTOGRAM_TYPE_ARQC;
                }
            }
            else {
                // *** AAC Requested ***

                // AAC decided.
                cryptogramType = PayPConstants.GENERATE_AC_P1_CRYPTOGRAM_TYPE_AAC;
            }
        }

        // Perform same processing for AAC and ARQC.

        // Reset 'Offline PIN Verification Successful' in PIN Verification Status
        this.pinVerificationSuccessful = false;

        // Perform different processing for AAC and ARQC.
        if (cryptogramType == PayPConstants.GENERATE_AC_P1_CRYPTOGRAM_TYPE_AAC) {
            // *** AAC Processing ***

            // IF Transaction Context.Context Defined != Invalidated context AND
            //    'CVM Required Is Not Satisfied' in CVR is not set
            if ((this.transactionContext[OFFSET_TRANSACTION_CONTEXT_CONTEXT_DEFINED] != PayPConstants.TRANSACTION_CONTEXT_CONTEXT_DEFINED_INVALIDATED_CONTEXT) && 
                ((cvr[5] & PayPConstants.CVR_BYTE_6_BIT_CVM_REQUIRED_IS_NOT_SATISFIED) != PayPConstants.CVR_BYTE_6_BIT_CVM_REQUIRED_IS_NOT_SATISFIED)) {
                // Transaction Context.Context Defined := Previous transaction
                this.transactionContext[OFFSET_TRANSACTION_CONTEXT_CONTEXT_DEFINED] = PayPConstants.TRANSACTION_CONTEXT_CONTEXT_DEFINED_PREVIOUS_CONTEXT;
            }

            // 'AC Returned In First Generate AC' in Card Verification Results := AAC Returned In First Generate AC
            // 'AC Returned In Second Generate AC' in Card Verification Results := AC Not Requested In Second Generate AC
            cvr[0] |= (byte) (PayPConstants.CVR_BYTE_1_AAC_RETURNED_IN_FIRST_GENERATE_AC | 
                              PayPConstants.CVR_BYTE_1_AC_NOT_REQUESTED_IN_SECOND_GENERATE_AC); 

            // 'Type Of Cryptogram' in Cryptogram Information Data := AAC
            cid = PayPConstants.CID_AAC;
        }
        else {
            // *** ARQC Processing ***

            // Transaction Context.Context Defined := Previous transaction
            this.transactionContext[OFFSET_TRANSACTION_CONTEXT_CONTEXT_DEFINED] = PayPConstants.TRANSACTION_CONTEXT_CONTEXT_DEFINED_PREVIOUS_CONTEXT;

            // 'AC Returned In First Generate AC' in Card Verification Results := ARQC Returned In First Generate AC
            // 'AC Returned In Second Generate AC' in Card Verification Results := AC Not Requested In Second Generate AC
            cvr[0] |= (byte) (PayPConstants.CVR_BYTE_1_ARQC_RETURNED_IN_FIRST_GENERATE_AC | 
                              PayPConstants.CVR_BYTE_1_AC_NOT_REQUESTED_IN_SECOND_GENERATE_AC); 

            // 'Type Of Cryptogram' in Cryptogram Information Data := ARQC
            cid = PayPConstants.CID_ARQC;

            // IF 'Combined DDA/AC Generation Requested' in Reference Control Parameter is set
            if (cdaRequested) {
                // Set 'Combined DDA/AC Generation Returned In First Generate AC' in Card Verification Results
                cvr[1] |= PayPConstants.CVR_BYTE_2_BIT_CDA_GENERATION_RETURNED_IN_FIRST_GENERATE_AC;
            }
        }

        // Continue processing for AAC and ARQC.

        // *** Standard Application Cryptogram Generation ***

        PaymentTokenPayloadSingleUseKey ptpSuk = this.arrayPtpSuk.removeFirst();

        //buildCountersField(apduBuffer);

        // CVR Byte 1 in sample transaction is 'A5'. Bit 3 is RFU so not sure what it represents.
        // Set CVR Byte 1 Bit 3 manually.
        cvr[0] |= (byte) 0x04;

        // Build the input for Application Cryptogram generation:
        // Amount, Authorized (Numeric) [6]
        // Amount, Other (Numeric) [6]
        // Terminal Country Code [2]
        // Terminal Verification Results [5]
        // Transaction Currency Code [2]
        // Transaction Date [3]
        // Transaction Type [1]
        // Unpredictable Number [4]
        // Application Interchange Profile [2]
        // Application Transaction Counter [2]
        // Card Verification Results [6]
        final int acInputOffset = 256;
        apduByteBuffer.position(acInputOffset);
        // Move data buffer Amount Authorized to Unpredictable Number.
        apduByteBuffer.put(cdol1RelatedData, 0, 29);
        apduByteBuffer.put(this.cardProfile.getAip());
        apduByteBuffer.putShort(ptpSuk.getAtc());
        apduByteBuffer.put(cvr);

        // Generate Application Cryptogram.
        // Pad first.
        apduByteBuffer.put((byte) 0x80);
        byte[] ac = CryptogramGeneration.generateCvn14Cryptogram(ptpSuk, 
                                                                 apduByteBuffer.array(), 
                                                                 acInputOffset, 
                                                                 apduByteBuffer.position() - acInputOffset);
        if (ac == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Build Issuer Application Data:
        // Key Derivation Index [1]
        // Cryptogram Version Number [1]
        // Card Verification Results [6]
        // DAC/ICC Dyn Nr [2]
        // Plaintext Counters [8]
        byte[] issuerAppData = new byte[PayPConstants.LENGTH_ISSUER_APPLICATION_DATA];
        ByteBuffer issuerAppDataByteBuffer = ByteBuffer.wrap(issuerAppData);
        issuerAppDataByteBuffer.put(this.cardProfile.getKeyDerivationIndex());
        // Cryptogram Version Number for MPP Remote-SE Lite is '14'.
        issuerAppDataByteBuffer.put((byte) 0x14);
        issuerAppDataByteBuffer.put(cvr);
        // IF ICC Dynamic Number (Terminal) = '0000000000000000'
        if (Arrays.equals(iccDynamicNumberTerminal, ZEROS)) {
            // DAC/ICC Dyn Nr := Data Authentication Code
            issuerAppDataByteBuffer.putShort(dataAuthenticationCode);
        }
        else {
            // DAC/ICC Dyn Nr := ICC Dynamic Number (Terminal)[1 : 2]
            issuerAppDataByteBuffer.put(iccDynamicNumberTerminal, 0, 2);
        }
        // Plaintext Counters for MPP Remote-SE Lite is '00 00 00 00 00 00 00 FF'.
        issuerAppDataByteBuffer.put(ZEROS, 0, 7);
        issuerAppDataByteBuffer.put((byte) 0xFF);

        final int sdadOffset = 256;
        int sdadLength = -1;
        // IF 'Combined DDA/AC Generation Requested' in Reference Control Parameter is set
        if ((cid == PayPConstants.CID_ARQC) && cdaRequested) {
            try {
                BigInteger primeP = new BigInteger(1, this.cardProfile.getIccPrivKeyPrimeP());
                BigInteger primeQ = new BigInteger(1, this.cardProfile.getIccPrivKeyPrimeQ());
                BigInteger primeExponentP = new BigInteger(1, this.cardProfile.getIccPrivKeyPrimeExponentP());
                BigInteger primeExponentQ = new BigInteger(1, this.cardProfile.getIccPrivKeyPrimeExponentQ());
                BigInteger crtCoefficient = new BigInteger(1, this.cardProfile.getIccPrivKeyCrtCoefficient());
                BigInteger modulus = primeP.multiply(primeQ);
                RSAPrivateCrtKeySpec iccPrivKeySpec = new RSAPrivateCrtKeySpec(modulus, 
                                                                               null, 
                                                                               null, 
                                                                               primeP, 
                                                                               primeQ, 
                                                                               primeExponentP, 
                                                                               primeExponentQ, 
                                                                               crtCoefficient);
                // Note: Need to use "BC" provider.
                RSAPrivateCrtKey iccPrivKey = (RSAPrivateCrtKey) KeyFactory.getInstance("RSA", "BC").generatePrivate(iccPrivKeySpec);

                sdadLength = OfflineDataAuthentication.generateSdad(ptpSuk, 
                                                                    apduBuffer, 
                                                                    sdadOffset, 
                                                                    this.pdolData, 
                                                                    cdol1RelatedData, 
                                                                    cid, 
                                                                    issuerAppData, 
                                                                    ac, 
                                                                    unpredictableNumber, 
                                                                    this.cardProfile.getIccPubKeyModulusLength(), 
                                                                    iccPrivKey);
            }
            catch (Exception e) {
                Log.e(LOG_TAG, "ICC Private Key not available.");
            }
            if (sdadLength != this.cardProfile.getIccPubKeyModulusLength()) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }

        apduByteBuffer.rewind();
        // Build response.
        apduByteBuffer.put(PayPConstants.TAG_RESPONSE_MESSAGE_TEMPLATE);
        // Skip response message template length.
        apduByteBuffer.put((byte) 0);
        // Append common data elements in response:
        // '9F27' [1] Cryptogram Information Data
        // '9F36' [2] Application Transaction Counter
        apduByteBuffer.putShort(PayPConstants.TAG_CRYPTOGRAM_INFO_DATA);
        apduByteBuffer.put((byte) 1);
        apduByteBuffer.put(cid);
        apduByteBuffer.putShort(PayPConstants.TAG_APPLICATION_TRANSACTION_COUNTER);
        apduByteBuffer.put((byte) 2);
        apduByteBuffer.putShort(ptpSuk.getAtc());
        if ((cid == PayPConstants.CID_ARQC) && cdaRequested && 
            (sdadLength == this.cardProfile.getIccPubKeyModulusLength())) {
            // Data elements in CDA response:
            // '9F27' [1] Cryptogram Information Data
            // '9F36' [2] Application Transaction Counter
            // '9F4B' [Length Of ICC Public Key Modulus] Signed Dynamic Application Data
            // '9F10' [18] Issuer Application Data

            // Append CDA data element in response:
            // '9F4B' [Length Of ICC Public Key Modulus] Signed Dynamic Application Data
            apduByteBuffer.putShort(PayPConstants.TAG_SIGNED_DYNAMIC_APPLICATION_DATA);
            if (sdadLength >= 128) {
                // 2-byte Signed Dynamic Application Data length.
                apduByteBuffer.put((byte) 0x81);
            }
            apduByteBuffer.put((byte) sdadLength);
            apduByteBuffer.put(apduBuffer, sdadOffset, sdadLength);
        }
        else {
            // Data elements in non-CDA response:
            // '9F27' [1] Cryptogram Information Data
            // '9F36' [2] Application Transaction Counter
            // '9F26' [8] Application Cryptogram
            // '9F10' [7 or 18 or 26] Issuer Application Data
            // 'DF4B' [3] POS Cardholder Interaction Information (for AAC only)

            // Append non-CDA data element in response:
            // '9F26' [8] Application Cryptogram
            apduByteBuffer.putShort(PayPConstants.TAG_APPLICATION_CRYPTOGRAM);
            apduByteBuffer.put((byte) ac.length);
            apduByteBuffer.put(ac);
        }
        // Append more common data element in response:
        // '9F10' [18] Issuer Application Data
        apduByteBuffer.putShort(PayPConstants.TAG_ISSUER_APPLICATION_DATA);
        apduByteBuffer.put((byte) issuerAppData.length);
        apduByteBuffer.put(issuerAppData);
        // IF the Application Cryptogram is an AAC
        if (cid == PayPConstants.CID_AAC) {
            // Append data element in AAC only response:
            // 'DF4B' [3] POS Cardholder Interaction Information
            apduByteBuffer.putShort(PayPConstants.TAG_POS_CARDHOLDER_INTERACTION_INFO);
            apduByteBuffer.put((byte) this.posCardholderInteractionInfo.length);
            apduByteBuffer.put(this.posCardholderInteractionInfo);
        }

        // Set response template message length.
        int rdataLength = apduByteBuffer.position();
        if (rdataLength < 130) {
            // 1-byte response template message length.
            apduByteBuffer.put(1, (byte) (rdataLength - 2));
        }
        else {
            // 2-byte response template message length.
            apduByteBuffer.put(1, (byte) 0x81);
            // Shift response template message data.
            System.arraycopy(apduBuffer, 2, apduBuffer, 3, rdataLength - 2);
            apduByteBuffer.put(2, (byte) (rdataLength - 2));
            rdataLength++;
        }

        this.apduState = APDU_SENDING_LAST;

        // DEBUG
        Log.v(LOG_TAG, "R-APDU: " + DataUtil.byteArrayToHexString(apduBuffer, 0, rdataLength) + "9000");

        apdu.setOutgoingLength((short) rdataLength);
        apdu.sendBytes((short) 0, (short) rdataLength);

        // Success triggers a successful transaction.
        apdu.setTransactionSuccess();
    }

    private void sendApduCFailure() throws ISOException {
        sendApduCFailure(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    private void sendApduCFailure(short sw) throws ISOException {
        this.apduState = APDU_SENDING_LAST;

        // DEBUG
        Log.v(LOG_TAG, "R-APDU: " + String.format("%04X", sw));

        try {
            transactionFailure();
        }
        catch (IOException e) {
        }

        this.transactionFailed = true;

        throw new ISOException(sw);
    }

    private String getNonNullMessage(Exception e) {
        String exceptionMessage = e.getMessage();
        if (exceptionMessage == null) {
            exceptionMessage = "null";
        }

        return exceptionMessage;
    }

    private void blockCondition(boolean waitGetCardProfile, 
                                boolean waitGetPtpSuk, 
                                int sleepInterval, 
                                String caller) {
        if (caller == null) {
            caller = "blockCondition";
        }

        // Block until the specified thread(s) has stopped and no longer accessing remote card applet.
        while (((this.tGetCardProfile != null) && waitGetCardProfile) || 
               ((this.tGetPtpSuk != null) && waitGetPtpSuk)) {
            if ((this.tGetCardProfile != null) && waitGetCardProfile) {
                Log.i(LOG_TAG, caller + ", tGetCardProfile is still accessing remote card applet, waiting...");
            }
            if ((this.tGetPtpSuk != null) && waitGetPtpSuk) {
                Log.i(LOG_TAG, caller + ", tGetPtpSuk is still accessing remote card applet, waiting...");
            }

            try {
                Thread.sleep(sleepInterval);
            }
            catch (InterruptedException e) {
            }
        }
    }

    private void getCardProfile() {
        if (this.tGetCardProfile != null) {
            Log.i(LOG_TAG, "getCardProfile, tGetCardProfile is still accessing remote card applet.");
            return;
        }

        // Block until 'tGetPtpSuk' thread has stopped before continuing.
        blockCondition(false, true, 200, "getCardProfile");

        // NOTE: This thread calls 'setBusy' method when it starts and 'clearBusy' when it stops to 
        //       block agent from processing contactless transaction while the thread is running.
        this.tGetCardProfile = new Thread(new Runnable() {
            public void run() {
                try {
                    setBusy();
                }
                catch (IOException e) {
                    Log.e(LOG_TAG, "tGetCardProfile setBusy IOException Log", e);

                    try {
                        postMessage("Card Agent Not Available to\n" + 
                                    "Get Card Profile\n" + 
                                    "Exception: " + getNonNullMessage(e), false, null);
                    }
                    catch (IOException e1) {
                    }

                    tGetCardProfile = null;
                    return;
                }

                try {
                    connect();
                }
                catch (IOException e) {
                    Log.e(LOG_TAG, "tGetCardProfile connect IOException Log", e);

                    try {
                        disconnect();
                    }
                    catch (IOException e1) {
                    }

                    if (getNonNullMessage(e).equalsIgnoreCase("SOCKET_ERR")) {
                        if (connectRetryCounter < MAX_CONNECT_RETRY) {
                            connectRetryCounter++;

                            try {
                                clearBusy();
                            }
                            catch (IOException e1) {
                            }

                            tGetCardProfile = null;

                            // Retry getCardProfile.
                            getCardProfile();

                            return;
                        }
                    }

                    try {
                        postMessage("No Connection Available to\n" + 
                                    "Get Card Profile\n" + 
                                    "Exception: " + getNonNullMessage(e), false, null);
                    }
                    catch (IOException e1) {
                    }

                    try {
                        clearBusy();
                    }
                    catch (IOException e1) {
                    }

                    tGetCardProfile = null;
                    return;
                }

                TransceiveData getCardData = new TransceiveData(TransceiveData.SOFT_CHANNEL);
                getCardData.packCardReset(false);
                getCardData.packApdu(APDU_SELECT_CARDAPPLET, true);
                getCardData.packApdu(APDU_GET_MOBILE_KEY, true);
                getCardData.packApdu(APDU_GET_CARDPROFILE, true);
                try {
                    transceive(getCardData);
                }
                catch (IOException e) {
                    Log.e(LOG_TAG, "tGetCardProfile transceive(getCardData) IOException Log", e);

                    try {
                        disconnect();
                    }
                    catch (IOException e1) {
                    }

                    try {
                        postMessage("Get Card Profile Error\n" + 
                                    "Exception: " + getNonNullMessage(e), false, null);
                    }
                    catch (IOException e1) {
                    }

                    try {
                        clearBusy();
                    }
                    catch (IOException e1) {
                    }

                    tGetCardProfile = null;
                    return;
                }

                byte[] selectResponse = getCardData.getNextResponse();
                if ((selectResponse == null) || 
                    (selectResponse.length <= 2) || 
                    (ByteBuffer.wrap(selectResponse).getShort(selectResponse.length - 2) != ISO7816.SW_NO_ERROR)) {
                    String invalidResponse = DataUtil.byteArrayToHexString(selectResponse);
                    Log.e(LOG_TAG, "Invalid selectResponse: " + invalidResponse);

                    try {
                        disconnect();
                    }
                    catch (IOException e) {
                    }

                    try {
                        if ((invalidResponse.length() == 4) && 
                            invalidResponse.equalsIgnoreCase(String.format("%04X", ISO7816.SW_FUNC_NOT_SUPPORTED))) {
                            terminated = true;
                            disabled = true;

                            cardProfile = null;
                            arrayPtpSuk = null;

                            postMessage("Account is Terminated", false, null);
                        }
                        else {
                            postMessage("Account Not Available", false, null);
                        }
                    }
                    catch (IOException e) {
                    }

                    try {
                        clearBusy();
                    }
                    catch (IOException e) {
                    }

                    tGetCardProfile = null;
                    return;
                }

                byte[] mobileKey = getCardData.getNextResponse();
                if ((mobileKey != null) && 
                    (mobileKey.length == 34) && 
                    (ByteBuffer.wrap(mobileKey).getShort(mobileKey.length - 2) == ISO7816.SW_NO_ERROR)) {
                    // Extract Mobile Key without SW.
                    mobileKey = Arrays.copyOf(mobileKey, mobileKey.length - 2);
                }
                else {
                    Log.e(LOG_TAG, "Invalid mobileKey: " + DataUtil.byteArrayToHexString(mobileKey));

                    try {
                        disconnect();
                    }
                    catch (IOException e) {
                    }

                    try {
                        postMessage("Invalid Mobile Key", false, null);
                    }
                    catch (IOException e) {
                    }

                    try {
                        clearBusy();
                    }
                    catch (IOException e) {
                    }

                    tGetCardProfile = null;
                    return;
                }
                mKey = new SecretKeySpec(mobileKey, "AES");

                byte[] cardProfileData = getCardData.getNextResponse();
                if ((cardProfileData != null) && 
                    (cardProfileData.length > 2) && 
                    (ByteBuffer.wrap(cardProfileData).getShort(cardProfileData.length - 2) == ISO7816.SW_NO_ERROR)) {
                    // Reset 'disabled' in case agent was in disabled state.
                    disabled = false;

                    // Extract Card Profile data without SW.
                    cardProfileData = Arrays.copyOf(cardProfileData, cardProfileData.length - 2);

                    // NOTE: Kludge to check 'FF FF FF FF' in card profile data that indicates Mobile PIN not initialized.
                    if (ByteBuffer.wrap(cardProfileData).getInt() == (int) 0xFFFFFFFF) {
                        // Remove 'FF FF FF FF'.
                        cardProfileData = Arrays.copyOfRange(cardProfileData, 4, cardProfileData.length);
                    }

                    ByteArrayInputStream bis = new ByteArrayInputStream(cardProfileData);
                    ObjectInput in = null;
                    try {
                        in = new ObjectInputStream(bis);
                        cardProfile = (CardProfile) in.readObject();
                    }
                    catch (Exception e) {
                        Log.e(LOG_TAG, "Cannot serialize cardProfileData: " + DataUtil.byteArrayToHexString(cardProfileData));

                        try {
                            postMessage("Card Profile Format Error\n" + 
                                        "Exception: " + getNonNullMessage(e), false, null);
                        }
                        catch (IOException e1) {
                        }
                    }
                    finally {
                        try {
                            bis.close();
                        }
                        catch (IOException ioe) {
                        }

                        try {
                            if (in != null) {
                                in.close();
                            }
                        }
                        catch (IOException ioe) {
                        }
                    }
                }
                else {
                    String invalidResponse = DataUtil.byteArrayToHexString(cardProfileData);
                    Log.e(LOG_TAG, "Invalid cardProfileData: " + invalidResponse);

                    try {
                        if ((invalidResponse.length() == 4) && 
                            invalidResponse.equalsIgnoreCase(String.format("%04X", ISO7816.SW_COMMAND_NOT_ALLOWED))) {
                            disabled = true;

                            cardProfile = null;
                            arrayPtpSuk = null;

                            postMessage("Account is Disabled", false, null);
                        }
                        else {
                            postMessage("Invalid Card Profile Data", false, null);
                        }
                    }
                    catch (IOException e) {
                    }
                }
                if (cardProfile == null) {
                    try {
                        disconnect();
                    }
                    catch (IOException e) {
                    }

                    try {
                        clearBusy();
                    }
                    catch (IOException e) {
                    }

                    tGetCardProfile = null;
                    return;
                }
                else {
                    // DEBUG
                    try {
                        Log.v(LOG_TAG, "cardProfile Aid: " + DataUtil.byteArrayToHexString(cardProfile.getAid()));
                        Log.v(LOG_TAG, "cardProfile AidPpse: " + DataUtil.byteArrayToHexString(cardProfile.getAidPpse()));
                        Log.v(LOG_TAG, "cardProfile PpseResponse: " + DataUtil.byteArrayToHexString(cardProfile.getPpseResponse()));
                        Log.v(LOG_TAG, "cardProfile TagA5Data: " + DataUtil.byteArrayToHexString(cardProfile.getTagA5Data()));
                        Log.v(LOG_TAG, "cardProfile Aip: " + DataUtil.byteArrayToHexString(cardProfile.getAip()));
                        Log.v(LOG_TAG, "cardProfile Afl: " + DataUtil.byteArrayToHexString(cardProfile.getAfl()));
                        Log.v(LOG_TAG, "cardProfile Sfi1Record1: " + DataUtil.byteArrayToHexString(cardProfile.getSfi1Record1()));
                        Log.v(LOG_TAG, "cardProfile Sfi2Record1: " + DataUtil.byteArrayToHexString(cardProfile.getSfi2Record1()));
                        Log.v(LOG_TAG, "cardProfile Sfi2Record2: " + DataUtil.byteArrayToHexString(cardProfile.getSfi2Record2()));
                        Log.v(LOG_TAG, "cardProfile Sfi2Record3: " + DataUtil.byteArrayToHexString(cardProfile.getSfi2Record3()));
                        Log.v(LOG_TAG, "cardProfile Cdol1RelatedDataLength: " + String.format("%02X", cardProfile.getCdol1RelatedDataLength()));
                        Log.v(LOG_TAG, "cardProfile MchipCvmIssuerOptions: " + String.format("%02X", cardProfile.getMchipCvmIssuerOptions()));
                        Log.v(LOG_TAG, "cardProfile CrmCountryCode: " + String.format("%04X", cardProfile.getCrmCountryCode()));
                        Log.v(LOG_TAG, "cardProfile CiacDeclineOnlineCapable: " + DataUtil.byteArrayToHexString(cardProfile.getCiacDeclineOnlineCapable()));
                        Log.v(LOG_TAG, "cardProfile KeyDerivationIndex: " + String.format("%02X", cardProfile.getKeyDerivationIndex()));
                        Log.v(LOG_TAG, "cardProfile ApplicationControl: " + DataUtil.byteArrayToHexString(cardProfile.getApplicationControl()));
                        Log.v(LOG_TAG, "cardProfile AdditionalCheckTable: " + DataUtil.byteArrayToHexString(cardProfile.getAdditionalCheckTable()));
                        Log.v(LOG_TAG, "cardProfile DualTapResetTimeout: " + String.format("%04X", cardProfile.getDualTapResetTimeout()));
                        //Log.v(LOG_TAG, "cardProfile SecurityWord: " + DataUtil.byteArrayToHexString(cardProfile.getSecurityWord()));
                        Log.v(LOG_TAG, "cardProfile CvmResetTimeout: " + String.format("%04X", cardProfile.getCvmResetTimeout()));
                        Log.v(LOG_TAG, "cardProfile MagstripeCvmIssuerOptions: " + String.format("%02X", cardProfile.getMagstripeCvmIssuerOptions()));
                        Log.v(LOG_TAG, "cardProfile CiacDeclinePpms: " + DataUtil.byteArrayToHexString(cardProfile.getCiacDeclinePpms()));
                        //Log.v(LOG_TAG, "cardProfile PinIvCvc3Track1: " + DataUtil.byteArrayToHexString(cardProfile.getPinIvCvc3Track1()));
                        //Log.v(LOG_TAG, "cardProfile PinIvCvc3Track2: " + DataUtil.byteArrayToHexString(cardProfile.getPinIvCvc3Track2()));
                        Log.v(LOG_TAG, "cardProfile IccPubKeyModulusLength: " + String.format("%02X", cardProfile.getIccPubKeyModulusLength()));
                        //Log.v(LOG_TAG, "cardProfile IccPrivKeyPrimeP: " + DataUtil.byteArrayToHexString(cardProfile.getIccPrivKeyPrimeP()));
                        //Log.v(LOG_TAG, "cardProfile IccPrivKeyPrimeQ: " + DataUtil.byteArrayToHexString(cardProfile.getIccPrivKeyPrimeQ()));
                        //Log.v(LOG_TAG, "cardProfile IccPrivKeyPrimeExponentP: " + DataUtil.byteArrayToHexString(cardProfile.getIccPrivKeyPrimeExponentP()));
                        //Log.v(LOG_TAG, "cardProfile IccPrivKeyPrimeExponentQ: " + DataUtil.byteArrayToHexString(cardProfile.getIccPrivKeyPrimeExponentQ()));
                        //Log.v(LOG_TAG, "cardProfile IccPrivKeyCrtCoefficient: " + DataUtil.byteArrayToHexString(cardProfile.getIccPrivKeyCrtCoefficient()));
                        Log.v(LOG_TAG, "cardProfile MaxNumberPtpSuk: " + cardProfile.getMaxNumberPtpSuk());
                        Log.v(LOG_TAG, "cardProfile MinThresholdNumberPtpSuk: " + cardProfile.getMinThresholdNumberPtpSuk());
                    }
                    catch (Exception e) {
                        Log.e(LOG_TAG, "cardProfile Debug Exception Log", e);
                    }
                }

                final int maxNumberPtpSuk = cardProfile.getMaxNumberPtpSuk();
                arrayPtpSuk = new ArrayDeque<PaymentTokenPayloadSingleUseKey>(maxNumberPtpSuk);

                final int addNumberPtpSuk = maxNumberPtpSuk - arrayPtpSuk.size();
                if (addNumberPtpSuk <= 0) {
                    try {
                        disconnect();
                    }
                    catch (IOException e) {
                    }

                    try {
                        clearBusy();
                    }
                    catch (IOException e) {
                    }

                    tGetCardProfile = null;
                    return;
                }

                TransceiveData tranceiveDataGetPtpSuk = new TransceiveData(TransceiveData.SOFT_CHANNEL);
                int numberPtpSuk = 0;
                while (numberPtpSuk < addNumberPtpSuk) {
                    tranceiveDataGetPtpSuk.packApdu(APDU_GET_PTPSUK, true);
                    numberPtpSuk++;
                }
                try {
                    transceive(tranceiveDataGetPtpSuk);
                }
                catch (IOException e) {
                    Log.e(LOG_TAG, "tGetCardProfile transceive(tranceiveDataGetPtpSuk) IOException Log", e);

                    try {
                        postMessage("Get PTP_SUK Error\n" + 
                                    "Exception: " + getNonNullMessage(e), false, null);
                    }
                    catch (IOException e1) {
                    }
                }

                try {
                    disconnect();
                }
                catch (IOException e) {
                }

                numberPtpSuk = 0;
                while (numberPtpSuk < addNumberPtpSuk) {
                    syncGetPtpSuk(tranceiveDataGetPtpSuk.getNextResponse());
                    numberPtpSuk++;
                }

                try {
                    clearBusy();
                }
                catch (IOException e) {
                }

                tGetCardProfile = null;
            }
        });

        this.tGetCardProfile.start();
    }

    private void getPtpSuk(final boolean checkMinThreshold) {
        // Block until 'tGetPtpSuk' thread has stopped before continuing.
        blockCondition(false, true, 200, "getPtpSuk");

        if ((this.cardProfile == null) && !this.disabled) {
            try {
                postMessage("Missing Card Data\nPlease Check Connection is Available and Refresh Card", false, null);
            }
            catch (IOException e) {
            }
            return;
        }

        if (checkMinThreshold && 
            (this.arrayPtpSuk.size() > this.cardProfile.getMinThresholdNumberPtpSuk())) {
            //Log.i(LOG_TAG, "Not yet minimum threshold number of PTP_SUK.");
            return;
        }

        final int addNumberPtpSuk = this.cardProfile.getMaxNumberPtpSuk() - this.arrayPtpSuk.size();
        if (addNumberPtpSuk <= 0) {
            Log.i(LOG_TAG, "Already maximum number of PTP_SUK.");
            return;
        }

        // Block until 'tGetCardProfile' thread has stopped before continuing.
        blockCondition(true, false, 200, "getPtpSuk");

        // NOTE: This thread does not call 'setBusy' method so agent is not blocked from processing 
        //       contactless transaction while the thread is running.
        this.tGetPtpSuk = new Thread(new Runnable() {
            public void run() {
                try {
                    connect();
                }
                catch (IOException e) {
                    Log.e(LOG_TAG, "tGetPtpSuk connect IOException Log", e);

                    try {
                        disconnect();
                    }
                    catch (IOException e1) {
                    }

                    if (getNonNullMessage(e).equalsIgnoreCase("SOCKET_ERR")) {
                        if (connectRetryCounter < MAX_CONNECT_RETRY) {
                            connectRetryCounter++;

                            tGetPtpSuk = null;

                            // Retry getPtpSuk.
                            getPtpSuk(checkMinThreshold);

                            return;
                        }
                    }

                    try {
                        postMessage("No Connection Available to\n" + 
                                    "Get More PTP_SUK\n" + 
                                    arrayPtpSuk.size() + " Transactions Remaining\n" + 
                                    "Exception: " + getNonNullMessage(e), false, null);
                    }
                    catch (IOException e1) {
                    }

                    tGetPtpSuk = null;
                    return;
                }

                TransceiveData tranceiveDataGetPtpSuk = new TransceiveData(TransceiveData.SOFT_CHANNEL);
                tranceiveDataGetPtpSuk.packCardReset(false);
                tranceiveDataGetPtpSuk.packApdu(APDU_SELECT_CARDAPPLET, true);
                int numberPtpSuk = 0;
                while (numberPtpSuk < addNumberPtpSuk) {
                    tranceiveDataGetPtpSuk.packApdu(APDU_GET_PTPSUK, true);
                    numberPtpSuk++;
                }
                try {
                    transceive(tranceiveDataGetPtpSuk);
                }
                catch (IOException e) {
                    Log.e(LOG_TAG, "tGetPtpSuk transceive IOException Log", e);

                    // Indicate exception occurred.
                    numberPtpSuk = -1;

                    try {
                        postMessage("Get PTP_SUK Error\n" + 
                                    "Exception: " + getNonNullMessage(e), false, null);
                    }
                    catch (IOException e1) {
                    }
                }

                try {
                    disconnect();
                }
                catch (IOException e) {
                }

                // Check if error already occurred.
                if (numberPtpSuk != -1) {
                    byte[] selectResponse = tranceiveDataGetPtpSuk.getNextResponse();
                    if ((selectResponse == null) || 
                        (selectResponse.length <= 2) || 
                        (ByteBuffer.wrap(selectResponse).getShort(selectResponse.length - 2) != ISO7816.SW_NO_ERROR)) {
                        String invalidResponse = DataUtil.byteArrayToHexString(selectResponse);
                        Log.e(LOG_TAG, "Invalid selectResponse: " + invalidResponse);

                        try {
                            if ((invalidResponse.length() == 4) && 
                                invalidResponse.equalsIgnoreCase(String.format("%04X", ISO7816.SW_FUNC_NOT_SUPPORTED))) {
                                terminated = true;
                                disabled = true;

                                cardProfile = null;
                                arrayPtpSuk = null;

                                postMessage("Account is Terminated", false, null);
                            }
                            else {
                                postMessage("Account Not Available", false, null);
                            }
                        }
                        catch (IOException e) {
                        }

                        tGetPtpSuk = null;
                        return;
                    }

                    numberPtpSuk = 0;
                    while (numberPtpSuk < addNumberPtpSuk) {
                        syncGetPtpSuk(tranceiveDataGetPtpSuk.getNextResponse());
                        numberPtpSuk++;
                    }
                }

                tGetPtpSuk = null;
            }
        });

        this.tGetPtpSuk.start();
    }

    private synchronized void syncGetPtpSuk(byte[] ptpSukData) {
        if ((ptpSukData != null) && 
            (ptpSukData.length > 2) && 
            (ByteBuffer.wrap(ptpSukData).getShort(ptpSukData.length - 2) == ISO7816.SW_NO_ERROR)) {
            // Extract PTP_SUK data without SW.
            ptpSukData = Arrays.copyOf(ptpSukData, ptpSukData.length - 2);

            PaymentTokenPayloadSingleUseKey ptpSuk = null;

            ByteArrayInputStream bis = new ByteArrayInputStream(ptpSukData);
            ObjectInput in = null;
            try {
                in = new ObjectInputStream(bis);
                ptpSuk = (PaymentTokenPayloadSingleUseKey) in.readObject();
            }
            catch (Exception e) {
                Log.e(LOG_TAG, "Cannot serialize ptpSukData: " + DataUtil.byteArrayToHexString(ptpSukData));

                try {
                    postMessage("PTP_SUK Format Error\n" + 
                                "Exception: " + getNonNullMessage(e), false, null);
                }
                catch (IOException e1) {
                }
            }
            finally {
                try {
                    bis.close();
                }
                catch (IOException ioe) {
                }

                try {
                    if (in != null) {
                        in.close();
                    }
                }
                catch (IOException ioe) {
                }
            }

            if (ptpSuk != null) {
                // DEBUG
                try {
                    //Log.v(LOG_TAG, "PTP_SUK PtpCpTruncatedHash: " + DataUtil.byteArrayToHexString(ptpSuk.getPtpCpTruncatedHash()));
                    Log.v(LOG_TAG, "PTP_SUK Atc: " + String.format("%04X", ptpSuk.getAtc()));
                    //Log.v(LOG_TAG, "PTP_SUK Suk: " + DataUtil.byteArrayToHexString(ptpSuk.getSuk()));
                    //Log.v(LOG_TAG, "PTP_SUK Idn: " + DataUtil.byteArrayToHexString(ptpSuk.getIdn()));
                }
                catch (Exception e) {
                    Log.e(LOG_TAG, "ptpSuk Debug Exception Log", e);
                }

                // Calculate Card Profile hash.
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ObjectOutput out = null;
                try {
                    out = new ObjectOutputStream(bos);
                    out.writeObject(cardProfile);
                    byte[] cardProfileBytes = bos.toByteArray();

                    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                    byte[] generatedPtpCpHash = sha256.digest(cardProfileBytes);
                    if (Arrays.equals(Arrays.copyOf(generatedPtpCpHash, 24), ptpSuk.getPtpCpTruncatedHash())) {
                        // Hash matched.
                        arrayPtpSuk.add(ptpSuk);
                    }
                    else {
                        try {
                            postMessage("Corrupted PTP_SUK Error", false, null);
                        }
                        catch (IOException e1) {
                        }
                    }
                }
                catch (Exception e) {
                }
                finally {
                    try {
                        if (out != null) {
                            out.close();
                        }
                    }
                    catch (IOException ex) {
                    }

                    try {
                        bos.close();
                    }
                    catch (IOException ex) {
                    }
                }
            }
        }
        else {
            String invalidResponse = DataUtil.byteArrayToHexString(ptpSukData);
            Log.e(LOG_TAG, "Invalid ptpSukData: " + invalidResponse);

            try {
                if ((invalidResponse.length() == 4) && 
                    invalidResponse.equalsIgnoreCase(String.format("%04X", ISO7816.SW_COMMAND_NOT_ALLOWED))) {
                    disabled = true;

                    cardProfile = null;
                    arrayPtpSuk = null;

                    postMessage("Account is Disabled", false, null);
                }
                else {
                    postMessage("Invalid PTP_SUK Data", false, null);
                }
            }
            catch (IOException e) {
            }
        }
    }

}
