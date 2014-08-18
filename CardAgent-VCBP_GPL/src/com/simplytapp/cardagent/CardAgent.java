/**
 * This file is part of CardAgent-VCBP which is card agent implementation 
 * of V Cloud-Based Payments for SimplyTapp mobile platform.
 * Copyright 2014 SimplyTapp, Inc.
 * 
 * CardAgent-VCBP is free software: you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License, or 
 * (at your option) any later version.
 * 
 * CardAgent-VCBP is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License 
 * along with CardAgent-VCBP.  If not, see <http://www.gnu.org/licenses/>.
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
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import com.simplytapp.cardagent.vcbp.crypto.CryptogramGeneration;
import com.simplytapp.cardagent.vcbp.crypto.OfflineDataAuthentication;
import com.simplytapp.virtualcard.Agent;
import com.simplytapp.virtualcard.ApprovalData;
import com.simplytapp.virtualcard.CardAgentConnector;
import com.simplytapp.virtualcard.TransceiveData;
import com.st.vcbp.data.AccountParamsDynamic;
import com.st.vcbp.data.AccountParamsStatic;
import com.st.vcbp.data.LinkedHashMapFixedSize;
import com.st.vcbp.data.TransactionVerificationLog;

/**
 * Implementation of Card Agent based on V Cloud-Based Payments Contactless
 * Specifications Version 1.3 July 2014.
 * 
 * @author SimplyTapp, Inc.
 * @version 1.3.1 GPL
 */
public final class CardAgent extends Agent {

    private static final String LOG_TAG = CardAgent.class.getSimpleName();

    private static final long serialVersionUID = 1L;

    private static final String GCM_MSG_ACCOUNT_PARAMETERS_UPDATE = "apupdate";
    private static final String GCM_MSG_DEACTIVATE                = "deactivate";
    private static final String GCM_MSG_TERMINATE                 = "terminate";

    // Supported APDU commands.
    private static final byte INS_SELECT = (byte) 0xA4;
    private static final byte INS_GPO    = (byte) 0xA8;
    private static final byte INS_RR     = (byte) 0xB2;

    // APDU state definitions.
    private static final byte APDU_SENT         = (byte) 0x00;
    private static final byte APDU_SENDING      = (byte) 0x01;
    private static final byte APDU_SENDING_LAST = (byte) 0x02;

    // Transaction state definitions.
    private static final byte TRANSACTION_START  = (byte) 0x00;
    private static final byte TRANSACTION_SELECT = (byte) 0x01;
    private static final byte TRANSACTION_GPO    = (byte) 0x02;
    private static final byte TRANSACTION_RR     = (byte) 0x03;

    // V Payment AID
    private static final byte[] V_PAYMENT_AID = {
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x10, (byte) 0x10
    };

    //================================================================
    // APDUs to communicate with remote card applet.
    //================================================================
    private static final byte[] APDU_SELECT_CARDAPPLET = { 
        (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x07, 
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x10, (byte) 0x10, 
        (byte) 0x00
    };

    // NOTE: Use extended APDU format.
    private static final byte[] APDU_GET_STATIC_ACCOUNT_PARAMETERS = {
        (byte) 0x80, (byte) 0x30, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00
    };

    // NOTE: Use extended APDU format.
    private static final byte[] APDU_GET_DYNAMIC_ACCOUNT_PARAMETERS = {
        (byte) 0x80, (byte) 0x32, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00
    };

    // NOTE: Use extended APDU format. APDU header does not include 2-byte Lc. 
    private static final byte[] APDU_HEADER_PUT_TRANSACTION_VERIFICATION_LOG = {
        (byte) 0x80, (byte) 0x34, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };
    //================================================================

    private transient byte apduState = APDU_SENT;

    private transient byte transactionState = TRANSACTION_START;

    private transient boolean selected = false;
    private transient boolean transactionFailed = false;
    private transient boolean transactionStartFailed = false;
    private transient boolean disabled = false;
    private transient boolean terminated = false;

    // Threads to access remote card applet.
    private transient Thread tGetAccountParams;
    private transient Thread tGetDynamicAccountParams;
    private transient Thread tPutTransactionVerificationLog;

    private static final int MAX_CONNECT_RETRY = 3;
    private transient int connectRetryCounter;

    private static final int MAX_TRANSCEIVE_RETRY = 3;
    private transient int transceiveRetryCounter;

    // Card data.
    private AccountParamsStatic accountParamsStatic;
    private ArrayDeque<AccountParamsDynamic> arrayAccountParamsDynamic;

    // Card data for ODA.
    private RSAPrivateCrtKey iccPrivKey;

    private LinkedHashMapFixedSize<String, TransactionVerificationLog> transactionVerificationLogs;

    private boolean readyToPay;

    // Transaction data to keep track of across different APDUs.
    private transient ByteBuffer afl;
    private transient int aflRecords;
    private transient int readRecordCounter;
    private transient byte[] dynamicSfi2Record4;  // For ODA.

    // Transaction data to save in Transaction Verification Log.
    private transient String accountParametersIndex;
    private transient byte transactionType;
    private transient String unpredictableNumber;

    private transient int checkInternalTimeToExpire = 0;
    private transient long startTime;  // DEBUG
    private transient Thread tTimeToExpire;
    private transient Handler handlerTimeToExpire;
    private transient Runnable runnableTimeToExpire;

    // DEBUG
    private transient long transactionStartTime;

    public CardAgent() {
        allowNfcTransactions();
        denySoftTransactions();
        denySocketTransactions();

        setAidCategory("payment");
        //setAidCategory(AID_CATEGORY_PAYMENT);
        try {
            registerAid(V_PAYMENT_AID);
        }
        catch (IOException e) {
        }
    }

    public static void install(CardAgentConnector cardAgentConnector) {
        new CardAgent().register(cardAgentConnector);
    }

    @Override
    public void create() {
        try {
            this.tTimeToExpire = new Thread(new Runnable() {
                public void run() {
                    try {
                        // preparing a looper on current thread
                        // the current thread is being detected implicitly
                        Looper.prepare();

                        // the handler will automatically bind to the Looper that is attached to the current thread
                        handlerTimeToExpire = new Handler();

                        // the thread will start running the message loop and will not normally exit the loop 
                        // unless a problem happens or you quit() the looper
                        Looper.loop();
                    }
                    catch (Throwable t) {
                        Log.e(LOG_TAG, "tTimeToExpire run Exception Log", t);
                    }
                }
            });
            this.tTimeToExpire.start();

            this.runnableTimeToExpire = new Runnable() {
                public void run() {
                    // Check if Dynamic Account Parameters are expired.
                    checkTimeToLive();

                    handlerTimeToExpire.postDelayed(this, checkInternalTimeToExpire);
                }
            };
        }
        catch (Exception e) {
            Log.e(LOG_TAG, "create Exception Log", e);
        }

        // Retrieve Account Parameters when card is created.
        this.connectRetryCounter = 0;
        this.transceiveRetryCounter= 0; 
        getAccountParams();
    }

    private synchronized void checkTimeToLive() {
        // DEBUG
        long millis = System.currentTimeMillis() - this.startTime;
        int seconds = (int) (millis / 1000);
        int minutes = seconds / 60;
        seconds = seconds % 60;
        Log.i(LOG_TAG, "checkTimeToLive Timestamp=" + System.currentTimeMillis() + 
                       String.format(" %d:%02d since provision", minutes, seconds));

        if ((this.accountParamsStatic != null) && 
            (this.arrayAccountParamsDynamic != null) && 
            !this.arrayAccountParamsDynamic.isEmpty()) {
            final long nextCheckTimestamp = System.currentTimeMillis() + this.checkInternalTimeToExpire;
            boolean removedAccountParamsDynamic = false;
            Iterator<AccountParamsDynamic> iteratorAccountParamsDynamic = this.arrayAccountParamsDynamic.iterator();
            while (iteratorAccountParamsDynamic.hasNext()) {
                final long expirationTimestamp = iteratorAccountParamsDynamic.next().getExpirationTimestamp();
                // Check if Dynamic Account Parameters will expire before the next check. 
                if ((expirationTimestamp != 0) && 
                    (nextCheckTimestamp >= expirationTimestamp)) {
                    this.arrayAccountParamsDynamic.remove();

                    removedAccountParamsDynamic = true;

                    // DEBUG
                    Log.v(LOG_TAG, "Removed soon to expire dynamic account parameters, ExpirationTimestamp=" + expirationTimestamp);
                }
            }

            if (removedAccountParamsDynamic) {
                // Provision additional Dynamic Account Parameters.
                this.connectRetryCounter = 0;
                this.transceiveRetryCounter = 0;
                getDynamicAccountParams(false);
            }
        }
    }

    // Called when press "Pay" button (for Activate On Touch) or when selecting Card Always Activated setting.
    @Override
    public void activated() {
        //Log.i(LOG_TAG, "activated");

        if (this.tGetAccountParams != null) {
            // Wait until 'tGetAccountParams' thread has stopped before performing transaction checks.
            blockCondition(true, false, false, 100, "activated");

            // Provide enough time for message generated in 'tGetAccountParams' thread to be displayed on screen. 
            try {
                Thread.sleep(3000);
            }
            catch (InterruptedException e) {
            }
        }

        performTransactionChecks(true);
    }

	// Perform transaction initialization checks.
    private void performTransactionChecks(boolean activating) {
        if ((this.accountParamsStatic == null) || 
            (this.arrayAccountParamsDynamic == null) || 
            (this.arrayAccountParamsDynamic.size() == 0)) {
            // If transaction started, set flag immediately so 'process' method can check flag in time.  
            if (!activating) {
                this.transactionStartFailed = true;

                this.readyToPay = false;
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
                else if ((this.accountParamsStatic == null) || (this.arrayAccountParamsDynamic == null)) {
                    postMessage("Missing Account Parameters\n" + 
                                "Please Check Connection is Available and Refresh Card", 
                                false, null);
                }
                else {
                    postMessage("No Dynamic Account Parameters\n" + 
                                "to Perform Transactions\n" + 
                                "Attempting to Replenish Account Parameter...", 
                                false, null);
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

                if (this.transactionVerificationLogs != null) {
                    // Save transaction data in Transaction Verification Log.
                    TransactionVerificationLog transactionVerificationLog = new TransactionVerificationLog(this.accountParametersIndex, 
                                                                                                           this.transactionType, 
                                                                                                           this.unpredictableNumber);
                    this.transactionVerificationLogs.put(String.valueOf(transactionVerificationLog.getUtcTimestamp()),
                                                         transactionVerificationLog);

                    // Attempt to save Transaction Verification Log in remote card applet.
                    putTransactionVerificationLog();
                }
            }
        }

        this.apduState = APDU_SENT;
    }

    /* 
     * Called when first acceptable Selected APDU (contained in aid_list.xml) is received.
     * Note: Not called for subsequent transactions while device is still in reader field.
     * 
     * (non-Javadoc)
     * @see com.simplytapp.virtualcard.Agent#transactionStarted()
     */
    @Override
    public void transactionStarted() {
        // DEBUG
        this.transactionStartTime = System.currentTimeMillis();
        Log.i(LOG_TAG, "transactionStarted Timestamp=" + this.transactionStartTime);

        this.transactionState = TRANSACTION_START;

        // Initialize transaction data.
        this.afl = null;
        this.aflRecords = 0;
        this.readRecordCounter = 0;
        this.dynamicSfi2Record4 = null;
        this.accountParametersIndex = null;
        this.transactionType = (byte) 0;
        this.unpredictableNumber = null;

        // NOTE: Workaround for non-VCP specific apps.
        this.readyToPay = true;

        // Perform transaction checks.
        performTransactionChecks(false);
    }

    /*
     * Called when device is removed from field.
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

        // Reset transaction data.
        this.afl = null;
        this.aflRecords = 0;
        this.readRecordCounter = 0;
        this.dynamicSfi2Record4 = null;
        this.accountParametersIndex = null;
        this.transactionType = (byte) 0;
        this.unpredictableNumber = null;

        // NOTE: Workaround for non-VCP specific apps.
        this.readyToPay = false;

        this.apduState = APDU_SENT;

        // Provision additional Dynamic Account Parameters if minimum threshold is reached.
        this.connectRetryCounter = 0;
        this.transceiveRetryCounter = 0;
        getDynamicAccountParams(true);

        // Update the state of the class.
        try {
            saveState();
        }
        catch (IOException e) {
        }
    }

    private void blockCondition(boolean waitGetAccountParams, 
                                boolean waitGetDynamicAccountParams, 
                                boolean waitPutTransactionVerificationLog, 
                                int sleepInterval, 
                                String caller) {
        if (caller == null) {
            caller = "blockCondition";
        }

        // Block until the specified thread(s) has stopped and no longer accessing remote card applet.
        while (((this.tGetAccountParams != null) && waitGetAccountParams) || 
               ((this.tGetDynamicAccountParams != null) && waitGetDynamicAccountParams) || 
               ((this.tPutTransactionVerificationLog != null) && waitPutTransactionVerificationLog)) {
            if ((this.tGetAccountParams != null) && waitGetAccountParams) {
                Log.i(LOG_TAG, caller + ", tGetAccountParams is still accessing remote card applet, waiting...");
            }
            if ((this.tGetDynamicAccountParams != null) && waitGetDynamicAccountParams) {
                Log.i(LOG_TAG, caller + ", tGetDynamicAccountParams is still accessing remote card applet, waiting...");
            }
            if ((this.tPutTransactionVerificationLog != null) && waitPutTransactionVerificationLog) {
                Log.i(LOG_TAG, caller + ", tPutTransactionVerificationLog is still accessing remote card applet, waiting...");
            }

            try {
                Thread.sleep(sleepInterval);
            }
            catch (InterruptedException e) {
            }
        }
    }

    @Override
    public void messageApproval(boolean approved, 
                                ApprovalData approvalData) {
        Log.i(LOG_TAG, "messageApproval");

        if (approvalData == null) {
            this.readyToPay = approved;
        }
    }

    @Override
    public void messageFromRemoteCard(String msg) {
        Log.i(LOG_TAG, "messageFromRemoteCard: " + msg);

        // Block until there is no thread accessing remote card applet before processing remote message.
        blockCondition(true, true, true, 50, "messageFromRemoteCard");

        if (msg.equalsIgnoreCase(GCM_MSG_ACCOUNT_PARAMETERS_UPDATE)) {
            // Delete existing card data.
            this.accountParamsStatic = null;
            this.arrayAccountParamsDynamic = null;
            this.iccPrivKey = null;

            // NOTE: Kludge to delay processing in case there is STBridge connection.
            try {
                Thread.sleep(100);
                if (this.disabled) {
                    postMessage("Account Has Been Enabled\n" + 
                                "Updating Card", 
                                false, null);
                }
                else {
                    postMessage("Account Parameters Has Changed\n" + 
                                "Updating Card", 
                                false, null);
                }
                Thread.sleep(500);
            }
            catch (Exception e) {
            }

            this.connectRetryCounter = 0;
            this.transceiveRetryCounter= 0; 
            getAccountParams();
        }
        else if (msg.equalsIgnoreCase(GCM_MSG_DEACTIVATE)) {
            this.disabled = true;

            // Delete existing card data.
            this.accountParamsStatic = null;
            this.arrayAccountParamsDynamic = null;
            this.iccPrivKey = null;

            this.handlerTimeToExpire.removeCallbacks(this.runnableTimeToExpire);

            try {
                postMessage("Account Has Been Disabled", false, null);
            }
            catch (IOException e) {
            }
        }
        else if (msg.equalsIgnoreCase(GCM_MSG_TERMINATE)) {
            this.terminated = true;
            this.disabled = true;

            // Delete existing card data.
            this.accountParamsStatic = null;
            this.arrayAccountParamsDynamic = null;
            this.iccPrivKey = null;

            this.handlerTimeToExpire.removeCallbacks(this.runnableTimeToExpire);

            try {
                postMessage("Account Has Been Terminated", false, null);
            }
            catch (IOException e) {
            }
        }
        else {
            Log.e(LOG_TAG, "Unknown Remote Message");
        }
    }

    /*
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

                if ((this.transactionState != TRANSACTION_START) && 
                    (this.transactionState != TRANSACTION_SELECT)) {
                    Log.e(LOG_TAG, "Transaction Failure: Out-of-order transaction flow.");
                    sendApduCFailure(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }

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
                byte[] aid = this.accountParamsStatic.getAid();
                if ((aid != null) && 
                    (aid.length == apduAidLength) && 
                    Arrays.equals(aid, Arrays.copyOfRange(apduBuffer, ISO7816.OFFSET_CDATA, ISO7816.OFFSET_CDATA + apduAidLength))) {
                    // Select, matching AID.

                    // Build response.
                    apduByteBuffer.put(PayWConstants.TAG_FCI_TEMPLATE);
                    // Skip FCI template length.
                    apduByteBuffer.put((byte) 0);
                    apduByteBuffer.put(PayWConstants.TAG_DF_NAME);
                    apduByteBuffer.put((byte) this.accountParamsStatic.getAid().length);
                    apduByteBuffer.put(this.accountParamsStatic.getAid());
                    apduByteBuffer.put(this.accountParamsStatic.getTagA5Data());
                    // Set FCI template length.
                    apduByteBuffer.put(1, (byte) (apduByteBuffer.position() - 2));

                    this.selected = true;
                }
                else {
                    byte[] ppseAid = this.accountParamsStatic.getAidPpse();
                    if ((ppseAid != null) && 
                        (ppseAid.length == apduAidLength) && 
                        Arrays.equals(ppseAid, Arrays.copyOfRange(apduBuffer, ISO7816.OFFSET_CDATA, ISO7816.OFFSET_CDATA + apduAidLength))) {
                        // Select, PPSE AID.

                        // Build response.
                        apduByteBuffer.put(this.accountParamsStatic.getPpseResponse());
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
                else if (this.selected && this.readyToPay) {
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
                else if (this.selected && this.readyToPay) {
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
            else {
                sendApduCFailure(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        }
        else {
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
    private synchronized void getProcessingOptions(APDU apdu) throws ISOException {
        byte[] apduBuffer = apdu.getBuffer();

        ByteBuffer apduByteBuffer = ByteBuffer.wrap(apduBuffer);

        // Check if P1=0x00 and P2=0x00.
        if (apduByteBuffer.getShort(ISO7816.OFFSET_P1) != (short) 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Check if Lc=[number of data bytes read].
        // Check if Lc=0x23.
        // Check if Le=0x00.
        short cdataLength = apdu.setIncomingAndReceive();

        // DEBUG
        Log.v(LOG_TAG, "C-APDU: " + DataUtil.byteArrayToHexString(apduBuffer, 0, cdataLength + 6));

        if ((cdataLength != (short) (apduBuffer[ISO7816.OFFSET_LC] & (short) 0x00FF)) || 
            (cdataLength != (short) 0x23) || 
            (apdu.setOutgoing() != (short) 256)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Check PDOL data.
        apduByteBuffer.position(ISO7816.OFFSET_CDATA);
        if (apduByteBuffer.getShort() != (short) 0x8321) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        byte ttqByte1 = apduByteBuffer.get();
        byte ttqByte2 = apduByteBuffer.get();
        byte ttqByte3 = apduByteBuffer.get();

        // Determine CVN from IAD.
        byte[] issuerApplicationData = this.accountParamsStatic.getIssuerApplicationData().clone();
        byte cvn = (byte) 0xFF;
        if (issuerApplicationData[AccountParamsStatic.IAD_VALUE_OFFSET] == (byte) 0x1F) {
            cvn = issuerApplicationData[AccountParamsStatic.IAD_VALUE_OFFSET + 1];
        }
        if (cvn != (byte) 0x43) {
            // CVN not supported.
            Log.e(LOG_TAG, "Transaction Failure: CVN " + String.format("%02X", cvn) + " not supported.");
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Default is support MSD.
        boolean msd = true;

        // Determine transaction type.
        if ((ttqByte1 & (byte) 0x20) == (byte) 0x20) {
            // Terminal supports qVSDC.
            msd = false;

            // Set transaction type to save in Transaction Verification Log.
            this.transactionType = TransactionVerificationLog.TRANSACTION_TYPE_QVSDC;

            // Shift reader data used as input to the cryptogram to offset 0.
            // '9F02'    6 bytes    Amount, Authorized
            // '9F03'    6 bytes    Amount, Other
            // '9F1A'    2 bytes    Terminal Country Code
            // '95'      5 bytes    Terminal Verification Results (TVR)
            // '5F2A'    2 bytes    Transaction Currency Code
            // '9A'      3 bytes    Transaction Date
            // '9C'      1 byte     Transaction Type
            // '9F37'    4 bytes    Unpredictable Number
            //    Total: 29 bytes
            System.arraycopy(apduBuffer, ISO7816.OFFSET_CDATA + 6, apduBuffer, 0, 29);
            // Re-position offset to later append card data used as input to the cryptogram.
            apduByteBuffer.position(29);

            // Set unpredictable number to later save in Transaction Verification Log.
            this.unpredictableNumber = DataUtil.byteArrayToHexString(apduBuffer, (short) 25, (short) 4);
        }
        else if ((ttqByte1 & (byte) 0x80) != (byte) 0x80) {
            // Terminal does not support MSD.
            Log.e(LOG_TAG, "Transaction Failure: Terminal does not support MSD.");
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        else {
            // Check if card supports MSD.
            if ((this.accountParamsStatic.getSfiRecord((short) 0x0101) == null) || 
                (this.accountParamsStatic.getGpoResponseMsd() == null)) {
                Log.e(LOG_TAG, "Transaction Failure: Card does not support MSD.");
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            // Set transaction type to save in Transaction Verification Log.
            this.transactionType = TransactionVerificationLog.TRANSACTION_TYPE_MSD;

            // Set unpredictable number to later save in Transaction Verification Log.
            this.unpredictableNumber = "00000000";
        }

        // Check if Dynamic Account Parameters are available.
        if (this.arrayAccountParamsDynamic.isEmpty()) {
            Log.e(LOG_TAG, "Transaction Failure: Dynamic Account Parameters not available.");
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        AccountParamsDynamic accountParamsDynamic = this.arrayAccountParamsDynamic.remove();
        long expirationTimestamp = accountParamsDynamic.getExpirationTimestamp();
        final long currentTimestamp = System.currentTimeMillis();
        // Check if Dynamic Account Parameters are expired.
        while ((expirationTimestamp != 0) && 
               (currentTimestamp > expirationTimestamp)) {
            // Check if additional Dynamic Account Parameters are available.
            if (this.arrayAccountParamsDynamic.isEmpty()) {
                Log.e(LOG_TAG, "Transaction Failure: Dynamic Account Parameters not available.");
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            accountParamsDynamic = this.arrayAccountParamsDynamic.remove();
            expirationTimestamp = accountParamsDynamic.getExpirationTimestamp();
        }
        this.accountParametersIndex = accountParamsDynamic.getAccountParamtersIndex();

        // Generate MSD cryptogram.
        String msdCryptogram = CryptogramGeneration.generateCvn43MsdCryptogram(accountParamsDynamic);
        if (msdCryptogram.length() != 6) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Inject Account Parameters Index and MSD Cryptogram into Track 2 Equivalent Data after the Service Code. 
        byte[] track2EquivalentData = this.accountParamsStatic.getTrack2EquivalentData().clone();
        String derivationDataString = this.accountParametersIndex + msdCryptogram + "F";
        byte[] derivationData = DataUtil.stringToCompressedByteArray(derivationDataString);
        System.arraycopy(derivationData, 0, 
                         track2EquivalentData, AccountParamsStatic.TRACK2_OFFSET_DD, derivationData.length);

        boolean transactionSuccess = false;
        if (msd) {
            // NOTE: TTQ Byte 2 Bit 8, Online Cryptogram Required is ignored.

            // Overwrite Track 2 Equivalent Data in record.
            byte[] sfi1Record1 = this.accountParamsStatic.getSfiRecord((short) 0x0101);
            System.arraycopy(track2EquivalentData, 0, sfi1Record1, 2, track2EquivalentData.length);

            // MSD Transaction: Format 1 response.
            apduByteBuffer.rewind();
            // Build response.
            apduByteBuffer.put(PayWConstants.TAG_RESPONSE_MESSAGE_TEMPLATE_FORMAT_1);
            byte[] gpoResponseMsd = this.accountParamsStatic.getGpoResponseMsd();
            apduByteBuffer.put((byte) (gpoResponseMsd.length - 4));
            apduByteBuffer.put(gpoResponseMsd, AccountParamsStatic.GPO_RESPONSE_OFFSET_AIP, 2);
            apduByteBuffer.put(gpoResponseMsd, 
                               AccountParamsStatic.GPO_RESPONSE_OFFSET_AFL, 
                               (int) (gpoResponseMsd[AccountParamsStatic.GPO_RESPONSE_OFFSET_AFL_LENGTH] & 0xFF));

            // Set AFL for Read Record processing.
            try {
                this.afl = ByteBuffer.wrap(gpoResponseMsd, 
                                           AccountParamsStatic.GPO_RESPONSE_OFFSET_AFL, 
                                           (int) (gpoResponseMsd[AccountParamsStatic.GPO_RESPONSE_OFFSET_AFL_LENGTH] & 0xFF));
            }
            catch (Exception e) {
                // AFL not available.
                this.afl = null;
            }
        }
        else {
            byte[] gpoResponseQvsdc = this.accountParamsStatic.getGpoResponseQvsdc();
            final short aip = ByteBuffer.wrap(gpoResponseQvsdc).getShort(AccountParamsStatic.GPO_RESPONSE_OFFSET_AIP);
            // Check 'DDA is supported' bit in AIP to determine if ODA is supported.
            if ((short) (aip & (short) 0x2000) == (short) 0x2000) {
                if (this.iccPrivKey == null) {
                    Log.e(LOG_TAG, "Transaction Failure: Missing ICC Private Key for ODA.");
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                if (this.accountParamsStatic.getIccKeyModulusLength() <= 0) {
                    Log.e(LOG_TAG, "Transaction Failure: Missing ICC Key Modulus Length for ODA.");
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
            }

            byte[] cardTransactionQualifier = this.accountParamsStatic.getCardTransactionQualifier().clone();

            // Set CTQ Byte 1, bits 8-7 to 00b and Byte 2, bit 8 to 0b.
            //byte[] cardTransactionQualifier = this.accountParamsStatic.getCardTransactionQualifier();
            cardTransactionQualifier[AccountParamsStatic.CTQ_OFFSET_BYTE_1] &= (byte) 0x3F;
            cardTransactionQualifier[AccountParamsStatic.CTQ_OFFSET_BYTE_2] &= (byte) 0xEF;

            // Set CVR Byte 1 to 00000000b.
            issuerApplicationData[AccountParamsStatic.IAD_OFFSET_CVR_BYTE_1] = (byte) 0x00;

            // qVSDC CVM Processing.
            if ((ttqByte2 & (byte) 0x40) == (byte) 0x40) {
                try {
                    ByteBuffer cvmListBuffer = ByteBuffer.wrap(this.accountParamsStatic.getCvmList());
                    // Skip amount fields.
                    cvmListBuffer.position(8);
                    // Parse CVM List to determine which CVM(s) is/are supported.
                    while (cvmListBuffer.hasRemaining()) {
                        // Process CVM Code.
                        byte cvmCode = cvmListBuffer.get();
                        boolean applyNext = ((byte) (cvmCode & (byte) 0x40) == (byte) 0x40);
                        cvmCode = (byte) (cvmCode & (byte) 0x3F);
                        if ((cvmCode == (byte) 0x02) && 
                            ((ttqByte1 & (byte) 0x04) == (byte) 0x04)) {
                            // Online PIN supported by account and Online PIN supported by reader.
                            // Set CTQ Byte 1 bit 8 to 1b.
                            cardTransactionQualifier[AccountParamsStatic.CTQ_OFFSET_BYTE_1] |= (byte) 0x80;
                            // Set CVR Byte 1 to 01101110b.
                            issuerApplicationData[AccountParamsStatic.IAD_OFFSET_CVR_BYTE_1] = (byte) 0x6E;
                        }
                        else if ((cvmCode == (byte) 0x1E) && 
                                 ((ttqByte1 & (byte) 0x02) == (byte) 0x02)) {
                            // Signature supported by account and Signature supported by reader.
                            // Set CTQ Byte 1 bit 7 to 1b.
                            cardTransactionQualifier[AccountParamsStatic.CTQ_OFFSET_BYTE_1] |= (byte) 0x40;
                            // Set CVR Byte 1 to 01101101b.
                            issuerApplicationData[AccountParamsStatic.IAD_OFFSET_CVR_BYTE_1] = (byte) 0x6D;
                        }
                        else if ((ttqByte3 & (byte) 0x40) == (byte) 0x40) {
                            // TODO: Consumer Device CVM option.
                        }
                        else if (!applyNext) {
                            // No common CVM found.
                            cvmListBuffer.position(cvmListBuffer.limit());
                        }
                        else {
                            // Continue processing CVM List, skip CVM Condition.
                            cvmListBuffer.get();
                            continue;
                        }

                        break;
                    }
                    if (!cvmListBuffer.hasRemaining()) {
                        // No common CVM found.
                        // Set CTQ Byte 2 bit 8 to 1b.
                        cardTransactionQualifier[AccountParamsStatic.CTQ_OFFSET_BYTE_2] |= (byte) 0x80;
                        // Set CVR Byte 1 to 00000000b. [already done]
                    }
                }
                catch (Exception e) {
                    // No common CVM found due to exception.
                    // Set CTQ Byte 2 bit 8 to 1b.
                    cardTransactionQualifier[AccountParamsStatic.CTQ_OFFSET_BYTE_2] |= (byte) 0x80;
                    // Set CVR Byte 1 to 00000000b. [already done]
                }
            }
            else {
                // CVM not required by reader.
                // Set CTQ Byte 2 bit 8 to 1b.
                cardTransactionQualifier[AccountParamsStatic.CTQ_OFFSET_BYTE_2] |= (byte) 0x80;
                // Set CVR Byte 1 to 00000000b. [already done]
            }

            // Update IAD.
            derivationDataString = "0" + this.accountParametersIndex;
            derivationData = DataUtil.stringToCompressedByteArray(derivationDataString);
            System.arraycopy(derivationData, 0, 
                             issuerApplicationData, AccountParamsStatic.IAD_OFFSET_DERIVATION_DATA, derivationData.length);

            // Check 'DDA is supported' bit in AIP to determine if ODA is supported.
            if ((short) (aip & (short) 0x2000) == (short) 0x2000) {
                // Process ODA.

                final int cardAuthRelatedDataOffset = 256;
                // 'generateSdad' requirements:
                // - Unpredictable Number, 4 bytes starting at offset 25 in 'apduBuffer'
                // - Amount Authorized, 6 bytes starting at offset 0 in 'apduBuffer'
                // - Transaction Currency Code, 2 bytes starting at offset 19 in 'apduBuffer'
                int sdadEndOffset = OfflineDataAuthentication.generateSdad(accountParamsDynamic, 
                                                                           apduBuffer, 
                                                                           cardAuthRelatedDataOffset, 
                                                                           cardTransactionQualifier, 
                                                                           this.accountParamsStatic.getIccKeyModulusLength(), 
                                                                           this.iccPrivKey);
                if (sdadEndOffset == -1) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }

                // Construct dynamic SFI 2 Record 4 data.
                int dynamicSfi2Record4Offset = cardAuthRelatedDataOffset - 1;
                apduBuffer[dynamicSfi2Record4Offset] = (byte) (sdadEndOffset - cardAuthRelatedDataOffset);
                if ((int) (apduBuffer[dynamicSfi2Record4Offset] & 0xFF) > 128) {
                    apduBuffer[--dynamicSfi2Record4Offset] = (byte) 0x81;
                }
                apduBuffer[--dynamicSfi2Record4Offset] = (byte) 0x70;
                this.dynamicSfi2Record4 = Arrays.copyOfRange(apduBuffer, dynamicSfi2Record4Offset, sdadEndOffset);
            }

            // Append card data used as input to the cryptogram.
            // '82'      2 bytes    Application Interchange Profile (AIP)
            // '9F36'    2 bytes    Application Transaction Counter (ATC)
            // Append AIP.
            apduByteBuffer.putShort(aip);
            // Append ATC.
            apduByteBuffer.putShort(accountParamsDynamic.getAtc());
            // '9F10'    4 bytes    Card Verification Results (part of Issuer Application Data - IAD)
            // Append first 4 bytes of CVR from IAD.
            apduByteBuffer.put(issuerApplicationData, AccountParamsStatic.IAD_OFFSET_CVR_BYTE_1, 4);

            // Generate AC.
            byte[] ac = CryptogramGeneration.generateCvn43Cryptogram(accountParamsDynamic, apduBuffer, 0, apduByteBuffer.position());
            if ((ac == null) || (ac.length != PayWConstants.LENGTH_AC)) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            // qVSDC Transaction: Format 2 response.
            apduByteBuffer.rewind();
            // Build response.
            apduByteBuffer.put(PayWConstants.TAG_RESPONSE_MESSAGE_TEMPLATE_FORMAT_2);
            // Skip response message template length.
            apduByteBuffer.put((byte) 0);
            // Add to response: AIP and AFL.
            apduByteBuffer.put(gpoResponseQvsdc);
            // Add to response: IAD.
            apduByteBuffer.put(issuerApplicationData);
            // Add to response: Track 2 Equivalent Data.
            apduByteBuffer.put(track2EquivalentData);
            // Add to response: PSN.
            apduByteBuffer.put(this.accountParamsStatic.getPanSequenceNumber());
            // Add to response: ATC.
            apduByteBuffer.putShort(PayWConstants.TAG_APPLICATION_TRANSACTION_COUNTER);
            apduByteBuffer.put((byte) 0x02);
            apduByteBuffer.putShort(accountParamsDynamic.getAtc());
            // Add to response: Application Cryptogram.
            apduByteBuffer.putShort(PayWConstants.TAG_APPLICATION_CRYPTOGRAM);
            apduByteBuffer.put((byte) PayWConstants.LENGTH_AC);
            apduByteBuffer.put(ac);
            // Add to response: CTQ.
            apduByteBuffer.put(cardTransactionQualifier);
            // Add to response: Fixed CID and Form Factor Indicator.
            apduByteBuffer.put(DataUtil.stringToCompressedByteArray("9F2701809F6E04238C0000"));
            // Set response template message length.
            apduByteBuffer.put(1, (byte) (apduByteBuffer.position() - 2));

            // Set AFL for Read Record processing.
            try {
                this.afl = ByteBuffer.wrap(gpoResponseQvsdc, 
                                           AccountParamsStatic.GPO_RESPONSE_OFFSET_AFL, 
                                           (int) (gpoResponseQvsdc[AccountParamsStatic.GPO_RESPONSE_OFFSET_AFL_LENGTH] & 0xFF));
            }
            catch (Exception e) {
                // AFL not available.
                this.afl = null;
            }
        }

        if (transactionSuccess) {
            this.apduState = APDU_SENDING_LAST;
        }
        else {
            this.apduState = APDU_SENDING;
        }

        // DEBUG
        Log.v(LOG_TAG, "R-APDU: " + DataUtil.byteArrayToHexString(apduBuffer, 0, apduByteBuffer.position()) + "9000");

        apdu.setOutgoingLength((short) apduByteBuffer.position());
        apdu.sendBytes((short) 0, (short) apduByteBuffer.position());

        if (transactionSuccess) {
            // Success triggers a successful transaction.
            apdu.setTransactionSuccess();
        }
        else {
            // Set number of records specified in AFL for Read Record processing.
            this.afl.mark();
            while (this.afl.hasRemaining()) {
                // Skip the SFI byte.
                this.afl.get();

                int aflFirstRecord = (int) (this.afl.get() & 0xFF);
                int aflLastRecord = (int) (this.afl.get() & 0xFF);
                this.aflRecords += (aflLastRecord - aflFirstRecord + 1);

                // Skip the next byte.
                this.afl.get();
            }
        }
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

        final byte recordNumber = apduBuffer[ISO7816.OFFSET_P1];

        // Check P1/P2.
        if ((recordNumber == (byte) 0x00) || 
            ((apduBuffer[ISO7816.OFFSET_P2] & (byte) 0x07) != (byte) 0x04)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Check if Lc is not present.
        // Check if Le=0x00.
        if ((apdu.setIncomingAndReceive() != (short) 0) || 
            (apdu.setOutgoing() != (short) 256)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Check if AFL saved in Get Processing Options or
        //       if Read Records counter is greater than number of records indicated in AFL.
        if ((this.afl == null) || 
            (this.readRecordCounter > this.aflRecords)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Check if SFI and record supported in AFL.
        final byte sfi = (byte) ((apduBuffer[ISO7816.OFFSET_P2] & (byte) 0xF8));
        boolean aflSupported = false;
        this.afl.reset();
        while (this.afl.hasRemaining()) {
            byte aflSfi = this.afl.get();
            byte aflFirstRecord = this.afl.get();
            byte aflLastRecord = this.afl.get();
            if ((aflSfi == sfi) && 
                (aflFirstRecord <= recordNumber) && 
                (aflLastRecord >= recordNumber)) {
                aflSupported = true;
                break;
            }

            // Skip the next byte.
            this.afl.get();
        }
        if (!aflSupported) {
            Log.e(LOG_TAG, "Transaction Failure: SFI and record not supported in AFL.");
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        // Retrieve record.
        short sfiRecord = (short) ((sfi << 5) | recordNumber);
        byte[] recordData = this.accountParamsStatic.getSfiRecord(sfiRecord);
        if (recordData == null) {
            if (sfiRecord == (short) 0x0204) {
                recordData = this.dynamicSfi2Record4;
            }
            else {
                // Req 7.23
                Log.e(LOG_TAG, "Transaction Failure: SFI and record not found.");
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
        }

        // Increment Read Record counter.
        this.readRecordCounter++;

        // Copy record data to APDU response buffer.
        short rdataLength = (short) recordData.length;
        System.arraycopy(recordData, 0, apduBuffer, 0, rdataLength);

        // Determine if this is the last Read Record command.
        if (this.readRecordCounter == this.aflRecords) {
            this.apduState = APDU_SENDING_LAST;
        }
        else {
            this.apduState = APDU_SENDING;
        }

        // DEBUG
        Log.v(LOG_TAG, "R-APDU: " + DataUtil.byteArrayToHexString(apduBuffer, 0, rdataLength) + "9000");

        apdu.setOutgoingLength(rdataLength);
        apdu.sendBytes((short) 0, rdataLength);

        // Determine if this is the last Read Record command.
        if (this.readRecordCounter == this.aflRecords) {
            // Success triggers a successful transaction.
            apdu.setTransactionSuccess();
        }
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

    private void getAccountParams() {
        if (this.tGetAccountParams != null) {
            Log.i(LOG_TAG, "getAccountParams, tGetAccountParams is still accessing remote card applet.");
            return;
        }

        // Block until 'tGetDynamicAccountParams' and 'tPutTransactionVerificationLog' threads have stopped before continuing.
        blockCondition(false, true, true, 100, "getAccountParams");

        // NOTE: This thread calls 'setBusy' method when it starts and 'clearBusy' when it stops to 
        //       block agent from processing contactless transaction while the thread is running.
        this.tGetAccountParams = new Thread(new Runnable() {
            public void run() {
                try {
                    setBusy();
                }
                catch (IOException e) {
                    Log.e(LOG_TAG, "tGetAccountParams setBusy IOException Log", e);

                    try {
                        postMessage("Card Agent Not Available to\n" + 
                                    "Get Account Parameters\n" + 
                                    "Exception: " + getNonNullMessage(e), 
                                    false, null);
                    }
                    catch (IOException e1) {
                    }

                    tGetAccountParams = null;
                    return;
                }

                try {
                    connect();
                }
                catch (IOException e) {
                    Log.e(LOG_TAG, "tGetAccountParams connect IOException Log", e);

                    try {
                        disconnect();
                    }
                    catch (IOException e1) {
                    }

                    // Retry connect if error is not NO_CARD.
                    if (!getNonNullMessage(e).equalsIgnoreCase("NO_CARD")) {
                        if (connectRetryCounter < MAX_CONNECT_RETRY) {
                            connectRetryCounter++;

                            try {
                                clearBusy();
                            }
                            catch (IOException e1) {
                            }

                            tGetAccountParams = null;

                            getAccountParams();

                            return;
                        }
                    }

                    try {
                        if (accountParamsStatic == null) {
                            postMessage("No Connection Available to\n" + 
                                        "Get Account Parameters\n" + 
                                        "Exception: " + getNonNullMessage(e), 
                                        false, null);
                        }
                        else {
                            postMessage("No Connection Available to\n" + 
                                        "Sync Account Parameters\n" + 
                                        "Exception: " + getNonNullMessage(e), 
                                        false, null);
                        }
                    }
                    catch (IOException e1) {
                    }

                    try {
                        clearBusy();
                    }
                    catch (IOException e1) {
                    }

                    tGetAccountParams = null;
                    return;
                }

                TransceiveData tranceiveDataGetAccountParams = null;
                while (true) {
                    tranceiveDataGetAccountParams = new TransceiveData(TransceiveData.SOFT_CHANNEL);
                    tranceiveDataGetAccountParams.packCardReset(false);
                    tranceiveDataGetAccountParams.packApdu(APDU_SELECT_CARDAPPLET, true);
                    tranceiveDataGetAccountParams.packApdu(APDU_GET_STATIC_ACCOUNT_PARAMETERS, true);
                    try {
                        transceive(tranceiveDataGetAccountParams);
                    }
                    catch (IOException e) {
                        Log.e(LOG_TAG, "tGetAccountParams transceive(tranceiveDataGetAccountParams) IOException Log", e);

                        // Retry transceive.
                        if (transceiveRetryCounter < MAX_TRANSCEIVE_RETRY) {
                            transceiveRetryCounter++;

                            continue;
                        }

                        try {
                            if (accountParamsStatic == null) {
                                postMessage("Get Account Parameters Error\n" + 
                                            "Exception: " + getNonNullMessage(e), 
                                            false, null);
                            }
                        }
                        catch (IOException e1) {
                        }

                        break;
                    }

                    byte[] selectResponse = tranceiveDataGetAccountParams.getNextResponse();
                    if ((selectResponse == null) || 
                        (selectResponse.length <= 2) || 
                        (ByteBuffer.wrap(selectResponse).getShort(selectResponse.length - 2) != ISO7816.SW_NO_ERROR)) {
                        String invalidResponse = DataUtil.byteArrayToHexString(selectResponse);
                        Log.e(LOG_TAG, "tranceiveDataGetAccountParams invalid selectResponse: " + invalidResponse);

                        try {
                            if ((invalidResponse.length() == 4) && 
                                invalidResponse.equalsIgnoreCase(String.format("%04X", ISO7816.SW_FUNC_NOT_SUPPORTED))) {
                                terminated = true;
                                disabled = true;

                                // Delete existing card data.
                                accountParamsStatic = null;
                                arrayAccountParamsDynamic = null;
                                iccPrivKey = null;

                                handlerTimeToExpire.removeCallbacks(runnableTimeToExpire);

                                postMessage("Account is Terminated", false, null);
                            }
                            else {
                                // Retry transceive.
                                if (transceiveRetryCounter < MAX_TRANSCEIVE_RETRY) {
                                    transceiveRetryCounter++;

                                    continue;
                                }

                                if (accountParamsStatic == null) {
                                    postMessage("Account Not Available", false, null);
                                }
                            }
                        }
                        catch (IOException e) {
                        }

                        break;
                    }

                    byte[] accountParamsStaticData = tranceiveDataGetAccountParams.getNextResponse();
                    if ((accountParamsStaticData != null) && 
                        (accountParamsStaticData.length > 2) && 
                        (ByteBuffer.wrap(accountParamsStaticData).getShort(accountParamsStaticData.length - 2) == ISO7816.SW_NO_ERROR)) {
                        // Reset 'disabled' in case agent was in disabled state.
                        disabled = false;

                        // Extract Static Account Parameters data without SW.
                        accountParamsStaticData = Arrays.copyOf(accountParamsStaticData, accountParamsStaticData.length - 2);

                        ByteArrayInputStream bis = new ByteArrayInputStream(accountParamsStaticData);
                        ObjectInput in = null;
                        try {
                            in = new ObjectInputStream(bis);
                            accountParamsStatic = (AccountParamsStatic) in.readObject();
                        }
                        catch (Exception e) {
                            Log.e(LOG_TAG, "Cannot serialize accountParamsStaticData: " + DataUtil.byteArrayToHexString(accountParamsStaticData));

                            // Retry transceive.
                            if (transceiveRetryCounter < MAX_TRANSCEIVE_RETRY) {
                                transceiveRetryCounter++;

                                continue;
                            }

                            try {
                                if (accountParamsStatic == null) {
                                    postMessage("Static Account Parameters Format Error\n" + 
                                                "Exception: " + getNonNullMessage(e), 
                                                false, null);
                                }
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
                        String invalidResponse = DataUtil.byteArrayToHexString(accountParamsStaticData);
                        Log.e(LOG_TAG, "Invalid accountParamsStaticData: " + invalidResponse);

                        try {
                            if ((invalidResponse.length() == 4) && 
                                invalidResponse.equalsIgnoreCase(String.format("%04X", ISO7816.SW_COMMAND_NOT_ALLOWED))) {
                                disabled = true;

                                // Delete existing card data.
                                accountParamsStatic = null;
                                arrayAccountParamsDynamic = null;
                                iccPrivKey = null;

                                handlerTimeToExpire.removeCallbacks(runnableTimeToExpire);

                                postMessage("Account is Disabled", false, null);
                            }
                            else {
                                // Retry transceive.
                                if (transceiveRetryCounter < MAX_TRANSCEIVE_RETRY) {
                                    transceiveRetryCounter++;

                                    continue;
                                }

                                if (accountParamsStatic == null) {
                                    postMessage("Invalid Static Account Parameters Data", false, null);
                                }
                            }
                        }
                        catch (IOException e) {
                        }
                    }

                    break;
                }  // while (true)
                if (accountParamsStatic == null) {
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

                    tGetAccountParams = null;
                    return;
                }
                else {
                    // DEBUG
                    try {
                        Log.v(LOG_TAG, "accountParamsStatic Aid: " + DataUtil.byteArrayToHexString(accountParamsStatic.getAid()));
                        Log.v(LOG_TAG, "accountParamsStatic AidPpse: " + DataUtil.byteArrayToHexString(accountParamsStatic.getAidPpse()));
                        Log.v(LOG_TAG, "accountParamsStatic PpseResponse: " + DataUtil.byteArrayToHexString(accountParamsStatic.getPpseResponse()));
                        Log.v(LOG_TAG, "accountParamsStatic TagA5Data: " + DataUtil.byteArrayToHexString(accountParamsStatic.getTagA5Data()));
                        Log.v(LOG_TAG, "accountParamsStatic GpoResponseMsd: " + DataUtil.byteArrayToHexString(accountParamsStatic.getGpoResponseMsd()));
                        Log.v(LOG_TAG, "accountParamsStatic GpoResponseQvsdc: " + DataUtil.byteArrayToHexString(accountParamsStatic.getGpoResponseQvsdc()));
                        Log.v(LOG_TAG, "accountParamsStatic IssuerApplicationData: " + DataUtil.byteArrayToHexString(accountParamsStatic.getIssuerApplicationData()));
                        Log.v(LOG_TAG, "accountParamsStatic PanSequenceNumber: " + DataUtil.byteArrayToHexString(accountParamsStatic.getPanSequenceNumber()));
                        Log.v(LOG_TAG, "accountParamsStatic CardTransactionQualifier: " + DataUtil.byteArrayToHexString(accountParamsStatic.getCardTransactionQualifier()));
                        Log.v(LOG_TAG, "accountParamsStatic Track2EquivalentData: " + DataUtil.byteArrayToHexString(accountParamsStatic.getTrack2EquivalentData()));
                        Log.v(LOG_TAG, "accountParamsStatic CardholderName: " + DataUtil.byteArrayToHexString(accountParamsStatic.getCardholderName()));
                        Log.v(LOG_TAG, "accountParamsStatic CvmList: " + DataUtil.byteArrayToHexString(accountParamsStatic.getCvmList()));
                        //Log.v(LOG_TAG, "accountParamsStatic IccPrivKeyCrtCoefficient: " + DataUtil.byteArrayToHexString(accountParamsStatic.getIccPrivKeyCrtCoefficient()));
                        //Log.v(LOG_TAG, "accountParamsStatic IccPrivKeyPrimeExponentQ: " + DataUtil.byteArrayToHexString(accountParamsStatic.getIccPrivKeyPrimeExponentQ()));
                        //Log.v(LOG_TAG, "accountParamsStatic IccPrivKeyPrimeExponentP: " + DataUtil.byteArrayToHexString(accountParamsStatic.getIccPrivKeyPrimeExponentP()));
                        //Log.v(LOG_TAG, "accountParamsStatic IccPrivKeyPrimeQ: " + DataUtil.byteArrayToHexString(accountParamsStatic.getIccPrivKeyPrimeQ()));
                        //Log.v(LOG_TAG, "accountParamsStatic IccPrivKeyPrimeP: " + DataUtil.byteArrayToHexString(accountParamsStatic.getIccPrivKeyPrimeP()));
                        Log.v(LOG_TAG, "accountParamsStatic IccKeyModulusLength: " + accountParamsStatic.getIccKeyModulusLength());
                        Log.v(LOG_TAG, "accountParamsStatic MaxNumberAccountParamsDynamic: " + accountParamsStatic.getMaxNumberAccountParamsDynamic());
                        Log.v(LOG_TAG, "accountParamsStatic MinThresholdNumberAccountParamsDynamic: " + accountParamsStatic.getMinThresholdNumberAccountParamsDynamic());
                        Log.v(LOG_TAG, "accountParamsStatic CheckIntervalTimeToExpire: " + accountParamsStatic.getCheckIntervalTimeToExpire());
                        Log.v(LOG_TAG, "accountParamsStatic MaxTransactionVerificationLogs: " + accountParamsStatic.getMaxTransactionVerificationLogs());
                    }
                    catch (Exception e) {
                        Log.e(LOG_TAG, "accountParamsStatic Debug Exception Log", e);
                    }
                }

                final int sizeTransactionVerificationLogs = accountParamsStatic.getMaxTransactionVerificationLogs();
                if (sizeTransactionVerificationLogs <= 0) {
                    transactionVerificationLogs = null;
                }
                else {
                    if (transactionVerificationLogs == null) {
                        transactionVerificationLogs = new LinkedHashMapFixedSize<String, TransactionVerificationLog>(sizeTransactionVerificationLogs);
                    }
                    else {
                        transactionVerificationLogs.updateSize(sizeTransactionVerificationLogs);
                    }
                }

                handlerTimeToExpire.removeCallbacks(runnableTimeToExpire);
                checkInternalTimeToExpire = accountParamsStatic.getCheckIntervalTimeToExpire() * 60000;
                // TEST: Use seconds instead of minutes for testing.
                //checkInternalTimeToExpire = accountParamsStatic.getCheckIntervalTimeToExpire() * 1000;
                if (checkInternalTimeToExpire > 0) {
                    // DEBUG
                    startTime = System.currentTimeMillis();

                    handlerTimeToExpire.postDelayed(runnableTimeToExpire, checkInternalTimeToExpire);
                }

                final int maxNumberAccountParamsDynamic = accountParamsStatic.getMaxNumberAccountParamsDynamic();
                arrayAccountParamsDynamic = new ArrayDeque<AccountParamsDynamic>(maxNumberAccountParamsDynamic);

                final int addNumberAccountParamsDynamic = maxNumberAccountParamsDynamic - arrayAccountParamsDynamic.size();
                if (addNumberAccountParamsDynamic <= 0) {
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

                    tGetAccountParams = null;
                    return;
                }

                TransceiveData tranceiveDataGetDynamicAccountParams = null;
                int numberAccountParamsDynamic = 0;
                while (true) {
                    tranceiveDataGetDynamicAccountParams = new TransceiveData(TransceiveData.SOFT_CHANNEL);
                    while (numberAccountParamsDynamic < addNumberAccountParamsDynamic) {
                        tranceiveDataGetDynamicAccountParams.packApdu(APDU_GET_DYNAMIC_ACCOUNT_PARAMETERS, true);
                        numberAccountParamsDynamic++;
                    }
                    try {
                        transceive(tranceiveDataGetDynamicAccountParams);
                    }
                    catch (IOException e) {
                        Log.e(LOG_TAG, "tGetAccountParams transceive(tranceiveDataGetDynamicAccountParams) IOException Log", e);

                        // Retry transceive.
                        if (transceiveRetryCounter < MAX_TRANSCEIVE_RETRY) {
                            transceiveRetryCounter++;

                            numberAccountParamsDynamic = 0;

                            continue;
                        }

                        try {
                            postMessage("Get Dynamic Account Parameters Error\n" + 
                                        "Exception: " + getNonNullMessage(e), 
                                        false, null);
                        }
                        catch (IOException e1) {
                        }
                    }

                    break;
                }

                try {
                    disconnect();
                }
                catch (IOException e) {
                }

                numberAccountParamsDynamic = 0;
                while (numberAccountParamsDynamic < addNumberAccountParamsDynamic) {
                    syncGetDynamicAccountParams(tranceiveDataGetDynamicAccountParams.getNextResponse());
                    numberAccountParamsDynamic++;
                }
                // NOTE: One or more 'syncGetDynamicAccountParams' calls could fail.
                //       Only display error if all 'syncGetDynamicAccountParams' calls fail. 
                if (arrayAccountParamsDynamic.size() == 0) {
                    try {
                        postMessage("Need to Provision\n" + 
                                    "Dynamic Account Parameters\n" + 
                                    "to Perform Transactions", 
                                    false, null);
                    }
                    catch (IOException e) {
                    }
                }

                try {
                    clearBusy();
                }
                catch (IOException e) {
                }

                // Initialize ICC Private Key if available.
                if ((accountParamsStatic.getIccPrivKeyCrtCoefficient() != null) || 
                    (accountParamsStatic.getIccPrivKeyPrimeExponentQ() != null) || 
                    (accountParamsStatic.getIccPrivKeyPrimeExponentP() != null) || 
                    (accountParamsStatic.getIccPrivKeyPrimeQ() != null) || 
                    (accountParamsStatic.getIccPrivKeyPrimeP() != null)) {
                    try {
                        BigInteger crtCoefficient = new BigInteger(1, accountParamsStatic.getIccPrivKeyCrtCoefficient());
                        BigInteger primeExponentQ = new BigInteger(1, accountParamsStatic.getIccPrivKeyPrimeExponentQ());
                        BigInteger primeExponentP = new BigInteger(1, accountParamsStatic.getIccPrivKeyPrimeExponentP());
                        BigInteger primeQ = new BigInteger(1, accountParamsStatic.getIccPrivKeyPrimeQ());
                        BigInteger primeP = new BigInteger(1, accountParamsStatic.getIccPrivKeyPrimeP());
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
                        iccPrivKey = (RSAPrivateCrtKey) KeyFactory.getInstance("RSA", "BC").generatePrivate(iccPrivKeySpec);
                    }
                    catch (Exception e) {
                        Log.e(LOG_TAG, "Failed to Initialize ICC Private Key Exception Log", e);
                    }

                    // Clear secret data in serializable class.
                    accountParamsStatic.setIccPrivKeyCrtCoefficient(null, (short) 0, (short) 0);
                    accountParamsStatic.setIccPrivKeyPrimeExponentQ(null, (short) 0, (short) 0);
                    accountParamsStatic.setIccPrivKeyPrimeExponentP(null, (short) 0, (short) 0);
                    accountParamsStatic.setIccPrivKeyPrimeQ(null, (short) 0, (short) 0);
                    accountParamsStatic.setIccPrivKeyPrimeP(null, (short) 0, (short) 0);
                }

                tGetAccountParams = null;
            }
        });

        this.tGetAccountParams.start();
    }

    private void getDynamicAccountParams(final boolean checkMinThreshold) {
        // Block until 'tGetDynamicAccountParams' thread has stopped before continuing.
        blockCondition(false, true, false, 200, "getDynamicAccountParams");

        if ((this.accountParamsStatic == null) && !this.disabled) {
            try {
                postMessage("Missing Account Parameters\n" + 
                            "Please Check Connection is Available and Refresh Card", 
                            false, null);
            }
            catch (IOException e) {
            }
            return;
        }

        if (checkMinThreshold && 
            (this.arrayAccountParamsDynamic.size() > this.accountParamsStatic.getMinThresholdNumberAccountParamsDynamic())) {
            //Log.i(LOG_TAG, "Not yet minimum threshold number of dynamic account parameters.");
            return;
        }

        final int addNumberAccountParamsDynamic = this.accountParamsStatic.getMaxNumberAccountParamsDynamic() - this.arrayAccountParamsDynamic.size();
        if (addNumberAccountParamsDynamic <= 0) {
            Log.i(LOG_TAG, "Already maximum number of dynamic account parameters.");
            return;
        }

        // Block until 'tGetAccountParams' and 'tPutTransactionVerificationLog' threads have stopped before continuing.
        blockCondition(true, false, true, 200, "getDynamicAccountParams");

        // NOTE: This thread does not call 'setBusy' method so agent is not blocked from processing 
        //       contactless transaction while the thread is running.
        this.tGetDynamicAccountParams = new Thread(new Runnable() {
            public void run() {
                try {
                    connect();
                }
                catch (IOException e) {
                    Log.e(LOG_TAG, "tGetDynamicAccountParams connect IOException Log", e);

                    try {
                        disconnect();
                    }
                    catch (IOException e1) {
                    }

                    // Retry connect if error is not NO_CARD.
                    if (!getNonNullMessage(e).equalsIgnoreCase("NO_CARD")) {
                        if (connectRetryCounter < MAX_CONNECT_RETRY) {
                            connectRetryCounter++;

                            tGetDynamicAccountParams = null;

                            getDynamicAccountParams(checkMinThreshold);

                            return;
                        }
                    }

                    try {
                        postMessage("No Connection Available to\n" + 
                                    "Replenish Account Parameter\n" + 
                                    arrayAccountParamsDynamic.size() + " Transactions Remaining\n" + 
                                    "Exception: " + getNonNullMessage(e), 
                                    false, null);
                    }
                    catch (IOException e1) {
                    }

                    tGetDynamicAccountParams = null;
                    return;
                }

                TransceiveData tranceiveDataGetDynamicAccountParams = null;
                int numberAccountParamsDynamic = 0;
                while (true) {
                    tranceiveDataGetDynamicAccountParams = new TransceiveData(TransceiveData.SOFT_CHANNEL);
                    tranceiveDataGetDynamicAccountParams.packCardReset(false);
                    tranceiveDataGetDynamicAccountParams.packApdu(APDU_SELECT_CARDAPPLET, true);
                    while (numberAccountParamsDynamic < addNumberAccountParamsDynamic) {
                        tranceiveDataGetDynamicAccountParams.packApdu(APDU_GET_DYNAMIC_ACCOUNT_PARAMETERS, true);
                        numberAccountParamsDynamic++;
                    }
                    try {
                        transceive(tranceiveDataGetDynamicAccountParams);
                    }
                    catch (IOException e) {
                        Log.e(LOG_TAG, "tGetDynamicAccountParams transceive IOException Log", e);

                        // Retry transceive.
                        if (transceiveRetryCounter < MAX_TRANSCEIVE_RETRY) {
                            transceiveRetryCounter++;

                            numberAccountParamsDynamic = 0;

                            continue;
                        }

                        // Indicate exception occurred.
                        numberAccountParamsDynamic = -1;

                        try {
                            postMessage("Get Dynamic Account Parameters Error\n" + 
                                        "Exception: " + getNonNullMessage(e), 
                                        false, null);
                        }
                        catch (IOException e1) {
                        }
                    }

                    break;
                }

                try {
                    disconnect();
                }
                catch (IOException e) {
                }

                // Check if error already occurred.
                if (numberAccountParamsDynamic != -1) {
                    byte[] selectResponse = tranceiveDataGetDynamicAccountParams.getNextResponse();
                    if ((selectResponse == null) || 
                        (selectResponse.length <= 2) || 
                        (ByteBuffer.wrap(selectResponse).getShort(selectResponse.length - 2) != ISO7816.SW_NO_ERROR)) {
                        String invalidResponse = DataUtil.byteArrayToHexString(selectResponse);
                        Log.e(LOG_TAG, "tranceiveDataGetDynamicAccountParams invalid selectResponse: " + invalidResponse);

                        try {
                            if ((invalidResponse.length() == 4) && 
                                invalidResponse.equalsIgnoreCase(String.format("%04X", ISO7816.SW_FUNC_NOT_SUPPORTED))) {
                                terminated = true;
                                disabled = true;

                                // Delete existing card data.
                                accountParamsStatic = null;
                                arrayAccountParamsDynamic = null;
                                iccPrivKey = null;

                                handlerTimeToExpire.removeCallbacks(runnableTimeToExpire);

                                postMessage("Account is Terminated", false, null);
                            }
                            else {
                                postMessage("Account Not Available", false, null);
                            }
                        }
                        catch (IOException e) {
                        }

                        tGetDynamicAccountParams = null;
                        return;
                    }

                    numberAccountParamsDynamic = 0;
                    while (numberAccountParamsDynamic < addNumberAccountParamsDynamic) {
                        syncGetDynamicAccountParams(tranceiveDataGetDynamicAccountParams.getNextResponse());
                        numberAccountParamsDynamic++;
                    }
                    // NOTE: One or more 'syncGetDynamicAccountParams' calls could fail.
                    //       Only display error if enough 'syncGetDynamicAccountParams' calls fail to replenish 
                    //       Dynamic Account Parameters above minimum threshold. 
                    if (arrayAccountParamsDynamic.size() <= accountParamsStatic.getMinThresholdNumberAccountParamsDynamic()) {
                        try {
                            postMessage("Failed to Fully Replenish\n" + 
                                        "Dynamic Account Parameter\n" + 
                                        arrayAccountParamsDynamic.size() + " Transactions Remaining\n", 
                                        false, null);
                        }
                        catch (IOException e) {
                        }
                    }
                }

                tGetDynamicAccountParams = null;
            }
        });

        this.tGetDynamicAccountParams.start();
    }

    private synchronized void syncGetDynamicAccountParams(byte[] accountParamsDynamicData) {
        if ((accountParamsDynamicData != null) && 
            (accountParamsDynamicData.length > 2) && 
            (ByteBuffer.wrap(accountParamsDynamicData).getShort(accountParamsDynamicData.length - 2) == ISO7816.SW_NO_ERROR)) {
            // Extract Dynamic Account Parameters data without SW.
            accountParamsDynamicData = Arrays.copyOf(accountParamsDynamicData, accountParamsDynamicData.length - 2);

            AccountParamsDynamic accountParamsDynamic = null;

            ByteArrayInputStream bis = new ByteArrayInputStream(accountParamsDynamicData);
            ObjectInput in = null;
            try {
                in = new ObjectInputStream(bis);
                accountParamsDynamic = (AccountParamsDynamic) in.readObject();
            }
            catch (Exception e) {
                Log.e(LOG_TAG, "Cannot serialize accountParamsDynamicData: " + DataUtil.byteArrayToHexString(accountParamsDynamicData));

                // Ignore badly formatted Dynamic Account Parameters data.
                /*
                try {
                    postMessage("Dynamic Account Parameters Format Error\n" + 
                                "Exception: " + getNonNullMessage(e), 
                                false, null);
                }
                catch (IOException e1) {
                }
                */
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

            if (accountParamsDynamic != null) {
                // Set received timestamp.
                accountParamsDynamic.setReceivedTimestamp(System.currentTimeMillis());

                // DEBUG
                try {
                    Log.v(LOG_TAG, "accountParamsDynamic AccountParamtersIndex: " + accountParamsDynamic.getAccountParamtersIndex());
                    //Log.v(LOG_TAG, "accountParamsDynamic Luk: " + DataUtil.byteArrayToHexString(accountParamsDynamic.getLuk()));
                    Log.v(LOG_TAG, "accountParamsDynamic ExpirationTimestamp: " + accountParamsDynamic.getExpirationTimestamp());
                    Log.v(LOG_TAG, "accountParamsDynamic ReceivedTimestamp: " + accountParamsDynamic.getReceivedTimestamp());
                    Log.v(LOG_TAG, "accountParamsDynamic Atc: " + String.format("%04X", accountParamsDynamic.getAtc()));
                    //Log.v(LOG_TAG, "accountParamsDynamic LukMsd: " + DataUtil.byteArrayToHexString(accountParamsDynamic.getLukMsd()));
                }
                catch (Exception e) {
                    Log.e(LOG_TAG, "accountParamsDynamic Debug Exception Log", e);
                }

                arrayAccountParamsDynamic.add(accountParamsDynamic);
            }
        }
        else {
            String invalidResponse = DataUtil.byteArrayToHexString(accountParamsDynamicData);
            Log.e(LOG_TAG, "Invalid accountParamsDynamicData: " + invalidResponse);

            try {
                if ((invalidResponse.length() == 4) && 
                    invalidResponse.equalsIgnoreCase(String.format("%04X", ISO7816.SW_COMMAND_NOT_ALLOWED))) {
                    disabled = true;

                    // Delete existing card data.
                    accountParamsStatic = null;
                    arrayAccountParamsDynamic = null;
                    iccPrivKey = null;

                    handlerTimeToExpire.removeCallbacks(runnableTimeToExpire);

                    postMessage("Account is Disabled", false, null);
                }
                // Ignore invalid Dynamic Account Parameters data.
                /*
                else {
                    postMessage("Invalid Dynamic Account Parameters Data", false, null);
                }
                */
            }
            catch (IOException e) {
            }
        }
    }

    private void putTransactionVerificationLog() {
        // Do not block if 'tPutTransactionVerificationLog' thread is already running.
        // It allows more than 2 transactions to be performed while 'tPutTransactionVerificationLog' thread is already running.
        if (this.tPutTransactionVerificationLog != null) {
            Log.i(LOG_TAG, "Do not start another 'tPutTransactionVerificationLog' thread.");
            return;
        }

        if ((this.transactionVerificationLogs == null) || 
            this.transactionVerificationLogs.isEmpty()) {
            Log.i(LOG_TAG, "No Transaction Verification Log to save.");
            return;
        }

        // Block until 'tGetAccountParams' and 'tGetDynamicAccountParams' threads have stopped before continuing.
        blockCondition(true, true, false, 200, "putTransactionVerificationLog");

        // NOTE: This thread calls 'setBusy' method when it starts and 'clearBusy' when it stops to 
        //       block agent from processing contactless transaction while the thread is running.
        this.tPutTransactionVerificationLog = new Thread(new Runnable() {
            public void run() {
                try {
                    connect();
                }
                catch (IOException e) {
                    Log.e(LOG_TAG, "tPutTransactionVerificationLog connect IOException Log", e);

                    // No connect retry. Attempt again after next transaction.

                    try {
                        disconnect();
                    }
                    catch (IOException e1) {
                    }

                    tPutTransactionVerificationLog = null;
                    return;
                }

                TransceiveData tranceiveDataPutTransactionVerificationLog = new TransceiveData(TransceiveData.SOFT_CHANNEL);
                tranceiveDataPutTransactionVerificationLog.packCardReset(false);
                tranceiveDataPutTransactionVerificationLog.packApdu(APDU_SELECT_CARDAPPLET, true);
                boolean tranceiveTransactionVerificationLog = false;
                Iterator<Map.Entry<String, TransactionVerificationLog>> iteratorTransactionVerificationLog = transactionVerificationLogs.entrySet().iterator();
                while (iteratorTransactionVerificationLog.hasNext()) {
                    final Map.Entry<String, TransactionVerificationLog> entry = iteratorTransactionVerificationLog.next();
                    TransactionVerificationLog transactionVerificationLog = entry.getValue();

                    // DEBUG
                    Log.v(LOG_TAG, "Save Transaction Verification Log - " 
                                   + "\n  UtcTimestamp: " + transactionVerificationLog.getUtcTimestamp() 
                                   //+ "\n  AccountParametersIndex: " + transactionVerificationLog.getAccountParametersIndex() 
                                   //+ "\n  TransactionType: " + transactionVerificationLog.getTransactionType() 
                                   //+ "\n  UnpredictableNumber: " + transactionVerificationLog.getUnpredictableNumber()
                         );

                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    ObjectOutput out = null;
                    byte[] transactionVerificationLogBytes = null;
                    try {
                        out = new ObjectOutputStream(bos);
                        out.writeObject(transactionVerificationLog);
                        transactionVerificationLogBytes = bos.toByteArray();
                    }
                    catch (Exception e) {
                        Log.e(LOG_TAG, "Cannot serialize transactionVerificationLog.");

                        // Remove Transaction Verification Log that fails to serialize.
                        iteratorTransactionVerificationLog.remove();
                    }
                    finally {
                        try {
                            if (out != null) {
                                out.close();
                            }
                        }
                        catch (IOException ioe) {
                        }

                        try {
                            bos.close();
                        }
                        catch (IOException ioe) {
                        }
                    }

                    if (transactionVerificationLogBytes != null) {
                        // NOTE: Including Le in C-APDU causes Lc to be processed incorrectly in remote card applet.
                        ByteBuffer transactionVerificationLogBuffer = ByteBuffer.allocate(APDU_HEADER_PUT_TRANSACTION_VERIFICATION_LOG.length + 
                                                                                          2 + 
                                                                                          transactionVerificationLogBytes.length);
                        transactionVerificationLogBuffer.put(APDU_HEADER_PUT_TRANSACTION_VERIFICATION_LOG);
                        transactionVerificationLogBuffer.putShort((short) transactionVerificationLogBytes.length);
                        transactionVerificationLogBuffer.put(transactionVerificationLogBytes);

                        tranceiveDataPutTransactionVerificationLog.packApdu(transactionVerificationLogBuffer.array(), true);

                        // Indicate tranceive needs to be performed.
                        tranceiveTransactionVerificationLog = true;
                    }
                }
                if (tranceiveTransactionVerificationLog) {
                    try {
                        transceive(tranceiveDataPutTransactionVerificationLog);
                    }
                    catch (IOException e) {
                        Log.e(LOG_TAG, "tPutTransactionVerificationLog transceive IOException Log", e);

                        // Indicate exception occurred.
                        tranceiveTransactionVerificationLog = false;

                        // No error recovery for now. Attempt again after next transaction.
                        /*
                        try {
                            postMessage("Put Transaction Verification Log Error\n" + 
                                        "Exception: " + getNonNullMessage(e), 
                                        false, null);
                        }
                        catch (IOException e1) {
                        }
                        */
                    }
                }

                try {
                    disconnect();
                }
                catch (IOException e) {
                }

                if (tranceiveTransactionVerificationLog) {
                    byte[] selectResponse = tranceiveDataPutTransactionVerificationLog.getNextResponse();
                    if ((selectResponse == null) || 
                        (selectResponse.length <= 2) || 
                        (ByteBuffer.wrap(selectResponse).getShort(selectResponse.length - 2) != ISO7816.SW_NO_ERROR)) {
                        String invalidResponse = DataUtil.byteArrayToHexString(selectResponse);
                        Log.e(LOG_TAG, "tranceiveDataPutTransactionVerificationLog invalid selectResponse: " + invalidResponse);

                        try {
                            if ((invalidResponse.length() == 4) && 
                                invalidResponse.equalsIgnoreCase(String.format("%04X", ISO7816.SW_FUNC_NOT_SUPPORTED))) {
                                terminated = true;
                                disabled = true;

                                // Delete existing card data.
                                accountParamsStatic = null;
                                arrayAccountParamsDynamic = null;
                                iccPrivKey = null;

                                handlerTimeToExpire.removeCallbacks(runnableTimeToExpire);

                                postMessage("Account is Terminated", false, null);
                            }
                            // No error recovery for now. Attempt again after next transaction.
                            /*
                            else {
                                postMessage("Account Not Available", false, null);
                            }
                            */
                        }
                        catch (IOException e) {
                        }

                        tPutTransactionVerificationLog = null;
                        return;
                    }

                    byte[] putTransactionVerificationResponse = tranceiveDataPutTransactionVerificationLog.getNextResponse();
                    while (putTransactionVerificationResponse != null) {
                        // DEBUG
                        Log.i(LOG_TAG, "putTransactionVerificationResponse=" + DataUtil.byteArrayToHexString(putTransactionVerificationResponse));

                        if ((putTransactionVerificationResponse.length > 2) && 
                            (ByteBuffer.wrap(putTransactionVerificationResponse).getShort(putTransactionVerificationResponse.length - 2) == ISO7816.SW_NO_ERROR)) {
                            // Extract transaction timestamp for Transaction Verification Log successfully saved in remote card applet without SW.
                            String transactionTimestamp = DataUtil.byteArrayToHexString(putTransactionVerificationResponse, 
                                                                                        0, 
                                                                                        putTransactionVerificationResponse.length - 2);
                            if (transactionTimestamp.endsWith("F")) {
                                // Remove padding.
                                transactionTimestamp = transactionTimestamp.substring(0,transactionTimestamp.length() - 1);
                            }

                            // Remove Transaction Verification Log successfully saved in remote card applet.
                            transactionVerificationLogs.remove(transactionTimestamp);
                        }

                        putTransactionVerificationResponse = tranceiveDataPutTransactionVerificationLog.getNextResponse();
                    }
                }

                tPutTransactionVerificationLog = null;
            }
        });

        this.tPutTransactionVerificationLog.start();
    }

}
