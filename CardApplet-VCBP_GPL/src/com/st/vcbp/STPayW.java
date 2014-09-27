/**
 * This file is part of CardApplet-VCBP which is card applet implementation 
 * of V Cloud-Based Payments for SimplyTapp cloud platform.
 * Copyright 2014 SimplyTapp, Inc.
 * 
 * CardApplet-VCBP is free software: you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License, or 
 * (at your option) any later version.
 * 
 * CardApplet-VCBP is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License 
 * along with CardApplet-VCBP.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.st.vcbp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
//import java.util.Iterator;
import java.util.TimeZone;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateCrtKey;
import javacardx.apdu.ExtendedLength;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

import com.st.vcbp.crypto.KeyDerivation;
import com.st.vcbp.data.AccountParamsDynamic;
import com.st.vcbp.data.AccountParamsStatic;
import com.st.vcbp.data.LinkedHashMapFixedSize;
import com.st.vcbp.data.TransactionVerificationLog;

/**
 * Implementation based on V Cloud-Based Payments Contactless
 * Specifications Version 1.3 July 2014.
 * 
 * @author SimplyTapp, Inc.
 * @version 1.3.2 GPL
 */
public final class STPayW extends Applet implements ExtendedLength {

    private static final long serialVersionUID = 1L;

    // 1.3.2
    private static final byte[] VERSION = { 0x31, 0x2E, 0x33, 0x2E, 0x32 };

    private static final String GCM_MSG_ACCOUNT_PARAMETERS_UPDATE = "apupdate";
    private static final String GCM_MSG_DEACTIVATE                = "deactivate";
    private static final String GCM_MSG_TERMINATE                 = "terminate";

    // CLA for supported commands.
    private static final byte CLA_PROPRIETARY        = (byte) 0x80;
    private static final byte CLA_PROPRIETARY_SECURE = (byte) 0x84;

    // CLA/INS for supported commands.
    // GP Commands
    private static final short CLA_INS_INITIALIZE_UPDATE                        = (short) 0x8050;
    private static final short CLA_INS_SET_STATUS                               = (short) 0x80F0;
    private static final short CLA_INS_STORE_DATA                               = (short) 0x80E2;
    private static final short CLA_INS_EXTERNAL_AUTHENTICATE                    = (short) 0x8482;
    private static final short CLA_INS_SET_STATUS_SECURED                       = (short) 0x84F0;
    private static final short CLA_INS_STORE_DATA_SECURED                       = (short) 0x84E2;
    // Card Agent Commands
    private static final short CLA_INS_GET_STATIC_ACCOUNT_PARAMETERS            = (short) 0x8030;
    private static final short CLA_INS_GET_DYNAMIC_ACCOUNT_PARAMETERS           = (short) 0x8032;
    private static final short CLA_INS_PUT_TRANSACTION_VERIFICATION_LOG         = (short) 0x8034;
    // Issuer Commands
    private static final short CLA_INS_GET_TRANSACTION_VERIFICATION_LOG         = (short) 0x8040;
    private static final short CLA_INS_GET_TRANSACTION_VERIFICATION_LOG_SECURED = (short) 0x8440;

    // Application-specific SW.
    private static final short SW_UNKNOWN_DGI = (short) 0x6A88;

    // Proprietary Personalization Tags
    private static final short TAG_MAX_NUM_LIVE_DYNAMIC_ACCT_PARAMS           = (short) 0xDF30;
    private static final short TAG_MIN_THRESHOLD_NUM_LIVE_DYNAMIC_ACCT_PARAMS = (short) 0xDF31;
    private static final short TAG_TIME_TO_LIVE_CHECK_INTERVAL                = (short) 0xDF39;
    private static final short TAG_TIME_TO_LIVE_DYNAMIC_ACCT_PARAMS           = (short) 0xDF3A;
    private static final short TAG_MAX_NUM_TRANSACTION_VERIFICATION_LOGS      = (short) 0xDF3B;

    // Records in AFL list.
    private HashMap<Short, byte[]> records = new HashMap<Short, byte[]>();

    // Variables for cryptogram calculation.
    private DESKey udk;
    private DESKey udkMsd;
    private DESKey tempKey;
    private RSAPrivateCrtKey iccPrivKey;

    private transient SecureChannel secureChannel;

    // NOTE: Use 'gpState' instead of using GPSystem.getCardContentState() and GPSystem.setCardContentState().
    // Supported States:
    // - GPSystem.APPLICATION_SELECTABLE (7)
    // - GPSystem.SECURITY_DOMAIN_PERSONALIZED (15)
    // - GPSystem.CARD_LOCKED (127)
    // - GPSystem.CARD_TERMINATED (-1)
    private byte gpState;

    private AccountParamsStatic accountParamsStatic;
    private AccountParamsDynamic accountParamsDynamic;

    private int prevHourOfDay;
    private short lukGenerationCounter;

    private short sequenceCounter;

    // Time to Live in Hours
    // Supports:
    // - 0 = never expire
    // - 1-255 = expires in 1-255 hours
    private byte timeToLiveHours;

    private LinkedHashMapFixedSize<String, TransactionVerificationLog> transactionVerificationLogs;

    /**
     * Creates Java Card applet object.
     * 
     * @param array
     *            the byte array containing the AID bytes
     * @param offset
     *            the start of AID bytes in array
     * @param length
     *            the length of the AID bytes in array
     */
    private STPayW(byte[] array, short offset, byte length) {
        this.udk = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);

        this.udkMsd = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);

        this.tempKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_DES3_2KEY, false);

        this.gpState = GPSystem.APPLICATION_SELECTABLE;

        this.accountParamsStatic = new AccountParamsStatic();

        // Build Static Account Parameters.
        // NOTE: This is a kludge to retrieve AID. This would not work with real Java Card.
        byte[] aidBuffer = new byte[16];
        byte aidLength = JCSystem.getAID().getBytes(aidBuffer, (short) 0);
        this.accountParamsStatic.setAid(aidBuffer, (short) 0, aidLength);

        this.sequenceCounter = (short) 0;

        try {
            setStatePerso();
        }
        catch (IOException e) {
        }

        // Register instance AID.
        register(array, (short) (offset + (byte) 1), array[offset]);
    }

    /**
     * Registers applet instance AID by calling constructor.
     * 
     * @param array
     *            the byte array containing the AID bytes
     * @param offset
     *            the start of AID bytes in array
     * @param length
     *            the length of the AID bytes in array
     * @see javacard.framework.Applet.install
     */
	public static void install(byte[] array, short offset, byte length) {
		new STPayW(array, offset, length);
	}

    /**
     * Processes incoming APDU command.
     * <p>
     * Supported commands (<b>CLA INS</b>):
     * <ul>
     * <li><b>00 A4</b>: Select
     * <li><b>80 30</b>: Get Static Account Parameters [from card agent]
     * <li><b>80 32</b>: Get Dynamic Account Parameters [from card agent]
     * <li><b>80 34</b>: Put Transaction Verification Log [from card agent]
     * <li><b>80 40</b>: Get Transaction Verification Log [from Issuer]
     * <li><b>80 50</b>: Initialize Update [from Issuer]
     * <li><b>80 E2</b>: Store Data [from Issuer]
     * <li><b>80 F0</b>: Set Status [from Issuer]
     * <li><b>84 40</b>: Get Transaction Verification Log, Secured [from Issuer]
     * <li><b>84 82</b>: External Authenticate [from Issuer]
     * <li><b>84 E2</b>: Store Data, Secured [from Issuer]
     * <li><b>84 F0</b>: Set Status, Secured [from Issuer]
     * </ul>
     * 
     * @param apdu
     *            the incoming <code>APDU</code> object
     * @see javacard.framework.Applet.process
     */
	public void process(APDU apdu) throws ISOException {
		byte[] apduBuffer = apdu.getBuffer();

        byte protocolMedia = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);

        if (selectingApplet()) {
            // Process Select command.

            // Check if card is terminated.
            if (this.gpState == GPSystem.CARD_TERMINATED) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }

            // Only support direct selection by DF name of first record and return FCI.
            // Check if P1=0x04 and P2=0x00.
            if (Util.getShort(apduBuffer, ISO7816.OFFSET_P1) != (short) 0x0400) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }

            // Check AID, partial select not supported.
            short aidLength = apdu.setIncomingAndReceive();
            if (!JCSystem.getAID().equals(apduBuffer, ISO7816.OFFSET_CDATA, (byte) aidLength)) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }

            // Construct Select response data.
            if (protocolMedia == APDU.PROTOCOL_MEDIA_SOFT) {
                // Return VERSION if Select command is from card agent.
                apdu.setOutgoingAndSend((short) 0, 
                                        Util.arrayCopyNonAtomic(VERSION, (short) 0, 
                                                                apduBuffer, (short) 0, 
                                                                (short) VERSION.length));

                return;
            }
            apduBuffer[0] = (byte) 0x6F;
            apduBuffer[2] = (byte) 0x84;
            apduBuffer[3] = JCSystem.getAID().getBytes(apduBuffer, (short) 4);
            if ((this.gpState == GPSystem.SECURITY_DOMAIN_PERSONALIZED) && 
                (protocolMedia == APDU.PROTOCOL_MEDIA_NFC)) {
                // FCI Template must be present if personalized.
                apduBuffer[1] = (byte) (Util.arrayCopyNonAtomic(this.accountParamsStatic.getTagA5Data(), (short) 0, 
                                                                apduBuffer, (short) (apduBuffer[3] + 4), 
                                                                (short) this.accountParamsStatic.getTagA5Data().length) - 2);
            }
            else {
                apduBuffer[1] = (byte) (apduBuffer[3] + 2);
            }

            apdu.setOutgoingAndSend((short) 0, (short) (apduBuffer[1] + 2));

            return;
        }

        // Handle commands starting from ones that have higher timing dependence.
        // Get CLA (ignore logical channel bits) and INS.
        byte claByte = (byte) (apduBuffer[ISO7816.OFFSET_CLA] & 0xFC);
        short capduClaIns = (short) (Util.getShort(apduBuffer, ISO7816.OFFSET_CLA) & (short) 0xFCFF);
        switch (capduClaIns) {
        case CLA_INS_GET_STATIC_ACCOUNT_PARAMETERS: {
            // Process Get Static Account Parameters command (from card agent).

            if (this.gpState != GPSystem.SECURITY_DOMAIN_PERSONALIZED) {
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }

            if (protocolMedia != APDU.PROTOCOL_MEDIA_SOFT) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            getAccountParamsStatic(apdu);

            return;
        }
        case CLA_INS_GET_DYNAMIC_ACCOUNT_PARAMETERS: {
            // Process Get Dynamic Account Parameters command (from card agent).

            if (this.gpState != GPSystem.SECURITY_DOMAIN_PERSONALIZED) {
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }

            if (protocolMedia != APDU.PROTOCOL_MEDIA_SOFT) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            getAccountParamsDynamic(apdu);

            return;
        }
        case CLA_INS_PUT_TRANSACTION_VERIFICATION_LOG: {
            // Process Put Transaction Verification Log command (from card agent).

            if ((this.gpState != GPSystem.SECURITY_DOMAIN_PERSONALIZED) || 
                (protocolMedia != APDU.PROTOCOL_MEDIA_SOFT)) {
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }

            putTransactionVerificationLog(apdu);

            return;
        }
        case CLA_INS_GET_TRANSACTION_VERIFICATION_LOG:
        case CLA_INS_GET_TRANSACTION_VERIFICATION_LOG_SECURED: {
            // Process Get Transaction Verification Log command (from Issuer).

            if (this.gpState == GPSystem.APPLICATION_SELECTABLE) {
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }

            getTransactionVerificationLog(apdu);

            return;
        }
        case CLA_INS_INITIALIZE_UPDATE: {
            // Process Initialize for Update command.

            // NOTE: Allowed post-personalization.
            /*
            if (this.gpState == GPSystem.SECURITY_DOMAIN_PERSONALIZED) {
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }
            */

            // Obtain handle to SecureChannel interface.
            this.secureChannel = GPSystem.getSecureChannel();
            this.secureChannel.resetSecurity();

            // Use GP API to process the APDU.
            // Note: Returns SW=0x6700 if Lc is not 0x08.
            short respLen = this.secureChannel.processSecurity(apdu);

            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, respLen);

            return;
        }
        case CLA_INS_EXTERNAL_AUTHENTICATE: {
            // Process External Authenticate command.

            // NOTE: Allowed post-personalization.
            /*
            if (this.gpState == GPSystem.SECURITY_DOMAIN_PERSONALIZED) {
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }
            */

            if (this.secureChannel == null) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            // Use GP API to process the APDU.
            // Note: If Initialize Update has not been processed, processSecurity automatically returns SW=0x6985.
            // Note: If External Authenticate has already been processed, processSecurity automatically returns SW=0x6985.
            this.secureChannel.processSecurity(apdu);

            // Note: There is no response data.

            return;
        }
        case CLA_INS_SET_STATUS:
        case CLA_INS_SET_STATUS_SECURED: {
            // Process Set Status command.

            // NOTE: Only allowed post-personalization.
            if ((this.gpState == GPSystem.APPLICATION_SELECTABLE) || 
                (this.gpState == GPSystem.CARD_TERMINATED)) {
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }

            // Check if External Authenticate has been performed successfully.
            if ((byte) (this.secureChannel.getSecurityLevel() & SecureChannel.AUTHENTICATED) != SecureChannel.AUTHENTICATED) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            // Check if P1 indicates status type is "Application or Supplementary Security Domain" 
            // and if P2 indicates supported state control.
            byte stateControl = apduBuffer[ISO7816.OFFSET_P2];
            if ((apduBuffer[ISO7816.OFFSET_P1] != (byte) 0x40) || 
                ((stateControl != GPSystem.SECURITY_DOMAIN_PERSONALIZED) && 
                 (stateControl != GPSystem.CARD_LOCKED) && 
                 (stateControl != GPSystem.CARD_TERMINATED))) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }

            short cdataLength = apdu.setIncomingAndReceive();

            // Check GP security level is C_MAC or C_MAC+C_DECRYPTION.
            if ((this.secureChannel.getSecurityLevel() & (byte) 0x03) >= SecureChannel.C_MAC) {
                // Use GP API to unwrap data.
                try {
                    cdataLength = this.secureChannel.unwrap(apduBuffer, (short) 0, (short) (ISO7816.OFFSET_CDATA + cdataLength));
                }
                catch (ISOException isoe) {
                    // Throw security exception to be consistent with SE.
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                cdataLength -= ISO7816.OFFSET_CDATA;
            }

            // Validate AID.
            apduBuffer[(byte) 64] = JCSystem.getAID().getBytes(apduBuffer, (short) 65);
            if ((cdataLength != apduBuffer[(byte) 64]) || 
                (Util.arrayCompare(apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer, (short) 65, cdataLength) != (byte) 0)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            String gcmMsg = null;
            if (stateControl == GPSystem.SECURITY_DOMAIN_PERSONALIZED) {
                // Resume account.

                if (this.gpState != GPSystem.SECURITY_DOMAIN_PERSONALIZED) {
                    // Send message to card agent to indicate card activated.
                    gcmMsg = GCM_MSG_ACCOUNT_PARAMETERS_UPDATE;
                }
            }
            else if (stateControl == GPSystem.CARD_LOCKED) {
                // Suspend account.

                if (this.gpState != GPSystem.CARD_LOCKED) {
                    // Send message to card agent to indicate card deactivated.
                    gcmMsg = GCM_MSG_DEACTIVATE;
                }
            }
            else {
                // Delete account.

                try {
                    setStateTerminated();
                }
                catch (IOException e) {
                }

                // Send message to card agent to indicate card terminated.
                gcmMsg = GCM_MSG_TERMINATE;
            }

            // Update GP state.
            this.gpState = stateControl;

            if (gcmMsg != null) {
                // Send message to card agent.
                try {
                    sendToAgent(gcmMsg);
                }
                catch (IOException e) {
                    ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
                }
            }

            // Note: There is no response data.

            return;
        }
        case CLA_INS_STORE_DATA:
        case CLA_INS_STORE_DATA_SECURED: {
            // Process Store Data command.

            // NOTE: Allow post-issuance personalization update.
            /*
            // Check if applet is already personalized.
            if (this.gpState == GPSystem.SECURITY_DOMAIN_PERSONALIZED) {
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }
            */

            // Check if External Authenticate has been performed successfully.
            if ((byte) (this.secureChannel.getSecurityLevel() & SecureChannel.AUTHENTICATED) != SecureChannel.AUTHENTICATED) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            byte p1 = apduBuffer[ISO7816.OFFSET_P1];

            short cdataLength = apdu.setIncomingAndReceive();

            // Check GP security level is C_MAC or C_MAC+C_DECRYPTION.
            if ((this.secureChannel.getSecurityLevel() & (byte) 0x03) >= SecureChannel.C_MAC) {
                // Use GP API to unwrap data.
                try {
                    cdataLength = this.secureChannel.unwrap(apduBuffer, (short) 0, (short) (ISO7816.OFFSET_CDATA + cdataLength));
                }
                catch (ISOException isoe) {
                    // Throw security exception to be consistent with SE.
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                cdataLength -= ISO7816.OFFSET_CDATA;
            }

            // NOTE: Restrict 1 DGI per Store Data command.
            short dgi = Util.getShort(apduBuffer, ISO7816.OFFSET_CDATA);
            short dgiOffset = 7;
            // DGI length is defined to be 1 byte.
            short dgiLength = (short) (apduBuffer[dgiOffset++] & 0xFF);

            if ((short) (cdataLength - (byte) 3) != dgiLength) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            if (((dgi & (short) 0xF000) == (short) 0x8000) || 
                ((p1 & (byte) 0x60) == (byte) 0x60)) {
                dgiLength = this.secureChannel.decryptData(apduBuffer, dgiOffset, dgiLength);
            }

            storeData(apduBuffer, dgi, dgiOffset, dgiLength);

            // Check if last Store Data command.
            if ((p1 & (byte) 0x80) == (byte) 0x80) {
                // Check perso state.
                if (this.gpState == GPSystem.APPLICATION_SELECTABLE) {
                    // Check if all mandatory data objects are personalized.
                    // Return DGI or tag of missing data elements separated by 'FF'.
                    dgiOffset = (short) 0;
                    if (this.accountParamsStatic.getTagA5Data() == null) {
                        dgiOffset = Util.setShort(apduBuffer, dgiOffset, (short) 0x9102);
                    }
                    if (this.accountParamsStatic.getGpoResponseQvsdc() == null) {
                        if (dgiOffset > (short) 0) {
                            apduBuffer[dgiOffset++] = (byte) 0xFF;
                        }
                        dgiOffset = Util.setShort(apduBuffer, dgiOffset, (short) 0x9207);
                    }
                    if (this.accountParamsStatic.getIssuerApplicationData() == null) {
                        if (dgiOffset > (short) 0) {
                            apduBuffer[dgiOffset++] = (byte) 0xFF;
                        }
                        dgiOffset = Util.setShort(apduBuffer, dgiOffset, (short) 0x9200);
                    }
                    if (this.accountParamsStatic.getTrack2EquivalentData() == null) {
                        if (dgiOffset > (short) 0) {
                            apduBuffer[dgiOffset++] = (byte) 0xFF;
                        }
                        apduBuffer[dgiOffset++] = (byte) 0x57;
                    }
                    if (this.accountParamsStatic.getPanSequenceNumber() == null) {
                        if (dgiOffset > (short) 0) {
                            apduBuffer[dgiOffset++] = (byte) 0xFF;
                        }
                        dgiOffset = Util.setShort(apduBuffer, dgiOffset, (short) 0x5F34);
                    }
                    if (this.accountParamsStatic.getCardTransactionQualifier() == null) {
                        if (dgiOffset > (short) 0) {
                            apduBuffer[dgiOffset++] = (byte) 0xFF;
                        }
                        dgiOffset = Util.setShort(apduBuffer, dgiOffset, (short) 0x9F6C);
                    }
                    if (!this.udk.isInitialized()) {
                        if (dgiOffset > (short) 0) {
                            apduBuffer[dgiOffset++] = (byte) 0xFF;
                        }
                        dgiOffset = Util.setShort(apduBuffer, dgiOffset, (short) 0x8000);
                    }
                    if (dgiOffset > (short) 0) {
                        apdu.setOutgoingAndSend((short) 0, dgiOffset);

                        // NOTE: Throwing exception returns empty response data.
                        //ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                        return;
                    }

                    String track2EquivalentData = DataUtil.byteArrayToHexString(this.accountParamsStatic.getTrack2EquivalentData());
                    int separatorOffset = track2EquivalentData.indexOf("D");
                    String pan = track2EquivalentData.substring(4, separatorOffset);

                    String tempExpDate = "20" + track2EquivalentData.substring(separatorOffset + 1, separatorOffset + 5);

                    Calendar expDate = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
                    expDate.set(Integer.parseInt(tempExpDate.substring(0, 4)), 
                                // Next month 0th day which reverts to this month last day.
                                Integer.parseInt(tempExpDate.substring(4)), 0, 
                                // Last hour, minute, second of the day.
                                23, 59, 59);

                    try {
                        setStatePersonalized(pan, expDate, "", "");
                    }
                    catch (IOException e) {
                    }

                    // Update application life cycle state to personalized.
                    this.gpState = GPSystem.SECURITY_DOMAIN_PERSONALIZED;
                }
                else if (this.gpState == GPSystem.SECURITY_DOMAIN_PERSONALIZED) {
                    // Send message to card agent to trigger account parameters update.
                    try {
                        sendToAgent(GCM_MSG_ACCOUNT_PARAMETERS_UPDATE);
                    }
                    catch (IOException e) {
                        ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
                    }
                }
            }

            return;
        }
        default:
        }

        if ((claByte == ISO7816.CLA_ISO7816) || 
            (claByte == CLA_PROPRIETARY) || 
            (claByte == CLA_PROPRIETARY_SECURE)) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    // NOTE: Processing this APDU does not use Java Card methods.
    private void getAccountParamsStatic(APDU apdu) throws ISOException {
        byte[] apduBuffer = apdu.getBuffer();

        // Check if P1=0x00 and P2=0x00.
        if (Util.getShort(apduBuffer, ISO7816.OFFSET_P1) != (short) 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // No Lc.

        // Retrieve Le.
        short dataLength = apdu.setOutgoing();
        // Check if Le=0x00 or 0x0000.
        if ((dataLength != (short) 256) && 
            (dataLength != (short) 32767)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Set secret data in serializable class.
        if ((this.iccPrivKey != null) && this.iccPrivKey.isInitialized()) {
            try {
                this.accountParamsStatic.setIccPrivKeyCrtCoefficient(apduBuffer, (short) 0, 
                                                                     this.iccPrivKey.getPQ(apduBuffer, (short) 0));
                this.accountParamsStatic.setIccPrivKeyPrimeExponentQ(apduBuffer, (short) 0, 
                                                                     this.iccPrivKey.getDQ1(apduBuffer, (short) 0));
                this.accountParamsStatic.setIccPrivKeyPrimeExponentP(apduBuffer, (short) 0, 
                                                                     this.iccPrivKey.getDP1(apduBuffer, (short) 0));
                this.accountParamsStatic.setIccPrivKeyPrimeQ(apduBuffer, (short) 0, 
                                                             this.iccPrivKey.getQ(apduBuffer, (short) 0));
                this.accountParamsStatic.setIccPrivKeyPrimeP(apduBuffer, (short) 0, 
                                                             this.iccPrivKey.getP(apduBuffer, (short) 0));

                this.accountParamsStatic.setIccKeyModulusLength(this.iccPrivKey.getSize() / 8);
            }
            catch (Exception e) {
            }

            Util.arrayFillNonAtomic(apduBuffer, (short) 0, (short) (this.iccPrivKey.getSize() / (byte) 16), (byte) 0x00);
        }

        // DEBUG
        /*
        if (this.accountParamsStatic != null) {
            System.out.println("accountParamsStatic Aid: " + DataUtil.byteArrayToHexString(this.accountParamsStatic.getAid()));
            System.out.println("accountParamsStatic AidPpse: " + DataUtil.byteArrayToHexString(this.accountParamsStatic.getAidPpse()));
            System.out.println("accountParamsStatic PpseResponse: " + DataUtil.byteArrayToHexString(this.accountParamsStatic.getPpseResponse()));
            System.out.println("accountParamsStatic TagA5Data: " + DataUtil.byteArrayToHexString(this.accountParamsStatic.getTagA5Data()));
            System.out.println("accountParamsStatic GpoResponseMsd: " + DataUtil.byteArrayToHexString(this.accountParamsStatic.getGpoResponseMsd()));
            System.out.println("accountParamsStatic GpoResponseQvsdc: " + DataUtil.byteArrayToHexString(this.accountParamsStatic.getGpoResponseQvsdc()));
            System.out.println("accountParamsStatic IssuerApplicationData: " + DataUtil.byteArrayToHexString(this.accountParamsStatic.getIssuerApplicationData()));
            System.out.println("accountParamsStatic PanSequenceNumber: " + DataUtil.byteArrayToHexString(this.accountParamsStatic.getPanSequenceNumber()));
            System.out.println("accountParamsStatic CardTransactionQualifier: " + DataUtil.byteArrayToHexString(this.accountParamsStatic.getCardTransactionQualifier()));
            System.out.println("accountParamsStatic Track2EquivalentData: " + DataUtil.byteArrayToHexString(this.accountParamsStatic.getTrack2EquivalentData()));
            System.out.println("accountParamsStatic CardholderName: " + DataUtil.byteArrayToHexString(this.accountParamsStatic.getCardholderName()));
            System.out.println("accountParamsStatic CvmList: " + DataUtil.byteArrayToHexString(this.accountParamsStatic.getCvmList()));
            //System.out.println("accountParamsStatic IccPrivKeyCrtCoefficient: " + DataUtil.byteArrayToHexString(this.accountParamsStatic.getIccPrivKeyCrtCoefficient()));
            //System.out.println("accountParamsStatic IccPrivKeyPrimeExponentQ: " + DataUtil.byteArrayToHexString(this.accountParamsStatic.getIccPrivKeyPrimeExponentQ()));
            //System.out.println("accountParamsStatic IccPrivKeyPrimeExponentP: " + DataUtil.byteArrayToHexString(this.accountParamsStatic.getIccPrivKeyPrimeExponentP()));
            //System.out.println("accountParamsStatic IccPrivKeyPrimeQ: " + DataUtil.byteArrayToHexString(this.accountParamsStatic.getIccPrivKeyPrimeQ()));
            //System.out.println("accountParamsStatic IccPrivKeyPrimeP: " + DataUtil.byteArrayToHexString(this.accountParamsStatic.getIccPrivKeyPrimeP()));
            System.out.println("accountParamsStatic IccKeyModulusLength: " + this.accountParamsStatic.getIccKeyModulusLength());
            System.out.println("accountParamsStatic MaxNumberAccountParamsDynamic: " + this.accountParamsStatic.getMaxNumberAccountParamsDynamic());
            System.out.println("accountParamsStatic MinThresholdNumberAccountParamsDynamic: " + this.accountParamsStatic.getMinThresholdNumberAccountParamsDynamic());
            System.out.println("accountParamsStatic CheckIntervalTimeToExpire: " + this.accountParamsStatic.getCheckIntervalTimeToExpire());
            System.out.println("accountParamsStatic MaxTransactionVerificationLogs: " + this.accountParamsStatic.getMaxTransactionVerificationLogs());
            System.out.println();
        }
        */

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = null;
        byte[] accountParamsStaticBytes = null;
        try {
            out = new ObjectOutputStream(bos);
            out.writeObject(this.accountParamsStatic);
            accountParamsStaticBytes = bos.toByteArray();
        }
        catch (Exception e) {
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

        // Clear secret data in serializable class.
        if ((this.iccPrivKey != null) && this.iccPrivKey.isInitialized()) {
            this.accountParamsStatic.setIccPrivKeyCrtCoefficient(null, (short) 0, (short) 0);
            this.accountParamsStatic.setIccPrivKeyPrimeExponentQ(null, (short) 0, (short) 0);
            this.accountParamsStatic.setIccPrivKeyPrimeExponentP(null, (short) 0, (short) 0);
            this.accountParamsStatic.setIccPrivKeyPrimeQ(null, (short) 0, (short) 0);
            this.accountParamsStatic.setIccPrivKeyPrimeP(null, (short) 0, (short) 0);
        }

        if (accountParamsStaticBytes != null) {
            try {
                if (dataLength < (short) accountParamsStaticBytes.length) {
                    Util.arrayCopyNonAtomic(accountParamsStaticBytes, (short) 0, apduBuffer, (short) 0, dataLength);
                }
                else {
                    dataLength = Util.arrayCopyNonAtomic(accountParamsStaticBytes, (short) 0, apduBuffer, (short) 0, (short) accountParamsStaticBytes.length);
                }
            }
            catch (Exception e) {
                // In case of buffer overflow.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            apdu.setOutgoingLength(dataLength);
            apdu.sendBytes((short) 0, dataLength);
        }
        else {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    // NOTE: Processing this APDU does not use Java Card methods.
    private void getAccountParamsDynamic(APDU apdu) throws ISOException {
        byte[] apduBuffer = apdu.getBuffer();

        // Check if P1=0x00 and P2=0x00.
        if (Util.getShort(apduBuffer, ISO7816.OFFSET_P1) != (short) 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // No Lc.

        // Retrieve Le.
        short dataLength = apdu.setOutgoing();
        // Check if Le=0x00 or 0x0000.
        if ((dataLength != (short) 256) && 
            (dataLength != (short) 32767)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Increment Sequence Counter.
        this.sequenceCounter++;

        // Initialize Account Parameters Index (YHHHHCC).
        // --------------------
        Calendar calendar = Calendar.getInstance();
        String year = String.valueOf(calendar.get(Calendar.YEAR));
        // Least significant digit of the current year. (0-9)
        year = year.substring(year.length() - 1);
        int dayOfYear = calendar.get(Calendar.DAY_OF_YEAR) - 1;
        int hourOfDay = calendar.get(Calendar.HOUR_OF_DAY) + 1;
        if (hourOfDay != this.prevHourOfDay) {
            this.prevHourOfDay = hourOfDay;
            this.lukGenerationCounter = (short) 0;
        }
        // Number of hours since start of January 1 of the current year. (0001-8784)
        String hours = String.format("%04d", (dayOfYear * 24) + hourOfDay);
        // Counter that starts at 00 at the beginning of each hour and incremented by 1 each time Limited Use Key is generated. (00-99)
        if (this.lukGenerationCounter >= (short) 100) {
            this.lukGenerationCounter = (short) (this.lukGenerationCounter % 100);

            // Generate warning when LUK Generation Counter overflows.
            //System.out.println("lukGenerationCounter overflowed");
        }
        String cc = String.format("%02d", this.lukGenerationCounter++);
        // --------------------

        short keyLength = (short) 0;
        final short lukOffset = (short) 0;
        final short lukMsdOffset = (short) (lukOffset + KeyDerivation.BYTE_LENGTH_DES3_2KEY);
        if (Util.getShort(this.accountParamsStatic.getIssuerApplicationData(), AccountParamsStatic.IAD_VALUE_OFFSET) == (short) 0x1F43) {
            // Derive LUK for CVN 43.
            keyLength = KeyDerivation.deriveCvn43Luk(this.udk, this.udkMsd, 
                                                     year, hours, cc, 
                                                     apduBuffer, lukOffset);
        }
        else {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Set expiration timestamp based on current timestamp.
        long expirationTimestamp = (long) ((this.timeToLiveHours & 0xFF) * 3600000);
        // TEST: Use minutes instead of hours for testing.
        //long expirationTimestamp = (long) ((this.timeToLiveHours & 0xFF) * 60000);
        if (expirationTimestamp > 0) {
            expirationTimestamp += calendar.getTimeInMillis();
        }
        else {
            expirationTimestamp = 0;
        }

        // Generate Dynamic Account Parameters.
        if (keyLength == KeyDerivation.BYTE_LENGTH_DES3_2KEY) {
            this.accountParamsDynamic = new AccountParamsDynamic(year + hours + cc, 
                                                                 apduBuffer, lukOffset, 
                                                                 expirationTimestamp, 
                                                                 this.sequenceCounter);
        }
        else if (keyLength == (short) (2 * KeyDerivation.BYTE_LENGTH_DES3_2KEY)) {
            this.accountParamsDynamic = new AccountParamsDynamic(year + hours + cc, 
                                                                 apduBuffer, lukOffset, 
                                                                 expirationTimestamp, 
                                                                 this.sequenceCounter, 
                                                                 apduBuffer, lukMsdOffset);
        }
        else {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // DEBUG
        /*
        if (this.accountParamsDynamic != null) {
            System.out.println("accountParamsDynamic AccountParamtersIndex: " + this.accountParamsDynamic.getAccountParamtersIndex());
            System.out.println("accountParamsDynamic Luk: " + DataUtil.byteArrayToHexString(this.accountParamsDynamic.getLuk()));
            System.out.println("accountParamsDynamic ExpirationTimestamp: " + this.accountParamsDynamic.getExpirationTimestamp());
            System.out.println("accountParamsDynamic Atc: " + String.format("%04X", this.accountParamsDynamic.getAtc()));
            System.out.println("accountParamsDynamic LukMsd: " + DataUtil.byteArrayToHexString(this.accountParamsDynamic.getLukMsd()));
            System.out.println();
        }
        */

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = null;
        byte[] accountParamsDynamicBytes = null;
        try {
            out = new ObjectOutputStream(bos);
            out.writeObject(this.accountParamsDynamic);
            accountParamsDynamicBytes = bos.toByteArray();
        }
        catch (Exception e) {
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

        if (accountParamsDynamicBytes != null) {
            try {
                if (dataLength < (short) accountParamsDynamicBytes.length) {
                    Util.arrayCopyNonAtomic(accountParamsDynamicBytes, (short) 0, apduBuffer, (short) 0, dataLength);
                }
                else {
                    dataLength = Util.arrayCopyNonAtomic(accountParamsDynamicBytes, (short) 0, apduBuffer, (short) 0, (short) accountParamsDynamicBytes.length);
                }
            }
            catch (Exception e) {
                // In case of buffer overflow.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            apdu.setOutgoingLength(dataLength);
            apdu.sendBytes((short) 0, dataLength);
        }
        else {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    // NOTE: Processing this APDU does not use Java Card methods.
    private void putTransactionVerificationLog(APDU apdu) throws ISOException {
        byte[] apduBuffer = apdu.getBuffer();

        // Check if P1=0x00 and P2=0x00.
        if (Util.getShort(apduBuffer, ISO7816.OFFSET_P1) != (short) 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Retrieve Lc.
        short cdataLength = apdu.setIncomingAndReceive();
        short offsetCdata = apdu.getOffsetCdata();

        // Retrieve Le.
        short dataLength = apdu.setOutgoing();

        if (this.transactionVerificationLogs == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(apduBuffer, 
                                                            offsetCdata, 
                                                            cdataLength);
        ObjectInput in = null;
        TransactionVerificationLog transactionVerificationLog = null;
        String exceptionMsg = null;
        try {
            in = new ObjectInputStream(bis);
            transactionVerificationLog = (TransactionVerificationLog) in.readObject();

            if (transactionVerificationLog != null) {
                // DEBUG
                /*
                System.out.println("transactionVerificationLog UtcTimestamp: " + transactionVerificationLog.getUtcTimestamp());
                System.out.println("transactionVerificationLog AccountParametersIndex: " + transactionVerificationLog.getAccountParametersIndex());
                System.out.println("transactionVerificationLog TransactionType: " + transactionVerificationLog.getTransactionType());
                System.out.println("transactionVerificationLog UnpredictableNumber: " + transactionVerificationLog.getUnpredictableNumber());
                System.out.println();
                */

                this.transactionVerificationLogs.put(transactionVerificationLog.getAccountParametersIndex(), 
                                                     transactionVerificationLog);

                // DEBUG
                /*
                System.out.println("transactionVerificationLogs size: " + this.transactionVerificationLogs.size());
                Iterator<Map.Entry<String, TransactionVerificationLog>> iterator = this.transactionVerificationLogs.entrySet().iterator();
                while (iterator.hasNext()) {
                    final Map.Entry<String, TransactionVerificationLog> entry = iterator.next();
                    System.out.println("  key=" + entry.getKey());
                }
                System.out.println();
                */
            }
        }
        catch (Exception e) {
            exceptionMsg = e.getMessage();
            if (exceptionMsg == null) {
                exceptionMsg = "null";
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
        if (exceptionMsg != null) {
            // Return exception message.
            try {
                byte[] exceptionMsgBytes = exceptionMsg.getBytes("UTF-8");
                apdu.setOutgoingLength((short) exceptionMsgBytes.length);
                apdu.sendBytes((short) 0, 
                               Util.arrayCopyNonAtomic(exceptionMsgBytes, (short) 0, 
                                                       apduBuffer, (short) 0, (short) exceptionMsgBytes.length));
                return;
            }
            catch (UnsupportedEncodingException e) {
                ISOException.throwIt(ISO7816.SW_FILE_INVALID);
            }
        }

        if (transactionVerificationLog == null) {
            /*
            // DEBUG
            // Return received data.
            apdu.setOutgoingLength(cdataLength);
            apdu.sendBytes(offsetCdata, cdataLength);
            return;
            */
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Return transaction timestamp in response.
        byte[] transactionTimestamp = DataUtil.stringToCompressedByteArray(String.valueOf(transactionVerificationLog.getUtcTimestamp()));
        dataLength = Util.arrayCopyNonAtomic(transactionTimestamp, (short) 0, apduBuffer, (short) 0, (short) transactionTimestamp.length);

        apdu.setOutgoingLength(dataLength);
        apdu.sendBytes((short) 0, dataLength);
    }

    // NOTE: Processing this APDU does not use Java Card methods.
    private void getTransactionVerificationLog(APDU apdu) throws ISOException {
        byte[] apduBuffer = apdu.getBuffer();

        // Check if P1=0x00 and P2=0x00.
        if (Util.getShort(apduBuffer, ISO7816.OFFSET_P1) != (short) 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Check if External Authenticate has been performed successfully.
        if ((byte) (this.secureChannel.getSecurityLevel() & SecureChannel.AUTHENTICATED) != SecureChannel.AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        short cdataLength = apdu.setIncomingAndReceive();
        short offsetCdata = apdu.getOffsetCdata();

        // Check GP security level.
        if ((this.secureChannel.getSecurityLevel() & (byte) 0x03) >= SecureChannel.C_MAC) {
            // Use GP API to unwrap data.
            try {
                cdataLength = this.secureChannel.unwrap(apduBuffer, (short) 0, (short) (offsetCdata + cdataLength));
            }
            catch (ISOException isoe) {
                // Throw security exception to be consistent with SE.
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            cdataLength -= offsetCdata;
        }

        // Retrieve Le.
        short dataLength = apdu.setOutgoing();
        // Check if Lc=0x07.
        // Check if Le=0x00.
        if ((cdataLength != (short) 7) || 
            (dataLength != (short) 256)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (this.transactionVerificationLogs == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        String accountParameterIndex = null;
        try {
            accountParameterIndex = new String(apduBuffer, offsetCdata, cdataLength, "UTF-8");
        }
        catch (Exception e) {
        }
        if (accountParameterIndex == null) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        TransactionVerificationLog transactionVerificationLog = this.transactionVerificationLogs.get(accountParameterIndex);
        if (transactionVerificationLog == null) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = null;
        byte[] transactionVerificationLogBytes = null;
        try {
            out = new ObjectOutputStream(bos);
            out.writeObject(transactionVerificationLog);
            transactionVerificationLogBytes = bos.toByteArray();
        }
        catch (Exception e) {
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
            try {
                if (dataLength < (short) transactionVerificationLogBytes.length) {
                    Util.arrayCopyNonAtomic(transactionVerificationLogBytes, (short) 0, apduBuffer, (short) 0, dataLength);
                }
                else {
                    dataLength = Util.arrayCopyNonAtomic(transactionVerificationLogBytes, (short) 0, apduBuffer, (short) 0, (short) transactionVerificationLogBytes.length);
                }
            }
            catch (Exception e) {
                // In case of buffer overflow.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            apdu.setOutgoingLength(dataLength);
            apdu.sendBytes((short) 0, dataLength);
        }
        else {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    private void storeData(byte[] data, short dgi, short dgiOffset, short dgiLength) {
        // Check if DGI contains record data.
        if (((short) (dgi & (short) 0xFF00) >= (short) 0x0100) && 
            ((short) (dgi & (short) 0xFF00) <= (short) 0x0A00)) {
            // NOTE: SFIs outside of EVM range, '0BXX' to '1EXX', will not be stored in records.
            //((short) (dgi & (short) 0xFF00) <= (short) 0x1E00)) {
            // Store SFI record.
            this.records.put(dgi, Arrays.copyOfRange(data, dgiOffset, dgiOffset + dgiLength));

            // Build Static Account Parameters.
            this.accountParamsStatic.setSfiRecords(this.records);

            return;
        }

        switch (dgi) {
        case (short) 0x4000: {
            dgiLength += dgiOffset;
            while (dgiOffset < dgiLength) {
                short tag = Util.getShort(data, dgiOffset);
                dgiOffset += (byte) 2;

                if (data[dgiOffset++] != (byte) 1) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }

                // Build Static Account Parameters.
                byte value = data[dgiOffset++];
                if (tag == TAG_MAX_NUM_LIVE_DYNAMIC_ACCT_PARAMS) {
                    // Maximum Number of Live Dynamic Account Parameters
                    this.accountParamsStatic.setMaxNumberAccountParamsDynamic(value);
                }
                else if (tag == TAG_MIN_THRESHOLD_NUM_LIVE_DYNAMIC_ACCT_PARAMS) {
                    // Minimum Threshold Number of Live Dynamic Account Parameters
                    this.accountParamsStatic.setMinThresholdNumberAccountParamsDynamic(value);
                }
                else if (tag == TAG_TIME_TO_LIVE_CHECK_INTERVAL) {
                    // Time to Live Check Interval in Minutes
                    this.accountParamsStatic.setCheckIntervalTimeToExpire(value);
                }
                else if (tag == TAG_TIME_TO_LIVE_DYNAMIC_ACCT_PARAMS) {
                    // Time to Live in Hours
                    this.timeToLiveHours = value;
                }
                else if (tag == TAG_MAX_NUM_TRANSACTION_VERIFICATION_LOGS) {
                    // Maximum Number of Transaction Verification Logs
                    this.accountParamsStatic.setMaxTransactionVerificationLogs(value);

                    // Initialize Transaction Verification Log storage.
                    final int sizeTransactionVerificationLogs = this.accountParamsStatic.getMaxTransactionVerificationLogs();
                    if (sizeTransactionVerificationLogs <= 0) {
                        this.transactionVerificationLogs = null;
                    }
                    else {
                        if (this.transactionVerificationLogs == null) {
                            this.transactionVerificationLogs = new LinkedHashMapFixedSize<String, TransactionVerificationLog>(sizeTransactionVerificationLogs);
                        }
                        else {
                            this.transactionVerificationLogs.updateSize(sizeTransactionVerificationLogs);
                        }

                        // DEBUG
                        /*
                        System.out.println("transactionVerificationLogs size: " + this.transactionVerificationLogs.size());
                        Iterator<Map.Entry<String, TransactionVerificationLog>> iterator = this.transactionVerificationLogs.entrySet().iterator();
                        while (iterator.hasNext()) {
                            final Map.Entry<String, TransactionVerificationLog> entry = iterator.next();
                            System.out.println("  key=" + entry.getKey());
                        }
                        System.out.println();
                        */
                    }
                }
                else {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
            }

            return;
        }
        case (short) 0x8000:    // DES Key
        case (short) 0x8001: {  // Alternate DES Key for MSD
            // UDK (Unique Derivation Key).

            // Save temporarily in transient key object until KCV is verified.
            this.tempKey.setKey(data, dgiOffset);

            return;
        }
        case (short) 0x8201:
        case (short) 0x8202:
        case (short) 0x8203:
        case (short) 0x8204:
        case (short) 0x8205: {
            short keySize = (short) (dgiLength * (byte) 16);
            if (this.iccPrivKey == null) {
                // NOTE: 'keyEncryption' parameter not used.
                this.iccPrivKey = (RSAPrivateCrtKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, keySize, false);
            }
            else if (this.iccPrivKey.getSize() != keySize) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            if (dgi == (short) 0x8201) {
                // CRT constant q^-1 mod p
                this.iccPrivKey.setPQ(data, dgiOffset, dgiLength);
            }
            else if (dgi == (short) 0x8202) {
                // CRT constant d mod (q - 1)
                this.iccPrivKey.setDQ1(data, dgiOffset, dgiLength);
            }
            else if (dgi == (short) 0x8203) {
                // CRT constant d mod (p - 1)
                this.iccPrivKey.setDP1(data, dgiOffset, dgiLength);
            }
            else if (dgi == (short) 0x8204) {
                // CRT constant prime factor q
                this.iccPrivKey.setQ(data, dgiOffset, dgiLength);
            }
            else {
                // CRT constant prime factor p
                this.iccPrivKey.setP(data, dgiOffset, dgiLength);
            }

            return;
        }
        case (short) 0x9000:    // DES Key Check Value
        case (short) 0x9001: {  // Alternate DES Key Check Value
            // UDK KCV.

            final short kcvOffset = (short) 64;
            short kcvLength = KeyDerivation.generateKcv(this.tempKey, data, kcvOffset);
            if (kcvLength == (short) -1) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            // Compare computed KCV with received KCV.
            if (Util.arrayCompare(data, dgiOffset, data, kcvOffset, dgiLength) != (byte) 0) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            this.tempKey.getKey(data, (short) 0);
            this.tempKey.clearKey();
            if (dgi == (short) 0x9000) {
                // Save UDK.
                this.udk.setKey(data, (short) 0);
            }
            else {
                // Save alternate UDK for MSD.
                this.udkMsd.setKey(data, (short) 0);
            }
            Util.arrayFillNonAtomic(data, (short) 0, (short) 16, (byte) 0x00);

            return;
        }
        case (short) 0x9102: {  // Required
            // Build Static Account Parameters.
            // Select response data for contactless.
            this.accountParamsStatic.setTagA5Data(data, dgiOffset, dgiLength);

            return;
        }
        case (short) 0x9200: {
            // Build Static Account Parameters.
            // Issuer Application Data
            this.accountParamsStatic.setIssuerApplicationData(data, dgiOffset, dgiLength);

            return;
        }
        case (short) 0x9206: {  // Required
            // Build Static Account Parameters.
            // MSD GPO response data.
            this.accountParamsStatic.setGpoResponseMsd(data, dgiOffset, dgiLength);

            return;
        }
        case (short) 0x9207: {  // Required
            // Build Static Account Parameters.
            // qVSDC GPO response data.
            this.accountParamsStatic.setGpoResponseQvsdc(data, dgiOffset, dgiLength);

            return;
        }
        case (short) 0x0E01: {
            // Internal Data

            dgiLength += dgiOffset;
            while (dgiOffset < dgiLength) {
                // Find the tag (1 or 2 bytes).
                // If the low order 5 bits of high order byte are set, then we have a 2 byte tag.
                short tag = Util.makeShort(((byte) (data[dgiOffset] & 0x1F) == 0x1F) ? data[dgiOffset++] : (byte) 0, 
                                           data[dgiOffset++]);
                short length = (short) (data[dgiOffset++] & 0xFF);

                switch (tag) {
                case (short) 0x0057: {
                    // Build Static Account Parameters.
                    // Include tag and length.
                    this.accountParamsStatic.setTrack2EquivalentData(data, 
                                                                     (short) (dgiOffset - 2), 
                                                                     (short) (length + 2));

                    break;
                }
                case (short) 0x008E: {
                    // Build Static Account Parameters.
                    this.accountParamsStatic.setCvmList(data, dgiOffset, length);

                    break;
                }
                case (short) 0x5F20: {
                    // Build Static Account Parameters.
                    // Include tag and length.
                    this.accountParamsStatic.setCardholderName(data, 
                                                               (short) (dgiOffset - 3), 
                                                               (short) (length + 3));

                    break;
                }
                case (short) 0x5F34: {
                    if (length != (short) 1) {
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    }

                    // Build Static Account Parameters.
                    // Include tag and length.
                    this.accountParamsStatic.setPanSequenceNumber(data, 
                                                                  (short) (dgiOffset - 3), 
                                                                  (short) (length + 3));

                    break;
                }
                case (short) 0x9F6C: {
                    if (length != (short) 2) {
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    }

                    // Build Static Account Parameters.
                    // Include tag and length.
                    this.accountParamsStatic.setCardTransactionQualifier(data, 
                                                                         (short) (dgiOffset - 3), 
                                                                         (short) (length + 3));

                    break;
                }
                default:
                }

                dgiOffset += length;
            }

            return;
        }
        default:
            ISOException.throwIt(SW_UNKNOWN_DGI);
        }
    }

}
