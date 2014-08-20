/**
 * This file is part of CardApplet-MMPP which is card applet implementation 
 * of M Remote-SE Mobile PayP for SimplyTapp cloud platform.
 * Copyright 2014 SimplyTapp, Inc.
 * 
 * CardApplet-MMPP is free software: you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License, or 
 * (at your option) any later version.
 * 
 * CardApplet-MMPP is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License 
 * along with CardApplet-MMPP.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.st.mmpp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.Calendar;
import java.util.TimeZone;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RandomData;
import javacardx.apdu.ExtendedLength;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

import com.st.mmpp.crypto.DataEncryption;
import com.st.mmpp.crypto.DataGeneration;
import com.st.mmpp.data.CardProfile;
import com.st.mmpp.data.PaymentTokenPayloadSingleUseKey;

/**
 * Implementation of PayP based on Remote-SE Mobile PayP
 * 
 * @author SimplyTapp, Inc.
 * @version 1.2 GPL
 */
public final class STPayP extends Applet implements ExtendedLength {

    private static final long serialVersionUID = 1L;

    // Remote Management Information definitions.
    private static final byte RMI_VERSION                    = (byte) 0x60;
    private static final byte RMI_FUNCTION_PTP_CP            = (byte) 0x01;
    private static final byte RMI_FUNCTION_PTP_SUK           = (byte) 0x02;
    private static final byte RMI_FUNCTION_MOBILE_CHECK      = (byte) 0x1C;
    private static final byte RMI_FUNCTION_MOBILE_PIN_CHANGE = (byte) 0x1D;
    private static final byte RMI_FUNCTION_DEACTIVATE        = (byte) 0x1E;  // Proprietary
    private static final byte RMI_FUNCTION_REMOTE_WIPE       = (byte) 0x1F;
    private static final byte RMI_FORMAT_DISPLAY             = (byte) 0x01;

    private Records records;

    // Persistent data objects.
    // Stores persistent data objects.
    private byte[] persistentByteBuffer;
    // Stores personalized persistent data objects.
    private byte[] personalizedPersistentByteBuffer;

    // Stores File Control Information.
    private byte[] selectResponse;
    // Stores Card Layout Description Part 1.
    private byte[] cardLayoutDescriptionPart1;
    // Stores Card Layout Description Part 2.
    private byte[] cardLayoutDescriptionPart2;
    // Stores Card Layout Description Part 3.
    private byte[] cardLayoutDescriptionPart3;

    // Transient data objects.
    // Stores transient data objects.
    private byte[] transientByteBuffer;

    // Key objects.
    private DESKey mkAC;   // Card Master Key
    private DESKey mkIDN;  // ICC Dynamic Number Master Key
    private RSAPrivateCrtKey iccPrivKey;

    private transient SecureChannel secureChannel;

    // NOTE: Use 'gpState' instead of using GPSystem.getCardContentState() and GPSystem.setCardContentState().
    // Supported States:
    // - GPSystem.APPLICATION_SELECTABLE (7)
    // - GPSystem.SECURITY_DOMAIN_PERSONALIZED (15)
    // - GPSystem.CARD_LOCKED (127)
    // - GPSystem.CARD_TERMINATED (-1)
    private byte gpState;

    // For MPP Remote-SE Lite.
    private CardProfile cardProfile;
    private PaymentTokenPayloadSingleUseKey ptpSuk;
    private byte[] cardProfileHash;
    private byte[] mobilePin;
    private AESKey mobileKey;
    private MessageDigest sha256;
    private RandomData random;

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
    private STPayP(byte[] array, short offset, byte length) {
        /*** Start allocate memory when applet is instantiated. ***/
        this.records = new Records(Constants.MAX_SFI_RECORDS);

        this.persistentByteBuffer = new byte[Constants.SIZE_PBB];
        this.personalizedPersistentByteBuffer = new byte[Constants.SIZE_PPBB];

        this.transientByteBuffer = JCSystem.makeTransientByteArray(Constants.SIZE_TBB, JCSystem.CLEAR_ON_DESELECT);

        // NOTE: 'keyEncryption' parameter not used.
        this.mkAC = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        this.mkIDN = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        /*** End allocate memory when applet is instantiated. ***/

        /*** Allocate memory when personalized. ***/
        this.selectResponse = null;
        this.cardLayoutDescriptionPart1 = null;
        this.cardLayoutDescriptionPart2 = null;
        this.cardLayoutDescriptionPart3 = null;

        this.gpState = GPSystem.APPLICATION_SELECTABLE;

        /*** Start initialize variables specific to MPP Remote-SE Lite. ***/
        this.cardProfile = new CardProfile();

        // Build Card Profile.
        // NOTE: This is a kludge to retrieve AID. This would not work with real Java Card.
        byte aidLength = JCSystem.getAID().getBytes(this.transientByteBuffer, (short) 0);
        this.cardProfile.setAid(this.transientByteBuffer, (short) 0, aidLength);

        this.cardProfileHash = new byte[32];

        // Initialize and seed random.
        this.random = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        byte[] seed = DataUtil.stringToCompressedByteArray(String.valueOf(Calendar.getInstance().getTimeInMillis()));
        this.random.setSeed(seed, (short) 0, (short) seed.length);

        // Generate Mobile Key using random.
        byte[] mobileKeyData = new byte[32];
        this.random.generateData(mobileKeyData, (short) 0, (short) mobileKeyData.length);
        this.mobileKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, 
                                                      KeyBuilder.LENGTH_AES_256, 
                                                      false);
        this.mobileKey.setKey(mobileKeyData, (short) 0);

        this.sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        /*** End initialize variables specific to MPP Remote-SE Lite. ***/

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
        new STPayP(array, offset, length);
    }

    /**
     * Processes incoming APDU command.
     * <p>
     * Supported commands (<b>CLA INS</b>):
     * <ul>
     * <li><b>00 A4</b>: Select
     * <li><b>80 50</b>: Initialize Update [from Issuer]
     * <li><b>80 80</b>: Get Card Profile [from card agent]
     * <li><b>80 82</b>: Get PTP_SUK [from card agent]
     * <li><b>80 84</b>: Get Mobile Key [from card agent]
     * <li><b>80 90</b>: Send Agent Notification [from Issuer]
     * <li><b>80 A0</b>: Initialize Mobile PIN [from card agent]
     * <li><b>80 E2</b>: Store Data [from Issuer]
     * <li><b>80 F0</b>: Set Status [from Issuer]
     * <li><b>84 82</b>: External Authenticate [from Issuer]
     * <li><b>84 E2</b>: Store Data, Secured [from Issuer]
     * <li><b>84 F0</b>: Set Status, Secured [from Issuer]
     * </ul>
     * 
     * @param apdu
     *            the incoming <code>APDU</code> object
     * @see javacard.framework.Applet.process
     */
    public void process(APDU apdu) {
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

            // Create/reset global transient data.
            // NOTE: Buffer contents should already be reset. This forces reset.
            Util.arrayFillNonAtomic(this.transientByteBuffer, (short) 0, Constants.SIZE_TBB, (byte) 0x00);

            // Construct Select response data.
            // Check if applet is not personalized.
            if ((this.gpState != GPSystem.SECURITY_DOMAIN_PERSONALIZED) || 
                (protocolMedia != APDU.PROTOCOL_MEDIA_NFC)) {
                // Set FCI Template tag.
                apduBuffer[(byte) 0] = Constants.TAG_FCI_TEMPLATE;
                // Set DF Name tag.
                apduBuffer[(byte) 2] = Constants.TAG_DF_NAME;
                // Set DF Name length and DF Name value.
                apduBuffer[(byte) 3] = JCSystem.getAID().getBytes(apduBuffer, (short) 4);
                // Set FCI Template length.
                apduBuffer[(byte) 1] = (byte) (apduBuffer[(byte) 3] + (byte) 2);

                // Send Select response.
                apdu.setOutgoingAndSend((short) 0, (short) (apduBuffer[(byte) 1] + (byte) 2));

                // Go to Personalized state.
                this.transientByteBuffer[Constants.TBB_OFFSET_STATE] = Constants.APP_STATE_PERSO;

                return;
            }

            // Retrieve personalized FCI response and send Select response.
            apdu.setOutgoingAndSend((short) 0, Util.arrayCopyNonAtomic(this.selectResponse, (short) 0, 
                                                                       apduBuffer, (short) 0, (short) this.selectResponse.length));

            // Go to Selected state.
            this.transientByteBuffer[Constants.TBB_OFFSET_STATE] = Constants.APP_STATE_SELECTED;

            // IF 'Application Blocked' in Previous Transaction History is set
            if ((this.personalizedPersistentByteBuffer[Constants.PPBB_OFFSET_PREVIOUS_TRANSACTION_HISTORY] & Constants.PREVIOUS_TRANSACTION_HISTORY_BIT_APP_BLOCKED) != 
                (byte) 0x00) {
                // Return FCI with SW=0x6283.
                ISOException.throwIt(Constants.SW_WARNING_SELECTED_FILE_INVALIDATED);
            }

            return;
        }

        // Retrieve current application state.
        byte appState = this.transientByteBuffer[Constants.TBB_OFFSET_STATE];

        // Handle commands starting from ones that have higher timing dependence.
        // Get CLA (ignore logical channel bits) and INS.
        short capduClaIns = (short) (Util.getShort(apduBuffer, ISO7816.OFFSET_CLA) & (short) 0xFCFF);
        switch (capduClaIns) {
        case Constants.CLA_INS_GET_CARD_PROFILE: {
            // Process Get Card Profile command (from card agent).

            if (this.gpState != GPSystem.SECURITY_DOMAIN_PERSONALIZED) {
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }

            if (protocolMedia != APDU.PROTOCOL_MEDIA_SOFT) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            try {
                getCardProfile(apdu);

                if (this.mobilePin == null) {
                    // Send message to card agent to trigger Mobile PIN initialization.
                    try {
                        sendRemoteNotificationMessage(RMI_FUNCTION_MOBILE_PIN_CHANGE, true);
                    }
                    catch (Exception e) {
                        System.out.println("sendToAgentSecured exception: " + e.getMessage());
                    }
                }
            }
            catch (ISOException isoe) {
                ISOException.throwIt(isoe.getReason());
            }

            return;
        }
        case Constants.CLA_INS_GET_PTP_SUK: {
            // Process Get PTP_SUK command (from card agent).

            if (this.gpState != GPSystem.SECURITY_DOMAIN_PERSONALIZED) {
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }

            if (protocolMedia != APDU.PROTOCOL_MEDIA_SOFT) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            getPtpSuk(apdu);

            return;
        }
        case Constants.CLA_INS_GET_MOBILE_KEY: {
            // Process Get Mobile Key command (from card agent).

            if (protocolMedia != APDU.PROTOCOL_MEDIA_SOFT) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            getMobileKey(apdu);

            return;
        }
        case Constants.CLA_INS_INITIALIZE_MOBILE_PIN: {
            // Process Initialize Mobile PIN command (from card agent).

            if (this.gpState != GPSystem.SECURITY_DOMAIN_PERSONALIZED) {
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }

            if (protocolMedia != APDU.PROTOCOL_MEDIA_SOFT) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            // Check if P1=0x00 and P2=0x00.
            if (Util.getShort(apduBuffer, ISO7816.OFFSET_P1) != (short) 0x0000) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }

            short cdataLength = apdu.setIncomingAndReceive();
            // Check if Lc=[number of data bytes read].
            // Check if Lc>=4 and Lc<=8.
            if ((cdataLength != (short) (apduBuffer[ISO7816.OFFSET_LC] & (short) 0x00FF)) || 
                (cdataLength < (short) 4) || 
                (cdataLength > (short) 8)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            this.mobilePin = new byte[cdataLength];
            Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, this.mobilePin, (short) 0, cdataLength);

            // Send message to card agent to trigger Get PTP_SUK command.
            try {
                sendRemoteNotificationMessage(RMI_FUNCTION_PTP_SUK, false);
            }
            catch (Exception e) {
            }

            return;
        }
        case Constants.CLA_INS_SEND_AGENT_NOTIFICATON: {
            // Process Send Agent Notification command (from Issuer).

            // Check if P1=0x00 and P2=0x00.
            if (Util.getShort(apduBuffer, ISO7816.OFFSET_P1) != (short) 0x0000) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }

            // Send message to card agent to trigger Get PTP_SUK command.
            try {
                sendRemoteNotificationMessage(RMI_FUNCTION_PTP_SUK, true);
            }
            catch (Exception e) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            return;
        }
        case Constants.CLA_INS_INITIALIZE_UPDATE: {
            // Process Initialize for Update command.

            // NOTE: Allowed post-personalization.
            /*
            // Check if applet is already personalized.
            if (appState != Constants.APP_STATE_PERSO) {
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
        case Constants.CLA_INS_EXTERNAL_AUTHENTICATE: {
            // Process External Authenticate command.

            // NOTE: Allowed post-personalization.
            /*
            // Check if applet is already personalized.
            if (appState != Constants.APP_STATE_PERSO) {
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
        case Constants.CLA_INS_SET_STATUS:
        case Constants.CLA_INS_SET_STATUS_SECURED: {
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
                cdataLength = this.secureChannel.unwrap(apduBuffer, (short) 0, (short) (ISO7816.OFFSET_CDATA + cdataLength));
                cdataLength -= ISO7816.OFFSET_CDATA;
            }

            // Validate AID.
            apduBuffer[(byte) 64] = JCSystem.getAID().getBytes(apduBuffer, (short) 65);
            if ((cdataLength != apduBuffer[(byte) 64]) || 
                (Util.arrayCompare(apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer, (short) 65, cdataLength) != (byte) 0)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            byte rmiFunction = (byte) 0;
            if (stateControl == GPSystem.SECURITY_DOMAIN_PERSONALIZED) {
                if (this.gpState != GPSystem.SECURITY_DOMAIN_PERSONALIZED) {
                    // Send message to card agent to indicate card activated.
                    rmiFunction = RMI_FUNCTION_PTP_CP;
                }
            }
            else if (stateControl == GPSystem.CARD_LOCKED) {
                if (this.gpState != GPSystem.CARD_LOCKED) {
                    // Send message to card agent to indicate card deactivated.
                    rmiFunction = RMI_FUNCTION_DEACTIVATE;
                }
            }
            else {
                try {
                    setStateTerminated();
                }
                catch (IOException e) {
                }

                // Send message to card agent to indicate card terminated.
                rmiFunction = RMI_FUNCTION_REMOTE_WIPE;
            }

            // Update GP state.
            this.gpState = stateControl;

            if (rmiFunction != (byte) 0) {
                // Send message to card agent.
                try {
                    sendRemoteNotificationMessage(rmiFunction, true);
                }
                catch (Exception e) {
                    ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
                }
            }

            // Note: There is no response data.

            return;
        }
        case Constants.CLA_INS_STORE_DATA:
        case Constants.CLA_INS_STORE_DATA_SECURED: {
            // Process Store Data command.

            // NOTE: Allow post-issuance personalization update.
            /*
            // Check if applet is already personalized.
            if (appState != Constants.APP_STATE_PERSO) {
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }
            */

            // Check if External Authenticate has been performed successfully.
            if ((byte) (this.secureChannel.getSecurityLevel() & SecureChannel.AUTHENTICATED) != SecureChannel.AUTHENTICATED) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            byte p1 = apduBuffer[ISO7816.OFFSET_P1];

            storeData(apdu);

            // Check if last Store Data command.
            if ((p1 & (byte) 0x80) == (byte) 0x80) {
                // Check perso state.
                if (appState == Constants.APP_STATE_PERSO) {
                    // Build Card Profile.
                    this.cardProfile.setSfi1Record1(this.records.getRecord((byte) 1, (short) 1));
                    this.cardProfile.setSfi2Record1(this.records.getRecord((byte) 2, (short) 1));
                    this.cardProfile.setSfi2Record2(this.records.getRecord((byte) 2, (short) 2));
                    this.cardProfile.setSfi2Record3(this.records.getRecord((byte) 2, (short) 3));

                    // Check if all mandatory data objects are personalized.
                    // Return DGI or tag of missing data elements separated by 'FF'.
                    short offset = (short) 0;
                    if (this.cardProfile.getTagA5Data() == null) {
                        offset = Util.setShort(apduBuffer, offset, (short) 0x9102);
                    }
                    if ((this.cardProfile.getAip() == null) || 
                        (this.cardProfile.getAfl() == null)) {
                        if (offset > (short) 0) {
                            apduBuffer[offset++] = (byte) 0xFF;
                        }
                        offset = Util.setShort(apduBuffer, offset, (short) 0xB005);
                    }
                    if ((this.cardProfile.getSfi1Record1() == null) && 
                        (this.cardProfile.getSfi2Record1() == null)) {
                        if (offset > (short) 0) {
                            apduBuffer[offset++] = (byte) 0xFF;
                        }
                        offset = Util.setShort(apduBuffer, offset, (short) 0x0101);
                        apduBuffer[offset++] = (byte) 0xFF;
                        offset = Util.setShort(apduBuffer, offset, (short) 0x0201);
                    }
                    if (!this.mkAC.isInitialized()) {
                        if (offset > (short) 0) {
                            apduBuffer[offset++] = (byte) 0xFF;
                        }
                        offset = Util.setShort(apduBuffer, offset, (short) 0x8000);
                    }
                    if (!this.mkIDN.isInitialized()) {
                        if (offset > (short) 0) {
                            apduBuffer[offset++] = (byte) 0xFF;
                        }
                        offset = Util.setShort(apduBuffer, offset, (short) 0xA006);
                    }
                    if (offset > (short) 0) {
                        apdu.setOutgoingAndSend((short) 0, offset);

                        // NOTE: Throwing exception returns empty response data.
                        //ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                        return;
                    }

                    String recordData;
                    int track2DataOffset = 0;
                    if (this.cardProfile.getSfi2Record1() != null) {
                        recordData = DataUtil.byteArrayToHexString(this.cardProfile.getSfi2Record1());
                        track2DataOffset = recordData.indexOf("571") + 4;
                    }
                    else {
                        recordData = DataUtil.byteArrayToHexString(this.cardProfile.getSfi1Record1());
                        track2DataOffset = recordData.indexOf("9F6B1") + 6;
                    }

                    int separatorOffset = recordData.indexOf("D", track2DataOffset);
                    String pan = recordData.substring(track2DataOffset, separatorOffset);

                    String tempExpDate = "20" + recordData.substring(separatorOffset + 1, separatorOffset + 5);

                    Calendar expDate = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
                    expDate.set(Integer.parseInt(tempExpDate.substring(0, 4)), 
                                // Next month 0th day which reverts to this month last day.
                                Integer.parseInt(tempExpDate.substring(4)), 0, 
                                // Last hour, minute, second of the day.
                                23, 59, 59);

                    try {
                        setStatePersonalized(pan, expDate, "", "");
                    }
                    catch (Exception e) {
                    }

                    // Update application life cycle state to personalized.
                    gpState = GPSystem.SECURITY_DOMAIN_PERSONALIZED;
                }
                else if (gpState == GPSystem.SECURITY_DOMAIN_PERSONALIZED) {
                    // Send message to card agent to trigger card update.
                    try {
                        sendRemoteNotificationMessage(RMI_FUNCTION_PTP_CP, true);
                    }
                    catch (Exception e) {
                        ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
                    }
                }
            }

            return;
        }
        default:
        }

        // Get CLA byte, ignore logical channels bits.
        byte claByte = (byte) (capduClaIns >> (byte) 8);
        if ((claByte == ISO7816.CLA_ISO7816) || 
            (claByte == Constants.CLA_PROPRIETARY) || 
            (claByte == Constants.CLA_PROPRIETARY_SECURE)) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    // NOTE: This method contains non-standard Java Card methods.
    private void sendRemoteNotificationMessage(byte remoteManagementFunction, 
                                               boolean displayNotification) throws Exception {
        byte[] msgData = new byte[32];

        // Set Remote Management Information.
        msgData[0] = (byte) (RMI_VERSION | remoteManagementFunction);
        // Set Session ID Version and Format.
        msgData[1] = RMI_VERSION;
        if (displayNotification) {
            msgData[1] |= RMI_FORMAT_DISPLAY;
        }
        // Set Session ID random value.
        this.random.generateData(msgData, (short) 2, (short) 13);

        // Encrypt notification message using the Mobile Key.
        short encMsgDataLength = DataEncryption.encryptRemoteMessage(this.mobileKey, msgData, (short) 0, (short) 15);

        // Send notification message to card agent.
        if (encMsgDataLength > (short) 0) {
            sendToAgent(DataUtil.byteArrayToHexString(msgData, 0, encMsgDataLength));
        }
    }

    // NOTE: This method contains non-standard Java Card methods.
    private void getCardProfile(APDU apdu) throws ISOException {
        byte[] apduBuffer = apdu.getBuffer();

        // Check if P1=0x00 and P2=0x00.
        if (Util.getShort(apduBuffer, ISO7816.OFFSET_P1) != (short) 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short dataLength = apdu.setOutgoing();
        // Check if Le=0x00 or 0x0000.
        if ((dataLength != (short) 256) && 
            (dataLength != (short) 32767)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        /*
        // DEBUG
        if (this.cardProfile != null) {
            System.out.println("cardProfile Aid: " + DataUtil.byteArrayToHexString(this.cardProfile.getAid()));
            System.out.println("cardProfile AidPpse: " + DataUtil.byteArrayToHexString(this.cardProfile.getAidPpse()));
            System.out.println("cardProfile PpseResponse: " + DataUtil.byteArrayToHexString(this.cardProfile.getPpseResponse()));
            System.out.println("cardProfile TagA5Data: " + DataUtil.byteArrayToHexString(this.cardProfile.getTagA5Data()));
            System.out.println("cardProfile Aip: " + DataUtil.byteArrayToHexString(this.cardProfile.getAip()));
            System.out.println("cardProfile Afl: " + DataUtil.byteArrayToHexString(this.cardProfile.getAfl()));
            System.out.println("cardProfile Sfi1Record1: " + DataUtil.byteArrayToHexString(this.cardProfile.getSfi1Record1()));
            System.out.println("cardProfile Sfi2Record1: " + DataUtil.byteArrayToHexString(this.cardProfile.getSfi2Record1()));
            System.out.println("cardProfile Sfi2Record2: " + DataUtil.byteArrayToHexString(this.cardProfile.getSfi2Record2()));
            System.out.println("cardProfile Sfi2Record3: " + DataUtil.byteArrayToHexString(this.cardProfile.getSfi2Record3()));
            System.out.println("cardProfile Cdol1RelatedDataLength: " + String.format("%02X", this.cardProfile.getCdol1RelatedDataLength()));
            System.out.println("cardProfile MchipCvmIssuerOptions: " + String.format("%02X", this.cardProfile.getMchipCvmIssuerOptions()));
            System.out.println("cardProfile CrmCountryCode: " + String.format("%04X", this.cardProfile.getCrmCountryCode()));
            System.out.println("cardProfile CiacDeclineOnlineCapable: " + DataUtil.byteArrayToHexString(this.cardProfile.getCiacDeclineOnlineCapable()));
            System.out.println("cardProfile KeyDerivationIndex: " + String.format("%02X", this.cardProfile.getKeyDerivationIndex()));
            System.out.println("cardProfile ApplicationControl: " + DataUtil.byteArrayToHexString(this.cardProfile.getApplicationControl()));
            System.out.println("cardProfile AdditionalCheckTable: " + DataUtil.byteArrayToHexString(this.cardProfile.getAdditionalCheckTable()));
            System.out.println("cardProfile DualTapResetTimeout: " + String.format("%04X", this.cardProfile.getDualTapResetTimeout()));
            //System.out.println("cardProfile SecurityWord: " + DataUtil.byteArrayToHexString(this.cardProfile.getSecurityWord()));
            System.out.println("cardProfile CvmResetTimeout: " + String.format("%04X", this.cardProfile.getCvmResetTimeout()));
            System.out.println("cardProfile MagstripeCvmIssuerOptions: " + String.format("%02X", this.cardProfile.getMagstripeCvmIssuerOptions()));
            System.out.println("cardProfile CiacDeclinePpms: " + DataUtil.byteArrayToHexString(this.cardProfile.getCiacDeclinePpms()));
            //System.out.println("cardProfile PinIvCvc3Track1: " + DataUtil.byteArrayToHexString(this.cardProfile.getPinIvCvc3Track1()));
            //System.out.println("cardProfile PinIvCvc3Track2: " + DataUtil.byteArrayToHexString(this.cardProfile.getPinIvCvc3Track2()));
            System.out.println("cardProfile IccPubKeyModulusLength: " + String.format("%02X", this.cardProfile.getIccPubKeyModulusLength()));
            //System.out.println("cardProfile IccPrivKeyPrimeP: " + DataUtil.byteArrayToHexString(this.cardProfile.getIccPrivKeyPrimeP()));
            //System.out.println("cardProfile IccPrivKeyPrimeQ: " + DataUtil.byteArrayToHexString(this.cardProfile.getIccPrivKeyPrimeQ()));
            //System.out.println("cardProfile IccPrivKeyPrimeExponentP: " + DataUtil.byteArrayToHexString(this.cardProfile.getIccPrivKeyPrimeExponentP()));
            //System.out.println("cardProfile IccPrivKeyPrimeExponentQ: " + DataUtil.byteArrayToHexString(this.cardProfile.getIccPrivKeyPrimeExponentQ()));
            //System.out.println("cardProfile IccPrivKeyCrtCoefficient: " + DataUtil.byteArrayToHexString(this.cardProfile.getIccPrivKeyCrtCoefficient()));
            System.out.println("cardProfile MaxNumberPtpSuk: " + this.cardProfile.getMaxNumberPtpSuk());
            System.out.println("cardProfile MinThresholdNumberPtpSuk: " + this.cardProfile.getMinThresholdNumberPtpSuk());
            System.out.println();
        }
        */

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = null;
        byte[] cardProfileBytes = null;
        try {
            out = new ObjectOutputStream(bos);
            out.writeObject(this.cardProfile);
            cardProfileBytes = bos.toByteArray();

            // Calculate Card Profile hash.
            this.sha256.reset();
            this.sha256.doFinal(cardProfileBytes, (short) 0, (short) cardProfileBytes.length, 
                                this.cardProfileHash, (short) 0);
        }
        catch (IOException e) {
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

        if (cardProfileBytes != null) {
            short responseOffset = (short) 0;
            // Check if Mobile PIN is initialized.
            if (this.mobilePin == null) {
                // NOTE: Kludge to prepend 'FF FF FF FF' to response to indicate Mobile PIN not initialized.
                responseOffset = Util.arrayFillNonAtomic(apduBuffer, (short) 0, (short) 4, (byte) 0xFF);
                dataLength -= (byte) 4;
            }

            try {
                if (dataLength < (short) cardProfileBytes.length) {
                    dataLength = Util.arrayCopyNonAtomic(cardProfileBytes, (short) 0, apduBuffer, responseOffset, dataLength);
                }
                else {
                    dataLength = Util.arrayCopyNonAtomic(cardProfileBytes, (short) 0, apduBuffer, responseOffset, (short) cardProfileBytes.length);
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

    // NOTE: This method contains non-standard Java Card methods.
    private void getPtpSuk(APDU apdu) throws ISOException {
        byte[] apduBuffer = apdu.getBuffer();

        // Check if P1=0x00/0x01 and P2=0x00.
        // NOTE: P1=0x01 indicates Mobile PIN not used.
        byte p1 = apduBuffer[ISO7816.OFFSET_P1];
        if (((p1 != (byte) 0x00) && (p1 != (byte) 0x01)) || 
            (apduBuffer[ISO7816.OFFSET_P2] != (byte) 0x00)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short dataLength = apdu.setOutgoing();
        // Check if Le=0x00 or 0x0000.
        if ((dataLength != (short) 256) && 
            (dataLength != (short) 32767)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (p1 != (byte) 0x01) {
            // Check if Mobile PIN is initialized.
            if (this.mobilePin == null) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }

        // Increment ATC.
        short atc = Util.getShort(this.persistentByteBuffer, Constants.PBB_OFFSET_APPLICATION_TRANSACTION_COUNTER);
        atc++;
        Util.setShort(this.persistentByteBuffer, Constants.PBB_OFFSET_APPLICATION_TRANSACTION_COUNTER, atc);

        short keyLength = 0;
        final short keyOffset = (short) 128;
        if (p1 != (byte) 0x01) {
            keyLength = DataGeneration.generateSuk(this.mkAC, atc, this.mobilePin, apduBuffer, keyOffset);
        }
        else {
            keyLength = DataGeneration.generateSuk(this.mkAC, atc, null, apduBuffer, keyOffset);
        }
        if (keyLength != DataGeneration.BYTE_LENGTH_DES3_2KEY) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        final short idnOffset = (short) (keyOffset + DataGeneration.BYTE_LENGTH_DES3_2KEY);
        short idnLength = DataGeneration.generateIdn(this.mkIDN, atc, apduBuffer, idnOffset);
        if (idnLength != (short) 8) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Generate Payment Token Payload (Single Use Key) for MPP Remote-SE Lite.
        this.ptpSuk = new PaymentTokenPayloadSingleUseKey(this.cardProfileHash, (short) 0, 
                                                          atc, 
                                                          apduBuffer, keyOffset, 
                                                          apduBuffer, idnOffset);

        /*
        // DEBUG
        if (this.ptpSuk != null) {
            //System.out.println("PTP_SUK PtpCpTruncatedHash: " + DataUtil.byteArrayToHexString(this.ptpSuk.getPtpCpTruncatedHash()));
            System.out.println("PTP_SUK Atc: " + String.format("%04X", this.ptpSuk.getAtc()));
            //System.out.println("PTP_SUK Suk: " + DataUtil.byteArrayToHexString(this.ptpSuk.getSuk()));
            //System.out.println("PTP_SUK Idn: " + DataUtil.byteArrayToHexString(this.ptpSuk.getIdn()));
            System.out.println();
        }
        */

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = null;
        byte[] ptpSukBytes = null;
        try {
            out = new ObjectOutputStream(bos);
            out.writeObject(this.ptpSuk);
            ptpSukBytes = bos.toByteArray();
        }
        catch (IOException e) {
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

        if (ptpSukBytes != null) {
            try {
                if (dataLength < (short) ptpSukBytes.length) {
                    Util.arrayCopyNonAtomic(ptpSukBytes, (short) 0, apduBuffer, (short) 0, dataLength);
                }
                else {
                    dataLength = Util.arrayCopyNonAtomic(ptpSukBytes, (short) 0, apduBuffer, (short) 0, (short) ptpSukBytes.length);
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

    // NOTE: This method contains non-standard Java Card methods.
    private void getMobileKey(APDU apdu) throws ISOException {
        byte[] apduBuffer = apdu.getBuffer();

        // Check if P1=0x00 and P2=0x00.
        if (Util.getShort(apduBuffer, ISO7816.OFFSET_P1) != (short) 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short dataLength = apdu.setOutgoing();
        // Check if Le=0x00.
        if (dataLength != (short) 256) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Check if Mobile Key is initialized.
        if ((this.mobileKey == null) || !this.mobileKey.isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        dataLength = this.mobileKey.getKey(apduBuffer, (short) 0);
        apdu.setOutgoingLength(dataLength);
        apdu.sendBytes((short) 0, dataLength);
    }

    /**
     * Handle Store Data command.
     * 
     * @param apdu
     *            the incoming <code>APDU</code> object
     */
    private void storeData(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte p1 = apduBuffer[ISO7816.OFFSET_P1];

        // Validate sequence counter in P2.
        if (apduBuffer[ISO7816.OFFSET_P2] != this.transientByteBuffer[Constants.TBB_OFFSET_SEQUENCE_NUMBER]) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        this.transientByteBuffer[Constants.TBB_OFFSET_SEQUENCE_NUMBER]++;

        short cdataLength = apdu.setIncomingAndReceive();

        // Check GP security level.
        if ((this.secureChannel.getSecurityLevel() & (byte) 0x03) >= SecureChannel.C_MAC) {
            // Use GP API to unwrap data.
            cdataLength = this.secureChannel.unwrap(apduBuffer, (short) 0, (short) (ISO7816.OFFSET_CDATA + cdataLength));
            cdataLength -= ISO7816.OFFSET_CDATA;
        }

        byte dgiHighByte, dgiLowByte;
        short dgi, dgiLength;
        short dgiOffset = ISO7816.OFFSET_CDATA;
        cdataLength += ISO7816.OFFSET_CDATA;

        while (dgiOffset < cdataLength) {
            // Get DGI.
            dgiHighByte = apduBuffer[dgiOffset++];
            dgiLowByte = apduBuffer[dgiOffset++];
            // Get DGI length, which is defined to be 1 byte.
            dgiLength = (short) (apduBuffer[dgiOffset++] & (short) 0x00FF);

            // 'dgiDataLength' is the actual length of DGI data.
            short dgiDataLength = (short) 0;
            boolean dgiDecrypted = false;
            if ((p1 & (byte) 0x60) == (byte) 0x60) {
                dgiDataLength = this.secureChannel.decryptData(apduBuffer, dgiOffset, dgiLength);
                dgiDecrypted = true;
            }
            else {
                dgiDataLength = dgiLength;
            }

            // Check if DGI is SFI record.
            if ((dgiHighByte >= (byte) 0x01) && (dgiHighByte <= (byte) 0x1E) && 
                (dgiLowByte != (byte) 0x00)) {
                // Save SFI record.
                this.records.addSFIRecord(dgiHighByte, dgiLowByte, apduBuffer, dgiOffset, dgiDataLength);

                dgiOffset += dgiLength;
                continue;
            }

            /* Supported DGIs:
             * 0x8000
             * 0x8201, 0x8202, 0x8203, 0x8204, 0x8205
             * 0x9102
             * 0xA002
             * 0xA003
             * 0xA004
             * 0xB005
             * 0xA006
             * 0xA007
             * 0xA009
             * 0xA026
             * 0xA027
             * 0xA028
             * 0xB003
             * 0xB007
             */
            dgi = Util.makeShort(dgiHighByte, dgiLowByte);
            // Check if DGI is supported.
            switch (dgi) {
            case Constants.DGI_DES_KEYS: {
                // SKUdek encryption required.
                if (!dgiDecrypted) {
                    if ((p1 & (byte) 0x60) != (byte) 0x00) {
                        dgiDataLength = this.secureChannel.decryptData(apduBuffer, dgiOffset, dgiLength);            
                    }
                    else {
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    }
                }

                if (dgiDataLength != (short) 16) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }

                this.mkAC.setKey(apduBuffer, dgiOffset);

                break;
            }
            case Constants.DGI_ICC_PRIV_KEY_CRT_CONSTANT_PQ: 
            case Constants.DGI_ICC_PRIV_KEY_CRT_CONSTANT_DQ1: 
            case Constants.DGI_ICC_PRIV_KEY_CRT_CONSTANT_DP1: 
            case Constants.DGI_ICC_PRIV_KEY_CRT_CONSTANT_Q: 
            case Constants.DGI_ICC_PRIV_KEY_CRT_CONSTANT_P: {
                // SKUdek encryption required.
                if (!dgiDecrypted) {
                    if ((p1 & (byte) 0x60) != (byte) 0x00) {
                        dgiDataLength = this.secureChannel.decryptData(apduBuffer, dgiOffset, dgiLength);            
                    }
                    else {
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    }
                }

                short keySize = (short) (dgiDataLength * (byte) 16);
                if (this.iccPrivKey == null) {
                    // NOTE: 'keyEncryption' parameter not used.
                    this.iccPrivKey = (RSAPrivateCrtKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, keySize, false);
                }
                else if (this.iccPrivKey.getSize() != keySize) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }

                if (dgi == Constants.DGI_ICC_PRIV_KEY_CRT_CONSTANT_PQ) {
                    // Build Card Profile.
                    this.cardProfile.setIccPrivKeyCrtCoefficient(apduBuffer, dgiOffset, dgiDataLength);

                    this.iccPrivKey.setPQ(apduBuffer, dgiOffset, dgiDataLength);
                }
                else if (dgi == Constants.DGI_ICC_PRIV_KEY_CRT_CONSTANT_DQ1) {
                    // Build Card Profile.
                    this.cardProfile.setIccPrivKeyPrimeExponentQ(apduBuffer, dgiOffset, dgiDataLength);

                    this.iccPrivKey.setDQ1(apduBuffer, dgiOffset, dgiDataLength);
                }
                else if (dgi == Constants.DGI_ICC_PRIV_KEY_CRT_CONSTANT_DP1) {
                    // Build Card Profile.
                    this.cardProfile.setIccPrivKeyPrimeExponentP(apduBuffer, dgiOffset, dgiDataLength);

                    this.iccPrivKey.setDP1(apduBuffer, dgiOffset, dgiDataLength);
                }
                else if (dgi == Constants.DGI_ICC_PRIV_KEY_CRT_CONSTANT_Q) {
                    // Build Card Profile.
                    this.cardProfile.setIccPrivKeyPrimeQ(apduBuffer, dgiOffset, dgiDataLength);

                    this.iccPrivKey.setQ(apduBuffer, dgiOffset, dgiDataLength);
                }
                else {
                    // Build Card Profile.
                    this.cardProfile.setIccPrivKeyPrimeP(apduBuffer, dgiOffset, dgiDataLength);

                    this.iccPrivKey.setP(apduBuffer, dgiOffset, dgiDataLength);
                }

                break;
            }
            case Constants.DGI_SELECT_RESPONSE_DATA: {
                // Build Card Profile.
                this.cardProfile.setTagA5Data(apduBuffer, dgiOffset, dgiDataLength);

                byte aidLength = JCSystem.getAID().getBytes(this.transientByteBuffer, Constants.TBB_OFFSET_PREV_PARTIAL_DGI_DATA);

                // Determine entire Select response length.
                short selectResponseLength = (short) (dgiDataLength + aidLength + (byte) 4);
                if (selectResponseLength > (short) 129) {
                    selectResponseLength++;
                }

                // Allocate memory for entire Select response.
                this.selectResponse = new byte[selectResponseLength];
                short selectResponseOffset = (short) 0;
                this.selectResponse[selectResponseOffset++] = Constants.TAG_FCI_TEMPLATE;
                if (selectResponseLength > (short) 129) {
                    this.selectResponse[selectResponseOffset++] = (byte) 0x81;
                    this.selectResponse[selectResponseOffset++] = (byte) (selectResponseLength - (byte) 3);
                }
                else {
                    this.selectResponse[selectResponseOffset++] = (byte) (selectResponseLength - (byte) 2);
                }
                // Save DF Name in select response.
                this.selectResponse[selectResponseOffset++] = Constants.TAG_DF_NAME;
                this.selectResponse[selectResponseOffset++] = aidLength;
                selectResponseOffset = Util.arrayCopyNonAtomic(this.transientByteBuffer, Constants.TBB_OFFSET_PREV_PARTIAL_DGI_DATA, 
                                                               this.selectResponse, selectResponseOffset, aidLength);
                // Save FCI Proprietary Template in select response.
                Util.arrayCopyNonAtomic(apduBuffer, dgiOffset, this.selectResponse, 
                                        selectResponseOffset, dgiDataLength);

                break;
            }
            case Constants.DGI_DATA: {
                // Build Card Profile.
                this.cardProfile.setData(apduBuffer, dgiOffset);

                break;
            }
            case Constants.DGI_MAGSTRIPE_CVM_DATA: {
                // Build Card Profile.
                this.cardProfile.setMagstripeData(apduBuffer, dgiOffset);

                // For MPP Remote-SE Lite.
                // Magstripe CVM Issuer Options 1 1
                // Card Issuer Action Code - Decline On PPMS 2 2
                Util.arrayCopyNonAtomic(apduBuffer, dgiOffset, this.personalizedPersistentByteBuffer, 
                                        Constants.PPBB_OFFSET_MAGSTRIPE_CVM_ISSUER_OPTIONS, dgiDataLength);

                break;
            }
            case Constants.DGI_PUBLIC_KEY_MODULUS_LENGTH: {
                // Build Card Profile.
                this.cardProfile.setIccPubKeyModulusLength((short) (apduBuffer[dgiOffset] & (short) 0x00FF));

                // For MPP Remote-SE Lite.
                // Length Of ICC Public Key Modulus 1 1
                Util.arrayCopyNonAtomic(apduBuffer, dgiOffset, this.personalizedPersistentByteBuffer, 
                                        Constants.PPBB_OFFSET_ICC_PUB_KEY_MODULUS_LENGTH, dgiDataLength);

                break;
            }
            case Constants.DGI_GPO_RESPONSE_DATA_PAYMENT: {
                // Note that for 'A005' and 'B005', only values of the AIP and the AFL 
                // are personalized, without TLV-coding.

                short aflLength = (short) (dgiDataLength - (byte) 2);

                // Build Card Profile.
                this.cardProfile.setAip(apduBuffer, dgiOffset);
                this.cardProfile.setAfl(apduBuffer, (short) (dgiOffset + (byte) 2), aflLength);

                break;
            }
            case Constants.DGI_ICC_DYNAMIC_NUMBER_MASTER_KEY: {
                // SKUdek encryption required.
                if (!dgiDecrypted) {
                    if ((p1 & (byte) 0x60) != (byte) 0x00) {
                        dgiDataLength = this.secureChannel.decryptData(apduBuffer, dgiOffset, dgiLength);            
                    }
                    else {
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    }
                }

                if (dgiDataLength != (short) 16) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }

                this.mkIDN.setKey(apduBuffer, dgiOffset);

                break;
            }
            case Constants.DGI_LIMITS: {
                /*
                Previous Transaction History 1 1
                ATC Counter Limit 2 2
                AC Session Key Counter Limit 2 3
                SMI Session Key Counter Limit 2 4
                Bad Cryptogram Counter Limit 2 5
                */
                Util.arrayCopyNonAtomic(apduBuffer, dgiOffset, this.personalizedPersistentByteBuffer, 
                        Constants.PPBB_OFFSET_PREVIOUS_TRANSACTION_HISTORY, (short) (1 + 2 + 2 + 2 + 2));

                break;
            }
            case Constants.DGI_APPLICATION_LIFE_CYCLE_DATA: {
                Util.arrayCopyNonAtomic(apduBuffer, dgiOffset, this.personalizedPersistentByteBuffer, 
                                        Constants.PPBB_OFFSET_APPLICATION_LIFE_CYCLE_DATA, dgiDataLength);

                break;
            }
            case Constants.DGI_CARD_LAYOUT_DESCRIPTION_PART_1: {
                if (dgiDataLength > (short) 255) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }

                // Allocate memory.
                this.cardLayoutDescriptionPart1 = new byte[dgiDataLength];
                // Save data.
                Util.arrayCopyNonAtomic(apduBuffer, dgiOffset, this.cardLayoutDescriptionPart1, (short) 0, dgiDataLength);

                break;
            }
            case Constants.DGI_CARD_LAYOUT_DESCRIPTION_PART_2: {
                if (dgiDataLength > (short) 255) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }

                // Allocate memory.
                this.cardLayoutDescriptionPart2 = new byte[dgiDataLength];
                // Save data.
                Util.arrayCopyNonAtomic(apduBuffer, dgiOffset, this.cardLayoutDescriptionPart2, (short) 0, dgiDataLength);

                break;
            }
            case Constants.DGI_CARD_LAYOUT_DESCRIPTION_PART_3: {
                if (dgiDataLength > (short) 255) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }

                // Allocate memory.
                this.cardLayoutDescriptionPart3 = new byte[dgiDataLength];
                // Save data.
                Util.arrayCopyNonAtomic(apduBuffer, dgiOffset, this.cardLayoutDescriptionPart3, (short) 0, dgiDataLength);

                break;
            }
            case Constants.DGI_IVCVC3: {
                Util.arrayCopyNonAtomic(apduBuffer, dgiOffset, this.personalizedPersistentByteBuffer, 
                        Constants.PPBB_OFFSET_IVCVC3_TRACK1, (short) (2 + 2));

                break;
            }
            case Constants.DGI_PIN_IVCVC3: {
                // Build Card Profile.
                this.cardProfile.setPinIvCvc3(apduBuffer, dgiOffset);

                Util.arrayCopyNonAtomic(apduBuffer, dgiOffset, this.personalizedPersistentByteBuffer, 
                        Constants.PPBB_OFFSET_PIN_IVCVC3_TRACK1, (short) (2 + 2));

                break;
            }
            case (short) 0x4000: {
                dgiDataLength += dgiOffset;
                while (dgiOffset < dgiDataLength) {
                    short tag = Util.getShort(apduBuffer, dgiOffset);
                    dgiOffset += (byte) 2;

                    if (apduBuffer[dgiOffset++] != (byte) 1) {
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    }

                    // Build Card Profile.
                    byte value = apduBuffer[dgiOffset++];
                    if (tag == (short) 0xDF30) {
                        // Maximum Number of Live PTP_SUK
                        this.cardProfile.setMaxNumberPtpSuk(value);
                    }
                    else if (tag == (short) 0xDF31) {
                        // Minimum Threshold Number of Live PTP_SUK
                        this.cardProfile.setMinThresholdNumberPtpSuk(value);
                    }
                    else {
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    }
                }

                break;
            }
            default:
                break;
            }

            dgiOffset += dgiLength;
        }
    }

}
