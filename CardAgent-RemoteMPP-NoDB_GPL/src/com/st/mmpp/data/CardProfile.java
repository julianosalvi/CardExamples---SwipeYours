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
package com.st.mmpp.data;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.Arrays;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * Implementation of Card Profile defined in Remote-SE Mobile PayP - 
 * MPP Remote-SE Lite June 2013 - v1.1.
 * 
 * Use CardProfile object to share data between Card Applet and Card Agent.
 * 
 * @author SimplyTapp, Inc.
 * @version 1.0
 */
final public class CardProfile implements Serializable {

    private static final long serialVersionUID = 1L;

    // PPSE AID
    private static final byte[] AID_PPSE = {
        (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E, 
        (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E, 
        (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31
    };

    // PPSE Response
    private static final byte[] PPSE_RESPONSE = {
        (byte) 0x6F, (byte) 0x27, 
          (byte) 0x84, (byte) 0x0E, 
            (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E, 
            (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E, 
            (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31, 
          (byte) 0xA5, (byte) 0x15, 
            (byte) 0xBF, (byte) 0x0C, (byte) 0x12, 
              (byte) 0x61, (byte) 0x10, 
                (byte) 0x4F, (byte) 0x07
    };
    private static final short PPSE_RESPONSE_TAG_6F_LENGTH_OFFSET   = (short) 1;
    private static final short PPSE_RESPONSE_TAG_A5_LENGTH_OFFSET   = (short) 19;
    private static final short PPSE_RESPONSE_TAG_BF0C_LENGTH_OFFSET = (short) 22;
    private static final short PPSE_RESPONSE_TAG_61_LENGTH_OFFSET   = (short) 24;
    private static final short PPSE_RESPONSE_TAG_4F_LENGTH_OFFSET   = (short) 26;
    private static final byte[] PPSE_RESPONSE_TRAILER = {
        (byte) 0x87, (byte) 0x01, 
          (byte) 0x01, 
        (byte) 0x9F, (byte) 0x2A, (byte) 0x01, 
          (byte) 0x02
    };

    private byte[] aid;
    private byte[] aidPpse;

    private byte[] ppseResponse;

    private byte[] tagA5Data;

    private byte[] aip;
    private byte[] afl;

    private byte[] sfi1Record1;
    private byte[] sfi2Record1;
    private byte[] sfi2Record2;
    private byte[] sfi2Record3;

    // Additional Check Table [0 : 17]
    private static final short DATA_OFFSET_ADDITIONAL_CHECK_TABLE      = (short) 0;
    private static final short LENGTH_ADDITIONAL_CHECK_TABLE           = (short) 18;
    // CDOL1 Related Data Length [18]
    private static final short DATA_OFFSET_CDOL1_RELATED_DATA_LENGTH   = (short) (DATA_OFFSET_ADDITIONAL_CHECK_TABLE + 
                                                                                  LENGTH_ADDITIONAL_CHECK_TABLE);
    // CRM Country Code [19 : 20]
    private static final short DATA_OFFSET_CRM_COUNTRY_CODE            = (short) (DATA_OFFSET_CDOL1_RELATED_DATA_LENGTH + 1);
    // Application Control [21 : 24]
    private static final short DATA_OFFSET_APPLICATION_CONTROL         = (short) (DATA_OFFSET_CRM_COUNTRY_CODE + 2);
    private static final short LENGTH_APPLICATION_CONTROL              = (short) 4;
    // Security Word [25 : 40]
    private static final short DATA_OFFSET_SECURITY_WORD               = (short) (DATA_OFFSET_APPLICATION_CONTROL + 
                                                                                  LENGTH_APPLICATION_CONTROL);
    private static final short LENGTH_SECURITY_WORD                    = (short) 16;
    // Card Issuer Action Code - Decline On Online Capable [41 : 43]
    private static final short DATA_OFFSET_CIAC_DECLINE_ONLINE_CAPABLE = (short) (DATA_OFFSET_SECURITY_WORD + 
                                                                                  LENGTH_SECURITY_WORD);
    private static final short LENGTH_CIAC_DECLINE_ONLINE_CAPABLE      = (short) 3;
    // Key Derivation Index [44]
    private static final short DATA_OFFSET_KEY_DERIVATION_INDEX        = (short) (DATA_OFFSET_CIAC_DECLINE_ONLINE_CAPABLE + 
                                                                                  LENGTH_CIAC_DECLINE_ONLINE_CAPABLE);
    // M/Chip CVM Issuer Options [45]
    private static final short DATA_OFFSET_MCHIP_CVM_ISSUER_OPTIONS    = (short) (DATA_OFFSET_KEY_DERIVATION_INDEX + 1);
    // CVM Reset Timeout [46 : 47]
    private static final short DATA_OFFSET_CVM_RESET_TIMEOUT           = (short) (DATA_OFFSET_MCHIP_CVM_ISSUER_OPTIONS + 1);
    // Dual Tap Reset Timeout [48 : 49]
    private static final short DATA_OFFSET_DUAL_TAP_RESET_TIMEOUT      = (short) (DATA_OFFSET_CVM_RESET_TIMEOUT + 2);
    private static final short LENGTH_DATA                             = (short) (DATA_OFFSET_DUAL_TAP_RESET_TIMEOUT + 2);
    private byte[] data;

    // Magstripe CVM Issuer Options [0]
    private static final short MAGSTRIPE_DATA_OFFSET_MAGSTRIPE_CVM_ISSUER_OPTIONS = (short) 0;
    // Card Issuer Action Code - Decline On PPMS [1 : 2]
    private static final short MAGSTRIPE_DATA_OFFSET_CIAC_DECLINE_PPMS            = (short) (MAGSTRIPE_DATA_OFFSET_MAGSTRIPE_CVM_ISSUER_OPTIONS + 1);
    private static final short LENGTH_CIAC_DECLINE_PPMS                           = (short) 2;
    private static final short LENGTH_MAGSTRIPE_DATA                              = (short) (MAGSTRIPE_DATA_OFFSET_CIAC_DECLINE_PPMS + 
                                                                                             LENGTH_CIAC_DECLINE_PPMS);
    private byte[] magstripeData;

    private byte[] pinIvCvc3Track1;
    private byte[] pinIvCvc3Track2;

    private short iccPubKeyModulusLength;

    private byte[] iccPrivKeyPrimeP;
    private byte[] iccPrivKeyPrimeQ;
    private byte[] iccPrivKeyPrimeExponentP;
    private byte[] iccPrivKeyPrimeExponentQ;
    private byte[] iccPrivKeyCrtCoefficient;

    // Supports 1 to 255.
    private int maxNumberPtpSuk = 1;

    // Supports 1 to 255.
    private int minThresholdNumberPtpSuk = 1;

    public CardProfile() {
        this.aidPpse = AID_PPSE;
    }

    public byte[] getAid() {
        return this.aid;
    }

    public void setAid(byte[] aidBuffer, short aidOffset, byte aidLength) {
        try {
            this.aid = Arrays.copyOfRange(aidBuffer, 
                                          aidOffset, 
                                          aidOffset + aidLength);
        }
        catch (Exception e) {
            this.aid = null;
            return;
        }

        try {
            this.ppseResponse = new byte[PPSE_RESPONSE.length + 
                                         this.aid.length + 
                                         PPSE_RESPONSE_TRAILER.length];
            ByteBuffer ppseResponseByteBuffer = ByteBuffer.wrap(this.ppseResponse);
            ppseResponseByteBuffer.put(PPSE_RESPONSE);
            ppseResponseByteBuffer.put(this.aid);
            ppseResponseByteBuffer.put(PPSE_RESPONSE_TRAILER);
            if (aidLength != (byte) 7) {
                byte aidLengthDiff = (byte) (aidLength - 7);
                this.ppseResponse[PPSE_RESPONSE_TAG_6F_LENGTH_OFFSET] += aidLengthDiff;
                this.ppseResponse[PPSE_RESPONSE_TAG_A5_LENGTH_OFFSET] += aidLengthDiff;
                this.ppseResponse[PPSE_RESPONSE_TAG_BF0C_LENGTH_OFFSET] += aidLengthDiff;
                this.ppseResponse[PPSE_RESPONSE_TAG_61_LENGTH_OFFSET] += aidLengthDiff;
                this.ppseResponse[PPSE_RESPONSE_TAG_4F_LENGTH_OFFSET] += aidLengthDiff;
            }
        }
        catch (Exception e) {
            this.ppseResponse = null;
        }
    }

    public byte[] getAidPpse() {
        return this.aidPpse;
    }

    public byte[] getPpseResponse() {
        return this.ppseResponse;
    }

    public byte[] getTagA5Data() {
        return this.tagA5Data;
    }

    public void setTagA5Data(byte[] tagA5Buffer, short tagA5Offset, short tagA5Length) {
        try {
            this.tagA5Data = Arrays.copyOfRange(tagA5Buffer, 
                                                tagA5Offset, 
                                                tagA5Offset + tagA5Length);
        }
        catch (Exception e) {
            this.tagA5Data = null;
        }
    }

    public byte[] getAip() {
        return this.aip;
    }

    public void setAip(byte[] aipBuffer, short aipOffset) {
        try {
            this.aip = Arrays.copyOfRange(aipBuffer, 
                                          aipOffset, 
                                          aipOffset + 2);
        }
        catch (Exception e) {
            this.aip = null;
        }
    }

    public byte[] getAfl() {
        return this.afl;
    }

    public void setAfl(byte[] aflBuffer, short aflOffset, short aflLength) {
        try {
            this.afl = Arrays.copyOfRange(aflBuffer, 
                                          aflOffset, 
                                          aflOffset + aflLength);
        }
        catch (Exception e) {
            this.afl = null;
        }
    }

    public byte[] getSfi1Record1() {
        return this.sfi1Record1;
    }

    public void setSfi1Record1(byte[] sfi1Record1) {
        this.sfi1Record1 = sfi1Record1;
    }

    public byte[] getSfi2Record1() {
        return this.sfi2Record1;
    }

    public void setSfi2Record1(byte[] sfi2Record1) {
        this.sfi2Record1 = sfi2Record1;
    }

    public byte[] getSfi2Record2() {
        return this.sfi2Record2;
    }

    public void setSfi2Record2(byte[] sfi2Record2) {
        this.sfi2Record2 = sfi2Record2;
    }

    public byte[] getSfi2Record3() {
        return this.sfi2Record3;
    }

    public void setSfi2Record3(byte[] sfi2Record3) {
        this.sfi2Record3 = sfi2Record3;
    }

    public void setData(byte[] dataBuffer, short dataOffset) {
        try {
            this.data = Arrays.copyOfRange(dataBuffer, 
                                           dataOffset, 
                                           dataOffset + LENGTH_DATA);
        }
        catch (Exception e) {
            this.data = null;
        }
    }

    public byte getCdol1RelatedDataLength() {
        if (this.data == null) {
            return (byte) 0x00;
        }

        return this.data[DATA_OFFSET_CDOL1_RELATED_DATA_LENGTH];
    }

    public byte getMchipCvmIssuerOptions() {
        if (this.data == null) {
            return (byte) 0x00;
        }

        return this.data[DATA_OFFSET_MCHIP_CVM_ISSUER_OPTIONS];
    }

    public short getCrmCountryCode() {
        if (this.data == null) {
            return (short) 0x0000;
        }

        return ByteBuffer.wrap(this.data).getShort(DATA_OFFSET_CRM_COUNTRY_CODE);
    }

    public byte[] getCiacDeclineOnlineCapable() {
        if (this.data == null) {
            return null;
        }

        return Arrays.copyOfRange(this.data, 
                                  DATA_OFFSET_CIAC_DECLINE_ONLINE_CAPABLE, 
                                  DATA_OFFSET_CIAC_DECLINE_ONLINE_CAPABLE + LENGTH_CIAC_DECLINE_ONLINE_CAPABLE);
    }

    public byte getKeyDerivationIndex() {
        if (this.data == null) {
            return (byte) 0x00;
        }

        return this.data[DATA_OFFSET_KEY_DERIVATION_INDEX];
    }

    public byte[] getApplicationControl() {
        if (this.data == null) {
            return null;
        }

        return Arrays.copyOfRange(this.data, 
                                  DATA_OFFSET_APPLICATION_CONTROL, 
                                  DATA_OFFSET_APPLICATION_CONTROL + LENGTH_APPLICATION_CONTROL);
    }

    public byte[] getAdditionalCheckTable() {
        if (this.data == null) {
            return null;
        }

        return Arrays.copyOfRange(this.data, 
                                  DATA_OFFSET_ADDITIONAL_CHECK_TABLE, 
                                  DATA_OFFSET_ADDITIONAL_CHECK_TABLE + LENGTH_ADDITIONAL_CHECK_TABLE);
    }

    public short getDualTapResetTimeout() {
        if (this.data == null) {
            return (short) 0x0000;
        }

        return ByteBuffer.wrap(this.data).getShort(DATA_OFFSET_DUAL_TAP_RESET_TIMEOUT);
    }

    public byte[] getSecurityWord() {
        if (this.data == null) {
            return null;
        }

        return Arrays.copyOfRange(this.data, 
                                  DATA_OFFSET_SECURITY_WORD, 
                                  DATA_OFFSET_SECURITY_WORD + LENGTH_SECURITY_WORD);
    }

    public short getCvmResetTimeout() {
        if (this.data == null) {
            return (short) 0x0000;
        }

        return ByteBuffer.wrap(this.data).getShort(DATA_OFFSET_CVM_RESET_TIMEOUT);
    }

    public void setMagstripeData(byte[] dataBuffer, short dataOffset) {
        try {
            this.magstripeData = Arrays.copyOfRange(dataBuffer, 
                                                    dataOffset, 
                                                    dataOffset + LENGTH_MAGSTRIPE_DATA);
        }
        catch (Exception e) {
            this.magstripeData = null;
        }
    }

    public byte getMagstripeCvmIssuerOptions() {
        if (this.magstripeData == null) {
            return (byte) 0x00;
        }

        return this.magstripeData[MAGSTRIPE_DATA_OFFSET_MAGSTRIPE_CVM_ISSUER_OPTIONS];
    }

    public byte[] getCiacDeclinePpms() {
        if (this.magstripeData == null) {
            return null;
        }

        return Arrays.copyOfRange(this.magstripeData, 
                                  MAGSTRIPE_DATA_OFFSET_CIAC_DECLINE_PPMS, 
                                  MAGSTRIPE_DATA_OFFSET_CIAC_DECLINE_PPMS + LENGTH_CIAC_DECLINE_PPMS);
    }

    public void setPinIvCvc3(byte[] dataBuffer, short dataOffset) {
        try {
            this.pinIvCvc3Track1 = Arrays.copyOfRange(dataBuffer, 
                                                      dataOffset, 
                                                      dataOffset + 2);

            this.pinIvCvc3Track2 = Arrays.copyOfRange(dataBuffer, 
                                                      dataOffset + 2, 
                                                      dataOffset + 4);
        }
        catch (Exception e) {
            this.pinIvCvc3Track1 = null;
            this.pinIvCvc3Track2 = null;
        }
    }

    public byte[] getPinIvCvc3Track1() {
        return this.pinIvCvc3Track1;
    }

    public byte[] getPinIvCvc3Track2() {
        return this.pinIvCvc3Track2;
    }

    public short getIccPubKeyModulusLength() {
        return this.iccPubKeyModulusLength;
    }

    public void setIccPubKeyModulusLength(short iccPubKeyModulusLength) {
        this.iccPubKeyModulusLength = iccPubKeyModulusLength;
    }

    public byte[] getIccPrivKeyPrimeP() {
        return this.iccPrivKeyPrimeP;
    }

    public void setIccPrivKeyPrimeP(byte[] crtComponentBuffer, 
                                    short crtComponentOffset, 
                                    short crtComponentLength) {
        try {
            this.iccPrivKeyPrimeP = Arrays.copyOfRange(crtComponentBuffer, 
                                                       crtComponentOffset, 
                                                       crtComponentOffset + crtComponentLength);
        }
        catch (Exception e) {
            this.iccPrivKeyPrimeP = null;
        }
    }

    public byte[] getIccPrivKeyPrimeQ() {
        return this.iccPrivKeyPrimeQ;
    }

    public void setIccPrivKeyPrimeQ(byte[] crtComponentBuffer, 
                                    short crtComponentOffset, 
                                    short crtComponentLength) {
        try {
            this.iccPrivKeyPrimeQ = Arrays.copyOfRange(crtComponentBuffer, 
                                                       crtComponentOffset, 
                                                       crtComponentOffset + crtComponentLength);
        }
        catch (Exception e) {
            this.iccPrivKeyPrimeQ = null;
        }
    }

    public byte[] getIccPrivKeyPrimeExponentP() {
        return this.iccPrivKeyPrimeExponentP;
    }

    public void setIccPrivKeyPrimeExponentP(byte[] crtComponentBuffer, 
                                            short crtComponentOffset, 
                                            short crtComponentLength) {
        try {
            this.iccPrivKeyPrimeExponentP = Arrays.copyOfRange(crtComponentBuffer, 
                                                               crtComponentOffset, 
                                                               crtComponentOffset + crtComponentLength);
        }
        catch (Exception e) {
            this.iccPrivKeyPrimeExponentP = null;
        }
    }

    public byte[] getIccPrivKeyPrimeExponentQ() {
        return this.iccPrivKeyPrimeExponentQ;
    }

    public void setIccPrivKeyPrimeExponentQ(byte[] crtComponentBuffer, 
                                            short crtComponentOffset, 
                                            short crtComponentLength) {
        try {
            this.iccPrivKeyPrimeExponentQ = Arrays.copyOfRange(crtComponentBuffer, 
                                                               crtComponentOffset, 
                                                               crtComponentOffset + crtComponentLength);
        }
        catch (Exception e) {
            this.iccPrivKeyPrimeExponentQ = null;
        }
    }

    public byte[] getIccPrivKeyCrtCoefficient() {
        return this.iccPrivKeyCrtCoefficient;
    }

    public void setIccPrivKeyCrtCoefficient(byte[] crtComponentBuffer, 
                                            short crtComponentOffset, 
                                            short crtComponentLength) {
        try {
            this.iccPrivKeyCrtCoefficient = Arrays.copyOfRange(crtComponentBuffer, 
                                                               crtComponentOffset, 
                                                               crtComponentOffset + crtComponentLength);
        }
        catch (Exception e) {
            this.iccPrivKeyCrtCoefficient = null;
        }
    }

    public int getMaxNumberPtpSuk() {
        return this.maxNumberPtpSuk;
    }

    public void setMaxNumberPtpSuk(byte maxNumberPtpSuk) {
        if (maxNumberPtpSuk == (byte) 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        this.maxNumberPtpSuk = (int) (maxNumberPtpSuk & 0xFF);
    }

    public int getMinThresholdNumberPtpSuk() {
        return this.minThresholdNumberPtpSuk;
    }

    public void setMinThresholdNumberPtpSuk(byte minThresholdNumberPtpSuk) {
        if (minThresholdNumberPtpSuk == (byte) 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        this.minThresholdNumberPtpSuk = (int) (minThresholdNumberPtpSuk & 0xFF);
    }

}
