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
package com.st.vcbp.data;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * Use AccountParamsStatic object to share data between Card Applet and Card Agent.
 * 
 * @author SimplyTapp, Inc.
 * @version 1.0
 */
final public class AccountParamsStatic implements Serializable {

    private static final long serialVersionUID = 1L;

    // PPSE AID
    private static final byte[] AID_PPSE = {
        (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E, 
        (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E, 
        (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31
    };

    // PPSE Response
    private static final byte[] PPSE_RESPONSE = {
        (byte) 0x6F, (byte) 0x23, 
          (byte) 0x84, (byte) 0x0E, 
            (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E, 
            (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E, 
            (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31, 
          (byte) 0xA5, (byte) 0x11, 
            (byte) 0xBF, (byte) 0x0C, (byte) 0x0E, 
              (byte) 0x61, (byte) 0x0C, 
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
    };

    private byte[] aid;
    private byte[] aidPpse;

    private byte[] ppseResp;

    private byte[] tagA5Data;

    public static final short GPO_RESPONSE_OFFSET_AIP        = (short) 2;
    public static final short GPO_RESPONSE_OFFSET_AFL_LENGTH = (short) 5;
    public static final short GPO_RESPONSE_OFFSET_AFL        = (short) 6;
    private byte[] gpoRespMsd;
    private byte[] gpoRespQvsdc;

    private HashMap<Short, byte[]> records = new HashMap<Short, byte[]>();

    public static final short IAD_VALUE_OFFSET           = (short) 3;
    public static final short IAD_OFFSET_CVR_BYTE_1      = (short) 6;
    public static final short IAD_OFFSET_DERIVATION_DATA = (short) 16;
    private byte[] iad;

    private byte[] psn;

    public static final short CTQ_OFFSET_BYTE_1 = (short) 3;
    public static final short CTQ_OFFSET_BYTE_2 = (short) 4;
    private byte[] ctq;

    public static final short TRACK2_OFFSET_DD = (short) 14;
    private byte[] track2Data;

    private byte[] cardholderName;

    private byte[] cvmList;

    private byte[] iccPrivKeyCrtCoefficient;
    private byte[] iccPrivKeyPrimeExponentQ;
    private byte[] iccPrivKeyPrimeExponentP;
    private byte[] iccPrivKeyPrimeQ;
    private byte[] iccPrivKeyPrimeP;

    private int iccKeyModulusLength;

    // Supports 1 to 255.
    private int maxNumAcctParamsDynamic = 1;

    // Supports 1 to 255.
    private int minThresholdNumAcctParamsDynamic = 1;

    // Time to Live Check Interval in Minutes
    // Supports:
    // - 0 = never check
    // - 1-255 = check every 1-255 minutes
    private int checkIntervalTimeToExp = 0;

    // Supports 0-255.
    private int maxTransactionVerificationLogs = 0;

    public AccountParamsStatic() {
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
            this.ppseResp = new byte[PPSE_RESPONSE.length + 
                                     this.aid.length + 
                                     PPSE_RESPONSE_TRAILER.length];
            ByteBuffer ppseResponseByteBuffer = ByteBuffer.wrap(this.ppseResp);
            ppseResponseByteBuffer.put(PPSE_RESPONSE);
            ppseResponseByteBuffer.put(this.aid);
            ppseResponseByteBuffer.put(PPSE_RESPONSE_TRAILER);
            if (aidLength != (byte) 7) {
                byte aidLengthDiff = (byte) (aidLength - 7);
                this.ppseResp[PPSE_RESPONSE_TAG_6F_LENGTH_OFFSET] += aidLengthDiff;
                this.ppseResp[PPSE_RESPONSE_TAG_A5_LENGTH_OFFSET] += aidLengthDiff;
                this.ppseResp[PPSE_RESPONSE_TAG_BF0C_LENGTH_OFFSET] += aidLengthDiff;
                this.ppseResp[PPSE_RESPONSE_TAG_61_LENGTH_OFFSET] += aidLengthDiff;
                this.ppseResp[PPSE_RESPONSE_TAG_4F_LENGTH_OFFSET] += aidLengthDiff;
            }
        }
        catch (Exception e) {
            this.ppseResp = null;
        }
    }

    public byte[] getAidPpse() {
        return this.aidPpse;
    }

    public byte[] getPpseResponse() {
        return this.ppseResp;
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

    public byte[] getGpoResponseMsd() {
        return this.gpoRespMsd;
    }

    public void setGpoResponseMsd(byte[] gpoResponseMsdBuffer, 
                                  short gpoResponseMsdOffset, 
                                  short gpoResponseMsdLength) {
        try {
            this.gpoRespMsd = Arrays.copyOfRange(gpoResponseMsdBuffer, 
                                                 gpoResponseMsdOffset, 
                                                 gpoResponseMsdOffset + gpoResponseMsdLength);
        }
        catch (Exception e) {
            this.gpoRespMsd = null;
        }
    }

    public byte[] getGpoResponseQvsdc() {
        return this.gpoRespQvsdc;
    }

    public void setGpoResponseQvsdc(byte[] gpoResponseQvsdcBuffer, 
                                    short gpoResponseQvsdcOffset, 
                                    short gpoResponseQvsdcLength) {
        try {
            this.gpoRespQvsdc = Arrays.copyOfRange(gpoResponseQvsdcBuffer, 
                                                   gpoResponseQvsdcOffset, 
                                                   gpoResponseQvsdcOffset + gpoResponseQvsdcLength);
        }
        catch (Exception e) {
            this.gpoRespQvsdc = null;
        }
    }

    public byte[] getSfiRecord(short sfiRecord) {
        return this.records.get(sfiRecord);
    }

    public void setSfiRecords(HashMap<Short, byte[]> records) {
        try {
            this.records = (HashMap<Short, byte[]>) records.clone();
            this.records.putAll(records);
        }
        catch (Exception e) {
            this.records = null;
        }
    }

    public byte[] getIssuerApplicationData() {
        return this.iad;
    }

    public void setIssuerApplicationData(byte[] iadBuffer, short iadOffset, short iadLength) {
        try {
            this.iad = Arrays.copyOfRange(iadBuffer, 
                                          iadOffset, 
                                          iadOffset + iadLength);
        }
        catch (Exception e) {
            this.iad = null;
        }
    }

    public byte[] getPanSequenceNumber() {
        return this.psn;
    }

    public void setPanSequenceNumber(byte[] psnBuffer, short psnOffset, short psnLength) {
        try {
            this.psn = Arrays.copyOfRange(psnBuffer, 
                                          psnOffset, 
                                          psnOffset + psnLength);
        }
        catch (Exception e) {
            this.psn = null;
        }
    }

    public byte[] getCardTransactionQualifier() {
        return this.ctq;
    }

    public void setCardTransactionQualifier(byte[] ctqBuffer, short ctqOffset, short ctqLength) {
        try {
            this.ctq = Arrays.copyOfRange(ctqBuffer, 
                                          ctqOffset, 
                                          ctqOffset + ctqLength);
        }
        catch (Exception e) {
            this.ctq = null;
        }
    }

    public byte[] getTrack2EquivalentData() {
        return this.track2Data;
    }

    public void setTrack2EquivalentData(byte[] track2Buffer, short track2Offset, short track2Length) {
        try {
            this.track2Data = Arrays.copyOfRange(track2Buffer, 
                                                 track2Offset, 
                                                 track2Offset + track2Length);
        }
        catch (Exception e) {
            this.track2Data = null;
        }
    }

    public byte[] getCardholderName() {
        return this.cardholderName;
    }

    public void setCardholderName(byte[] cardholderNameBuffer, short cardholderNameOffset, short cardholderNameLength) {
        try {
            this.cardholderName = Arrays.copyOfRange(cardholderNameBuffer, 
                                                     cardholderNameOffset, 
                                                     cardholderNameOffset + cardholderNameLength);
        }
        catch (Exception e) {
            this.cardholderName = null;
        }
    }

    public byte[] getCvmList() {
        return this.cvmList;
    }

    public void setCvmList(byte[] cvmListBuffer, short cvmListOffset, short cvmListLength) {
        try {
            this.cvmList = Arrays.copyOfRange(cvmListBuffer, 
                                              cvmListOffset, 
                                              cvmListOffset + cvmListLength);
        }
        catch (Exception e) {
            this.cvmList = null;
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

    public int getIccKeyModulusLength() {
        return this.iccKeyModulusLength;
    }

    public void setIccKeyModulusLength(int iccKeyModulusLength) {
        this.iccKeyModulusLength = iccKeyModulusLength;
    }

    public int getMaxNumberAccountParamsDynamic() {
        return this.maxNumAcctParamsDynamic;
    }

    public void setMaxNumberAccountParamsDynamic(byte maxNumberAccountParamsDynamic) {
        if (maxNumberAccountParamsDynamic == (byte) 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        this.maxNumAcctParamsDynamic = (int) (maxNumberAccountParamsDynamic & 0xFF);
    }

    public int getMinThresholdNumberAccountParamsDynamic() {
        return this.minThresholdNumAcctParamsDynamic;
    }

    public void setMinThresholdNumberAccountParamsDynamic(byte minThresholdNumberAccountParamsDynamic) {
        if (minThresholdNumberAccountParamsDynamic == (byte) 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        this.minThresholdNumAcctParamsDynamic = (int) (minThresholdNumberAccountParamsDynamic & 0xFF);
    }

    public int getCheckIntervalTimeToExpire() {
        return this.checkIntervalTimeToExp;
    }

    public void setCheckIntervalTimeToExpire(byte checkIntervalTimeToExpire) {
        this.checkIntervalTimeToExp = (int) (checkIntervalTimeToExpire & 0xFF);
    }

    public int getMaxTransactionVerificationLogs() {
        return this.maxTransactionVerificationLogs;
    }

    public void setMaxTransactionVerificationLogs(byte maxTransactionVerificationLogs) {
        this.maxTransactionVerificationLogs = (int) (maxTransactionVerificationLogs & 0xFF);
    }

}
