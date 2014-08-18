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
package com.st.mmpp.data;

import java.io.Serializable;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * Implementation of Payment Token Payload (Single Use Key) (PTP_SUK) defined in
 * Remote-SE Mobile PayP.
 * 
 * Use PaymentTokenPayloadSingleUseKey object to share data between Card Applet
 * and Card Agent.
 * 
 * @author SimplyTapp, Inc.
 * @version 1.0
 */
final public class PaymentTokenPayloadSingleUseKey implements Serializable {

    private static final long serialVersionUID = 1L;

    // Payment Token Payload (Card Profile) Truncated Hash
    private byte[] ptpCpTruncatedHash;

    // Application Transaction Counter
    private short atc;

    // Single Use Key
    private byte[] suk;

    // ICC Dynamic Number
    private byte[] idn;

    public PaymentTokenPayloadSingleUseKey(byte[] hashBuffer, short hashOffset, 
                                           short atc, 
                                           byte[] sukBuffer, short sukOffset, 
                                           byte[] idnBuffer, short idnOffset) throws ISOException {
        this.ptpCpTruncatedHash = new byte[24];
        this.suk = new byte[16];
        this.idn = new byte[8];
        try {
            System.arraycopy(hashBuffer, hashOffset, this.ptpCpTruncatedHash, 0, this.ptpCpTruncatedHash.length);
            System.arraycopy(sukBuffer, sukOffset, this.suk, 0, this.suk.length);
            System.arraycopy(idnBuffer, idnOffset, this.idn, 0, this.idn.length);

            this.atc = atc;
        }
        catch (Exception e) {
            this.ptpCpTruncatedHash = null;
            this.suk = null;
            this.idn = null;

            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    public byte[] getPtpCpTruncatedHash() {
        return this.ptpCpTruncatedHash;
    }

    public short getAtc() {
        return this.atc;
    }

    public byte[] getSuk() {
        return this.suk;
    }

    public byte[] getIdn() {
        return this.idn;
    }

}
