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
package com.st.vcbp.data;

import java.io.Serializable;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * Use AccountParamsDynamic object to share data between Card Applet and Card Agent.
 * 
 * @author SimplyTapp, Inc.
 * @version 1.0
 */
final public class AccountParamsDynamic implements Serializable {

    private static final long serialVersionUID = 1L;

    // Account Parameters Index (YHHHHCC)
    private String acctParamIndex;

    // Limited Use Key
    private byte[] luk;

    // Expiration Timestamp
    private long expTimestamp;

    // Received Timestamp
    private long recTimestamp;

    // Application Transaction Counter
    private short atc;

    // Alternate Limited Use Key for MSD
    private byte[] lukMsd;

    public AccountParamsDynamic(String accountParametersIndex, 
                                byte[] lukBuffer, short lukOffset, 
                                long expirationTimestamp, 
                                short atc) throws ISOException {
        this(accountParametersIndex, 
             lukBuffer, lukOffset, 
             expirationTimestamp, 
             atc, 
             null, (short) 0);
    }

    public AccountParamsDynamic(String accountParametersIndex, 
                                byte[] lukBuffer, short lukOffset, 
                                long expirationTimestamp, 
                                short atc, 
                                byte[] lukMsdBuffer, short lukMsdOffset) throws ISOException {
        try {
            this.luk = new byte[16];
            System.arraycopy(lukBuffer, lukOffset, this.luk, 0, this.luk.length);

            if (lukMsdBuffer != null) {
                this.lukMsd = new byte[16];
                System.arraycopy(lukMsdBuffer, lukMsdOffset, this.lukMsd, 0, this.lukMsd.length);
            }

            this.acctParamIndex = accountParametersIndex;
            this.expTimestamp = expirationTimestamp;
            this.atc = atc;
        }
        catch (Exception e) {
            this.luk = null;
            this.lukMsd = null;

            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    public String getAccountParamtersIndex() {
        return this.acctParamIndex;
    }

    public byte[] getLuk() {
        return this.luk;
    }

    public long getExpirationTimestamp() {
        return this.expTimestamp;
    }

    public long getReceivedTimestamp() {
        return this.recTimestamp;
    }

    public void setReceivedTimestamp(long receivedTimestamp) {
        this.recTimestamp = receivedTimestamp;
    }

    public short getAtc() {
        return this.atc;
    }

    public byte[] getLukMsd() {
        return this.lukMsd;
    }

}
