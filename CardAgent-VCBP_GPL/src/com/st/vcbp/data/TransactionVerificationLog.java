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
import java.util.Calendar;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * Use TransactionVerificationLog object to share data between Card Applet and Card Agent.
 * 
 * @author SimplyTapp, Inc.
 * @version 1.0
 */
final public class TransactionVerificationLog implements Serializable {

    private static final long serialVersionUID = 1L;

    public static final byte TRANSACTION_TYPE_MSD   = (byte) 1;
    public static final byte TRANSACTION_TYPE_QVSDC = (byte) 2;

    // UTC timestamp at the time of transaction.
    private long utcTimestamp;

    // Account Parameters Index (YHHHHCC) used in transaction.
    private String acctParamIndex;

    // Transaction type, MSD or qVSDC.
    private byte transactionType;

    // Unpredictable number for a qVSDC transaction.
    private String un;

    public TransactionVerificationLog(String accountParametersIndex, 
                                      byte transactionType, 
                                      String unpredictableNumber) throws ISOException {
        if ((accountParametersIndex != null) && 
            ((transactionType == TRANSACTION_TYPE_MSD) || 
             ((transactionType == TRANSACTION_TYPE_QVSDC) && (unpredictableNumber != null)))) {
            this.utcTimestamp = Calendar.getInstance().getTimeInMillis();

            this.acctParamIndex = accountParametersIndex;
            this.transactionType = transactionType;
            this.un = unpredictableNumber;
        }
        else {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    public long getUtcTimestamp() {
        return this.utcTimestamp;
    }

    public String getAccountParametersIndex() {
        return this.acctParamIndex;
    }

    public byte getTransactionType() {
        return this.transactionType;
    }

    public String getUnpredictableNumber() {
        return this.un;
    }

}
