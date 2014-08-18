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

/**
 * Define constants.
 * 
 * @author SimplyTapp, Inc.
 * @version 1.0
 */
interface PayWConstants {

    static final int LENGTH_AC = 8;

    // 1-byte tags.
    static final byte TAG_FCI_TEMPLATE                       = (byte) 0x6F;
    static final byte TAG_RESPONSE_MESSAGE_TEMPLATE_FORMAT_2 = (byte) 0x77;
    static final byte TAG_RESPONSE_MESSAGE_TEMPLATE_FORMAT_1 = (byte) 0x80;
    static final byte TAG_DF_NAME                            = (byte) 0x84;

    // 2-byte 0x9FXX tags.
    static final short TAG_APPLICATION_CRYPTOGRAM          = (short) 0x9F26;
    static final short TAG_APPLICATION_TRANSACTION_COUNTER = (short) 0x9F36;

}
