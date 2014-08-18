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

/**
 * Define constants.
 * 
 * @author SimplyTapp, Inc.
 * @version 1.0
 */
public interface PayPConstants {

    static final byte FALSE = (byte) 0x00;
    static final byte TRUE  = (byte) 0x01;

    static final int LENGTH_AMOUNT                      = 6;
    static final int LENGTH_AC                          = 8;
    static final int LENGTH_CVM_RESULTS                 = 3;
    static final int LENGTH_CVR                         = 6;
    static final int LENGTH_ISSUER_APPLICATION_DATA     = 18;
    static final int LENGTH_ICC_DYNAMIC_NUMBER_TERMINAL = 8;
    static final int LENGTH_TRANSACTION_DATE            = 3;
    static final int LENGTH_TVR                         = 5;
    static final int LENGTH_UNPREDICTABLE_NUMBER        = 4;

    // 1-byte tags.
    static final byte TAG_FCI_TEMPLATE                          = (byte) 0x6F;
    static final byte TAG_READ_RECORD_RESPONSE_MESSAGE_TEMPLATE = (byte) 0x70;
    static final byte TAG_RESPONSE_MESSAGE_TEMPLATE             = (byte) 0x77;
    static final byte TAG_AIP                                   = (byte) 0x82;
    static final byte TAG_DF_NAME                               = (byte) 0x84;
    static final byte TAG_AFL                                   = (byte) 0x94;

    // 2-byte 0x9FXX tags.
    static final short TAG_ISSUER_APPLICATION_DATA         = (short) 0x9F10;
    static final short TAG_APPLICATION_CRYPTOGRAM          = (short) 0x9F26;
    static final short TAG_CRYPTOGRAM_INFO_DATA            = (short) 0x9F27;
    static final short TAG_APPLICATION_TRANSACTION_COUNTER = (short) 0x9F36;
    static final short TAG_SIGNED_DYNAMIC_APPLICATION_DATA = (short) 0x9F4B;
    static final short TAG_CVC3_TRACK1                     = (short) 0x9F60;
    static final short TAG_CVC3_TRACK2                     = (short) 0x9F61;

    // 2-byte 0xDFXX tags.
    static final short TAG_POS_CARDHOLDER_INTERACTION_INFO = (short) 0xDF4B;

    // Generate AC command P1 definitions.
    static final byte GENERATE_AC_P1_CRYPTOGRAM_TYPE         = (byte) 0xC0;
    static final byte GENERATE_AC_P1_CRYPTOGRAM_TYPE_AAC     = (byte) 0x00;
    static final byte GENERATE_AC_P1_CRYPTOGRAM_TYPE_TC      = (byte) 0x40;
    static final byte GENERATE_AC_P1_CRYPTOGRAM_TYPE_ARQC    = (byte) 0x80;
    static final byte GENERATE_AC_P1_CRYPTOGRAM_TYPE_RFU     = (byte) 0xC0;
    static final byte FIRST_GENERATE_AC_P1_BIT_CDA_REQUESTED = (byte) 0x10;

    // Application Control bit definitions.
    static final byte APPLICATION_CONTROL_BYTE_2_BIT_ACTIVATE_ADDITIONAL_CHECK_TABLE = (byte) 0x04;
    static final byte APPLICATION_CONTROL_BYTE_3_BIT_CCC_SUPPORTED                   = (byte) 0x20;

    // Cryptogram Information Data bit definitions.
    static final byte CID_ARQC = (byte) 0x80;
    static final byte CID_TC   = (byte) 0x40;
    static final byte CID_AAC  = (byte) 0x00;

    // MChip/Magstripe CVM Issuer Options bit definitions.
    static final byte CVM_ISSUER_BIT_ACK_ALWAYS_REQUIRED_IF_CURRENCY_PROVIDED     = (byte) 0x80;
    static final byte CVM_ISSUER_BIT_ACK_ALWAYS_REQUIRED_IF_CURRENCY_NOT_PROVIDED = (byte) 0x40;
    static final byte CVM_ISSUER_BIT_PIN_ALWAYS_REQUIRED_IF_CURRENCY_PROVIDED     = (byte) 0x10;
    static final byte CVM_ISSUER_BIT_PIN_ALWAYS_REQUIRED_IF_CURRENCY_NOT_PROVIDED = (byte) 0x08;
    static final byte CVM_ISSUER_BIT_PIN_PRE_ENTRY_ALLOWED                        = (byte) 0x04;
    static final byte CVM_ISSUER_BIT_ACK_AUTOMATICALLY_RESET_BY_APPLICATION       = (byte) 0x02;
    static final byte CVM_ISSUER_BIT_PIN_AUTOMATICALLY_RESET_BY_APPLICATION       = (byte) 0x01;

    // Card Verification Results bit definitions.
    static final byte CVR_BYTE_1_BITS_AC_RETURNED_IN_SECOND_GENERATE_AC            = (byte) 0xC0;
    static final byte CVR_BYTE_1_AC_NOT_REQUESTED_IN_SECOND_GENERATE_AC            = (byte) 0x80;
    static final byte CVR_BYTE_1_TC_RETURNED_IN_SECOND_GENERATE_AC                 = (byte) 0x40;
    static final byte CVR_BYTE_1_AAC_RETURNED_IN_SECOND_GENERATE_AC                = (byte) 0x00;
    static final byte CVR_BYTE_1_BITS_AC_RETURNED_IN_FIRST_GENERATE_AC             = (byte) 0x30;
    static final byte CVR_BYTE_1_ARQC_RETURNED_IN_FIRST_GENERATE_AC                = (byte) 0x20;
    static final byte CVR_BYTE_1_TC_RETURNED_IN_FIRST_GENERATE_AC                  = (byte) 0x10;
    static final byte CVR_BYTE_1_AAC_RETURNED_IN_FIRST_GENERATE_AC                 = (byte) 0x00;
    static final byte CVR_BYTE_1_BIT_OFFLINE_PIN_VERIFICATION_SUCCESSFUL           = (byte) 0x01;
    static final byte CVR_BYTE_2_BIT_CDA_GENERATION_RETURNED_IN_FIRST_GENERATE_AC  = (byte) 0x40;
    static final byte CVR_BYTE_4_BIT_INTERNATIONAL_TRANSACTION                     = (byte) 0x04;
    static final byte CVR_BYTE_4_BIT_DOMESTIC_TRANSACTION                          = (byte) 0x02;
    static final byte CVR_BYTE_4_BIT_TERMINAL_ERRONEOUSLY_CONSIDERS_OFFLINE_PIN_OK = (byte) 0x01;
    static final byte CVR_BYTE_6_BIT_CVM_REQUIRED_IS_NOT_SATISFIED                 = (byte) 0x08;
    static final byte CVR_BYTE_6_BIT_MATCH_FOUND_IN_ADDITIONAL_CHECK_TABLE         = (byte) 0x02;
    static final byte CVR_BYTE_6_BIT_NO_MATCH_FOUND_IN_ADDITIONAL_CHECK_TABLE      = (byte) 0x01;

    // Mobile Support Indicator bit definitions.
    static final byte MOBILE_SUPPORT_INDICATOR_BIT_OFFLINE_PIN_REQUIRED_READER = (byte) 0x02;
    static final byte MOBILE_SUPPORT_INDICATOR_BIT_READER_SUPPORTS_MOBILE      = (byte) 0x01;

    // POS Cardholder Interaction Information bit definitions.
    static final byte POS_CARDHOLDER_INTERACTION_INFO_BYTE_2_BIT_OFFLINE_PIN_VERIFICATION_SUCCESSFUL = (byte) 0x10;
    static final byte POS_CARDHOLDER_INTERACTION_INFO_BYTE_2_BIT_CONTEXT_CONFLICTING                 = (byte) 0x08;
    static final byte POS_CARDHOLDER_INTERACTION_INFO_BYTE_2_BIT_OFFLINE_CHANGE_PIN_REQUIRED         = (byte) 0x04;
    static final byte POS_CARDHOLDER_INTERACTION_INFO_BYTE_2_BIT_ACK_REQUIRED                        = (byte) 0x02;
    static final byte POS_CARDHOLDER_INTERACTION_INFO_BYTE_2_BIT_PIN_REQUIRED                        = (byte) 0x01;

    // PPMS Card Verification Results bit definitions.
    static final byte PPMS_CVR_BYTE_1_BIT_OFFLINE_PIN_VERIFICATION_SUCCESSFUL           = (byte) 0x01;
    static final byte PPMS_CVR_BYTE_2_BIT_OFFLINE_CHANGE_PIN_REQUIRED                   = (byte) 0x80;
    static final byte PPMS_CVR_BYTE_2_BIT_CVM_REQUIRED_IS_NOT_SATISFIED                 = (byte) 0x40;
    static final byte PPMS_CVR_BYTE_2_BIT_PTL_EXCEEDED                                  = (byte) 0x08;
    static final byte PPMS_CVR_BYTE_2_BIT_INTERNATIONAL_TRANSACTION                     = (byte) 0x04;
    static final byte PPMS_CVR_BYTE_2_BIT_DOMESTIC_TRANSACTION                          = (byte) 0x02;
    static final byte PPMS_CVR_BYTE_2_BIT_TERMINAL_ERRONEOUSLY_CONSIDERS_OFFLINE_PIN_OK = (byte) 0x01;

    // PPMS Cryptogram Information Data definitions.
    static final byte PPMS_CID_TRANSACTION_SENT_ONLINE = (byte) 0x01;
    static final byte PPMS_CID_TRANSACTION_DECLINED    = (byte) 0x00;

    // Transaction Context - Context Defined definitions.
    static final byte TRANSACTION_CONTEXT_CONTEXT_DEFINED_NONE                       = (byte) 0x00;
    static final byte TRANSACTION_CONTEXT_CONTEXT_DEFINED_FIRST_TAP                  = (byte) 0x01;
    static final byte TRANSACTION_CONTEXT_CONTEXT_DEFINED_INVALIDATED_CONTEXT        = (byte) 0x02;
    static final byte TRANSACTION_CONTEXT_CONTEXT_DEFINED_PREVIOUS_CONTEXT           = (byte) 0x03;
    static final byte TRANSACTION_CONTEXT_CONTEXT_DEFINED_MAGSTRIPE_FIRST_TAP        = (byte) 0x11;
    static final byte TRANSACTION_CONTEXT_CONTEXT_DEFINED_MAGSTRIPE_PREVIOUS_CONTEXT = (byte) 0x13;

    // Transaction Context - ACK Status definitions.
    static final byte TRANSACTION_CONTEXT_ACK_STATUS_NO_ACK     = (byte) 0x00;
    static final byte TRANSACTION_CONTEXT_ACK_STATUS_ACK_GIVEN  = (byte) 0x01;
    static final byte TRANSACTION_CONTEXT_ACK_STATUS_ACK_LOCKED = (byte) 0x02;

    // Transaction Context - PIN Status definitions.
    static final byte TRANSACTION_CONTEXT_PIN_STATUS_NO_PIN      = (byte) 0x00;
    static final byte TRANSACTION_CONTEXT_PIN_STATUS_PIN_ENTERED = (byte) 0x01;
    static final byte TRANSACTION_CONTEXT_PIN_STATUS_PIN_LOCKED  = (byte) 0x02;

}
