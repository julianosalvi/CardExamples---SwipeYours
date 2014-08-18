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

/**
 * Define constants.
 * 
 * @author SimplyTapp, Inc.
 * @version 1.0
 */
interface Constants {

    // CLA for supported commands.
    static final byte CLA_PROPRIETARY        = (byte) 0x80;
    static final byte CLA_PROPRIETARY_SECURE = (byte) 0x84;

    // CLA/INS for supported commands.
    // GP Commands
    static final short CLA_INS_INITIALIZE_UPDATE              = (short) 0x8050;
    static final short CLA_INS_SET_STATUS                     = (short) 0x80F0;
    static final short CLA_INS_STORE_DATA                     = (short) 0x80E2;
    static final short CLA_INS_EXTERNAL_AUTHENTICATE          = (short) 0x8482;
    static final short CLA_INS_SET_STATUS_SECURED             = (short) 0x84F0;
    static final short CLA_INS_STORE_DATA_SECURED             = (short) 0x84E2;
    // Card Agent Commands
    static final short CLA_INS_GET_CARD_PROFILE               = (short) 0x8080;
    static final short CLA_INS_GET_PTP_SUK                    = (short) 0x8082;
    static final short CLA_INS_GET_MOBILE_KEY                 = (short) 0x8084;
    static final short CLA_INS_INITIALIZE_MOBILE_PIN          = (short) 0x80A0;
    // Issuer Command
    static final short CLA_INS_SEND_AGENT_NOTIFICATON         = (short) 0x8090;   

    // Response status words.
    static final short SW_WARNING_SELECTED_FILE_INVALIDATED = (short) 0x6283;

    // DGI values.
    static final short DGI_DES_KEYS                              = (short) 0x8000;
    static final short DGI_ICC_PRIV_KEY_CRT_CONSTANT_PQ          = (short) 0x8201; // q-1 mod p
    static final short DGI_ICC_PRIV_KEY_CRT_CONSTANT_DQ1         = (short) 0x8202; // d mod (q-1)
    static final short DGI_ICC_PRIV_KEY_CRT_CONSTANT_DP1         = (short) 0x8203; // d mod (p-1)
    static final short DGI_ICC_PRIV_KEY_CRT_CONSTANT_Q           = (short) 0x8204; // q
    static final short DGI_ICC_PRIV_KEY_CRT_CONSTANT_P           = (short) 0x8205; // p
    static final short DGI_SELECT_RESPONSE_DATA                  = (short) 0x9102;
    static final short DGI_DATA                                  = (short) 0xA002;
    static final short DGI_MAGSTRIPE_CVM_DATA                    = (short) 0xA003;
    static final short DGI_PUBLIC_KEY_MODULUS_LENGTH             = (short) 0xA004;
    static final short DGI_ICC_DYNAMIC_NUMBER_MASTER_KEY         = (short) 0xA006;
    static final short DGI_LIMITS                                = (short) 0xA007;             
    static final short DGI_APPLICATION_LIFE_CYCLE_DATA           = (short) 0xA009;
    static final short DGI_CARD_LAYOUT_DESCRIPTION_PART_1        = (short) 0xA026;
    static final short DGI_CARD_LAYOUT_DESCRIPTION_PART_2        = (short) 0xA027;
    static final short DGI_CARD_LAYOUT_DESCRIPTION_PART_3        = (short) 0xA028;
    static final short DGI_IVCVC3                                = (short) 0xB003;
    static final short DGI_GPO_RESPONSE_DATA_PAYMENT             = (short) 0xB005;
    static final short DGI_PIN_IVCVC3                            = (short) 0xB007;

    // 1-byte tags.
    static final byte TAG_FCI_TEMPLATE                            = (byte) 0x6F;
    static final byte TAG_READ_RECORD_RESPONSE_MESSAGE_TEMPLATE   = (byte) 0x70;
    static final byte TAG_RESPONSE_MESSAGE_TEMPLATE               = (byte) 0x77;
    static final byte TAG_AIP_MANAGEMENT                          = (byte) 0x82;
    static final byte TAG_DF_NAME                                 = (byte) 0x84;
    static final byte TAG_AFL_MANAGEMENT                          = (byte) 0x94;
    static final byte TAG_COUNTERS                                = (byte) 0xC6;
    static final byte TAG_CDOL1_RELATED_DATA_LENGTH               = (byte) 0xC7;
    static final byte TAG_CRM_COUNTRY_CODE                        = (byte) 0xC8;
    static final byte TAG_ACCUMULATOR_1_CURRENCY_CODE             = (byte) 0xC9;
    static final byte TAG_ACCUMULATOR_1_LOWER_LIMIT               = (byte) 0xCA;
    static final byte TAG_ACCUMULATOR_1_UPPER_LIMIT               = (byte) 0xCB;
    static final byte TAG_ACCUMULATOR_1_CURRENCY_CONVERSION_TABLE = (byte) 0xD1;
    static final byte TAG_ADDITIONAL_CHECK_TABLE                  = (byte) 0xD3;
    static final byte TAG_APPLICATION_CONTROL_MANAGEMENT          = (byte) 0xD5;
    static final byte TAG_APPLICATION_CONTROL_PAYMENT             = (byte) 0xD7;
    static final byte TAG_AIP_PAYMENT                             = (byte) 0xD8;
    static final byte TAG_AFL_PAYMENT                             = (byte) 0xD9;
    static final byte TAG_IVCVC3_TRACK1                           = (byte) 0xDC;
    static final byte TAG_IVCVC3_TRACK2                           = (byte) 0xDD;

    // 2-byte 0x9FXX tags.
    static final short TAG_ISSUER_APPLICATION_DATA         = (short) 0x9F10;
    static final short TAG_COUNTER_1_LOWER_LIMIT           = (short) 0x9F14;
    static final short TAG_PIN_TRY_COUNTER                 = (short) 0x9F17;
    static final short TAG_COUNTER_1_UPPER_LIMIT           = (short) 0x9F23;
    static final short TAG_APPLICATION_CRYPTOGRAM          = (short) 0x9F26;
    static final short TAG_CRYPTOGRAM_INFO_DATA            = (short) 0x9F27;
    static final short TAG_APPLICATION_TRANSACTION_COUNTER = (short) 0x9F36;
    static final short TAG_SIGNED_DYNAMIC_APPLICATION_DATA = (short) 0x9F4B;
    static final short TAG_LOG_FORMAT                      = (short) 0x9F4F;
    static final short TAG_OFFLINE_ACCUMULATOR_BALANCE_1   = (short) 0x9F50;
    static final short TAG_OFFLINE_ACCUMULATOR_BALANCE_2   = (short) 0x9F58;
    static final short TAG_OFFLINE_COUNTER_BALANCE_2       = (short) 0x9F59;
    static final short TAG_CVC3_TRACK1                     = (short) 0x9F60;
    static final short TAG_CVC3_TRACK2                     = (short) 0x9F61;
    static final short TAG_OFFLINE_COUNTER_BALANCE_1       = (short) 0x9F7A;
    static final short TAG_APPLICATION_LIFE_CYCLE_DATA     = (short) 0x9F7E;

    // 2-byte 0xDFXX tags.
    static final short TAG_SECURITY_LIMITS                           = (short) 0xDF01;
    static final short TAG_SECURITY_LIMITS_STATUS                    = (short) 0xDF02;
    static final short TAG_ACCUMULATOR_1_CONTROL_MANAGEMENT          = (short) 0xDF11;
    static final short TAG_ACCUMULATOR_1_CONTROL_PAYMENT             = (short) 0xDF12;
    static final short TAG_ACCUMULATOR_2_AMOUNT                      = (short) 0xDF13;    
    static final short TAG_ACCUMULATOR_2_CONTROL_MANAGEMENT          = (short) 0xDF14;
    static final short TAG_ACCUMULATOR_2_CONTROL_PAYMENT             = (short) 0xDF15;
    static final short TAG_ACCUMULATOR_2_CURRENCY_CODE               = (short) 0xDF16;
    static final short TAG_ACCUMULATOR_2_CURRENCY_CONVERSION_TABLE   = (short) 0xDF17;
    static final short TAG_ACCUMULATOR_2_LOWER_LIMIT                 = (short) 0xDF18;
    static final short TAG_ACCUMULATOR_2_UPPER_LIMIT                 = (short) 0xDF19;
    static final short TAG_COUNTER_1_CONTROL_MANAGEMENT              = (short) 0xDF1A;
    static final short TAG_COUNTER_1_CONTROL_PAYMENT                 = (short) 0xDF1B;
    static final short TAG_COUNTER_1_NUMBER                          = (short) 0xDF1C;
    static final short TAG_COUNTER_2_CONTROL_MANAGEMENT              = (short) 0xDF1D;
    static final short TAG_COUNTER_2_CONTROL_PAYMENT                 = (short) 0xDF1E;
    static final short TAG_COUNTER_2_LOWER_LIMIT                     = (short) 0xDF1F;
    static final short TAG_COUNTER_2_NUMBER                          = (short) 0xDF20;
    static final short TAG_COUNTER_2_UPPER_LIMIT                     = (short) 0xDF21;
    static final short TAG_ACCUMULATOR_1_AMOUNT                      = (short) 0xDF3B;
    static final short TAG_PIN_IVCVC3_TRACK1                         = (short) 0xDF43;
    static final short TAG_PIN_IVCVC3_TRACK2                         = (short) 0xDF44;
    static final short TAG_CIAC_DECLINE_ON_ONLINE_CAPABLE_PAYMENT    = (short) 0xDF45;
    static final short TAG_CIAC_GO_ONLINE_PAYMENT                    = (short) 0xDF46;
    static final short TAG_CARD_LAYOUT_DESCRIPTION                   = (short) 0xDF47;
    static final short TAG_MCHIP_CVM_CARDHOLDER_OPTIONS              = (short) 0xDF48;
    static final short TAG_DATA_ENVELOPE                             = (short) 0xDF49;
    static final short TAG_DUAL_TAP_RESET_TIMEOUT                    = (short) 0xDF4A;
    static final short TAG_POS_CARDHOLDER_INTERACTION_INFO           = (short) 0xDF4B;
    static final short TAG_PWD                                       = (short) 0xDF4C;
    static final short TAG_CVM_RESET_TIMEOUT                         = (short) 0xDF4D;
    static final short TAG_PPMS_TRANSACTION_DETAILS                  = (short) 0xDF4E;
    static final short TAG_CIAC_DECLINE_ON_PPMS                      = (short) 0xDF4F;
    static final short TAG_SECURITY_WORD                             = (short) 0xDF50;
    static final short TAG_MOBILE_CARDHOLDER_INTERACTION_INFO        = (short) 0xDF51;
    static final short TAG_TRANSACTION_CONTEXT                       = (short) 0xDF52;
    static final short TAG_SWITCH_MODE_INFO                          = (short) 0xDF53;
    static final short TAG_ACK_RESET_TIMEOUT                         = (short) 0xDF55;
    static final short TAG_MCHIP_CVM_ISSUER_OPTIONS                  = (short) 0xDF56;
    static final short TAG_WCOTA                                     = (short) 0xDF57;
    static final short TAG_WCOTN                                     = (short) 0xDF58;
    static final short TAG_CIAC_DECLINE_ON_ARQC_MANAGEMENT           = (short) 0xDF59;
    static final short TAG_CIAC_DECLINE_ON_OFFLINE_ONLY_MANAGEMENT   = (short) 0xDF5A;
    static final short TAG_CIAC_DECLINE_ON_ONLINE_CAPABLE_MANAGEMENT = (short) 0xDF5B;
    static final short TAG_CIAC_GO_ONLINE_MANAGEMENT                 = (short) 0xDF5C;
    static final short TAG_CIAC_DECLINE_ON_ARQC_PAYMENT              = (short) 0xDF5D;
    static final short TAG_CIAC_DECLINE_ON_OFFLINE_ONLY_PAYMENT      = (short) 0xDF5E;
    static final short TAG_OFFLINE_CHANGE_PIN_REQUIRED               = (short) 0xDF5F;
    static final short TAG_MAGSTRIPE_CVM_CARDHOLDER_OPTIONS          = (short) 0xDF60;
    static final short TAG_MAGSTRIPE_CVM_ISSUER_OPTIONS              = (short) 0xDF61;

    // Application is being personalized.
    static final byte APP_STATE_PERSO     = (byte) 0xFF;
    // Application is not currently selected.
    static final byte APP_STATE_IDLE      = (byte) 0x00;
    // Application states after personalization:
    // Application is selected.
    static final byte APP_STATE_SELECTED  = (byte) 0x01;
    // Transaction is initiated.
    static final byte APP_STATE_INITIATED = (byte) 0x02;
    // Application expects a connection with the issuer.
    static final byte APP_STATE_ONLINE    = (byte) 0x03;
    // Application is ready to accept a script command.
    static final byte APP_STATE_SCRIPT    = (byte) 0x04;

    // Modes of operation.
    static final byte MODE_MANAGEMENT = (byte) 0x55;
    static final byte MODE_PAYMENT    = (byte) 0xCC;

    // Rejected, Conditions Not Satisfied identifiers.
    static final byte RCNS1 = (byte) 0x01;
    static final byte RCNS2 = (byte) 0x02;

    // Accumulator/Counter identifiers.
    static final byte ID1 = (byte) 0x01;
    static final byte ID2 = (byte) 0x02;

    static final byte MAX_SFI_RECORDS = (byte) 16;

    static final byte SFI_TRANSACTION_LOG_FILE = (byte) 0x0B;

    /*** Start of data-specific definitions. ***/
    // Previous Transaction History bit definitions.
    static final byte PREVIOUS_TRANSACTION_HISTORY_BIT_APP_DISABLED = (byte) 0x20;
    static final byte PREVIOUS_TRANSACTION_HISTORY_BIT_APP_BLOCKED = (byte) 0x10;
    static final byte PREVIOUS_TRANSACTION_HISTORY_BIT_GO_ONLINE_NEXT_TRANSACTION = (byte) 0x08;
    static final byte PREVIOUS_TRANSACTION_HISTORY_BIT_ISSUER_AUTH_FAILED = (byte) 0x04;
    static final byte PREVIOUS_TRANSACTION_HISTORY_BIT_SCRIPT_RECEIVED = (byte) 0x02;
    static final byte PREVIOUS_TRANSACTION_HISTORY_BIT_SCRIPT_FAILED = (byte) 0x01;
    /*** End of data-specific definitions. ***/

    /*** Start of data location definitions. ***/
    // 'persistentByteBuffer' constants.
    // PBB (persistent byte buffer)
    static final byte PBB_OFFSET_CTR_AC = (byte) 0;
    static final byte PBB_OFFSET_ACCUMULATOR_1_AMOUNT = (byte) (PBB_OFFSET_CTR_AC + 2); // 2
    static final byte PBB_OFFSET_ACCUMULATOR_2_AMOUNT = (byte) (PBB_OFFSET_ACCUMULATOR_1_AMOUNT + 6); // 8
    static final byte PBB_OFFSET_COUNTER_1_NUMBER = (byte) (PBB_OFFSET_ACCUMULATOR_2_AMOUNT + 6); // 14
    static final byte PBB_OFFSET_COUNTER_2_NUMBER = (byte) (PBB_OFFSET_COUNTER_1_NUMBER + 1); // 15
    // Counters is concatenation of:
    // - Application Transaction Counter      2
    // - Global MAC in Script Counter         3
    // - CFDC For Confidentiality Session Key 1
    // - CFDC for AC Session Key              1
    // - CFDC for Integrity Session Key       1
    // - Bad Cryptogram Counter               2
    static final byte PBB_OFFSET_COUNTERS = (byte) (PBB_OFFSET_COUNTER_2_NUMBER + 1); // 16
    static final byte PBB_OFFSET_APPLICATION_TRANSACTION_COUNTER = PBB_OFFSET_COUNTERS; // 16
    static final byte PBB_OFFSET_GLOBAL_MAC_IN_SCRIPT_COUNTER = (byte) (PBB_OFFSET_APPLICATION_TRANSACTION_COUNTER + 2); // 18
    static final byte PBB_OFFSET_CFDC_FOR_CONFIDENTIALITY_SK = (byte) (PBB_OFFSET_GLOBAL_MAC_IN_SCRIPT_COUNTER + 3); // 21
    static final byte PBB_OFFSET_CFDC_FOR_AC_SK = (byte) (PBB_OFFSET_CFDC_FOR_CONFIDENTIALITY_SK + 1); // 22
    static final byte PBB_OFFSET_CFDC_FOR_INTEGRITY_SK = (byte) (PBB_OFFSET_CFDC_FOR_AC_SK + 1); // 23
    static final byte PBB_OFFSET_BAD_CRYPTOGRAM_COUNTER = (byte) (PBB_OFFSET_CFDC_FOR_INTEGRITY_SK + 1); // 24
    static final byte PBB_OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_1 = (byte) (PBB_OFFSET_COUNTERS + 10); // 26
    static final byte PBB_OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_2 = (byte) (PBB_OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_1 + 1); // 27
    static final byte PBB_OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_3 = (byte) (PBB_OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_2 + 1); // 28
    static final byte PBB_OFFSET_PPMS_TRANSACTION_DETAILS = (byte) (PBB_OFFSET_POS_CARDHOLDER_INTERACTION_INFO_BYTE_1 + 3); // 29
    static final byte PBB_OFFSET_PPMS_TRANSACTION_DETAILS_VERSION_NUMBER = PBB_OFFSET_PPMS_TRANSACTION_DETAILS; // 29
    static final byte PBB_OFFSET_PPMS_TRANSACTION_DETAILS_ATC = (byte) (PBB_OFFSET_PPMS_TRANSACTION_DETAILS_VERSION_NUMBER + 1); // 30
    static final byte PBB_OFFSET_PPMS_TRANSACTION_DETAILS_CID = (byte) (PBB_OFFSET_PPMS_TRANSACTION_DETAILS_ATC + 2); // 32
    static final byte PBB_OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_1 = (byte) (PBB_OFFSET_PPMS_TRANSACTION_DETAILS_CID + 1); // 33
    static final byte PBB_OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_2 = (byte) (PBB_OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_1 + 1); // 34
    static final byte PBB_OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_3 = (byte) (PBB_OFFSET_PPMS_TRANSACTION_DETAILS_CVR_BYTE_2 + 1); // 35
    static final byte PBB_OFFSET_SCRIPT_COUNTER = (byte) (PBB_OFFSET_PPMS_TRANSACTION_DETAILS + 7); // 36
    static final byte PBB_OFFSET_SECURITY_LIMITS_STATUS = (byte) (PBB_OFFSET_SCRIPT_COUNTER + 1); // 37
    static final byte PBB_OFFSET_CTR_SMI = (byte) (PBB_OFFSET_SECURITY_LIMITS_STATUS + 1); // 38
    // Errata 6
    // Add PUK Try Counter with length 2 bytes in persistent data objects.
    static final byte PBB_OFFSET_PUK_TRY_COUNTER = (byte) (PBB_OFFSET_CTR_SMI + 2); // 40
    static final byte PBB_OFFSET_CDA_TRANSACTION_FLAG_RECOVERY = (byte) (PBB_OFFSET_PUK_TRY_COUNTER + 2); // 42
    static final byte PBB_OFFSET_APPLICATION_CRYPTOGRAM_RECOVERY = (byte) (PBB_OFFSET_CDA_TRANSACTION_FLAG_RECOVERY + 1); // 43
    static final byte PBB_OFFSET_APPLICATION_TRANSACTION_COUNTER_RECOVERY = (byte) (PBB_OFFSET_APPLICATION_CRYPTOGRAM_RECOVERY + 8); // 51
    static final byte PBB_OFFSET_ISSUER_APPLICATION_DATA_RECOVERY_LENGTH = (byte) (PBB_OFFSET_APPLICATION_TRANSACTION_COUNTER_RECOVERY + 2); // 53
    static final byte PBB_OFFSET_ISSUER_APPLICATION_DATA_RECOVERY = (byte) (PBB_OFFSET_ISSUER_APPLICATION_DATA_RECOVERY_LENGTH + 1); // 54
    static final byte PBB_OFFSET_CRYPTOGRAM_INFO_DATA_RECOVERY = (byte) (PBB_OFFSET_ISSUER_APPLICATION_DATA_RECOVERY + 26); // 80
    static final byte PBB_OFFSET_UNPREDICTABLE_NUMBER_RECOVERY = (byte) (PBB_OFFSET_CRYPTOGRAM_INFO_DATA_RECOVERY + 1); // 81
    static final byte PBB_OFFSET_HASH_RESULT_RECOVERY = (byte) (PBB_OFFSET_UNPREDICTABLE_NUMBER_RECOVERY + 4); // 85
    static final byte PBB_OFFSET_POS_CARDHOLDER_INTERACTION_INFO_RECOVERY = (byte) (PBB_OFFSET_HASH_RESULT_RECOVERY + 20); // 105
    static final byte SIZE_PBB = (byte) (PBB_OFFSET_POS_CARDHOLDER_INTERACTION_INFO_RECOVERY + 3); // 108

    // 'personalizedPersistentByteBuffer' constants.
    // PPBB (personalized persistent byte buffer)
    // TODO: Re-order data elements as defined in DGI 'A002'.
    static final byte PPBB_OFFSET_ACCUMULATOR_1_CURRENCY_CODE = (byte) 0;
    static final byte PPBB_OFFSET_ACCUMULATOR_1_CURRENCY_CONVERSION_TABLE = (byte) (PPBB_OFFSET_ACCUMULATOR_1_CURRENCY_CODE + 2); // 2
    static final byte PPBB_OFFSET_ACCUMULATOR_1_LOWER_LIMIT = (byte) (PPBB_OFFSET_ACCUMULATOR_1_CURRENCY_CONVERSION_TABLE + 25); // 27
    static final byte PPBB_OFFSET_ACCUMULATOR_1_UPPER_LIMIT = (byte) (PPBB_OFFSET_ACCUMULATOR_1_LOWER_LIMIT + 6); // 33
    static final byte PPBB_OFFSET_ACCUMULATOR_2_CURRENCY_CODE = (byte) (PPBB_OFFSET_ACCUMULATOR_1_UPPER_LIMIT + 6); // 39
    static final byte PPBB_OFFSET_ACCUMULATOR_2_CURRENCY_CONVERSION_TABLE = (byte) (PPBB_OFFSET_ACCUMULATOR_2_CURRENCY_CODE + 2); // 41
    static final byte PPBB_OFFSET_ACCUMULATOR_2_LOWER_LIMIT = (byte) (PPBB_OFFSET_ACCUMULATOR_2_CURRENCY_CONVERSION_TABLE + 25); // 66
    static final byte PPBB_OFFSET_ACCUMULATOR_2_UPPER_LIMIT = (byte) (PPBB_OFFSET_ACCUMULATOR_2_LOWER_LIMIT + 6); // 72
    static final byte PPBB_OFFSET_ADDITIONAL_CHECK_TABLE_POSITION_IN_CDOL1_RELATED_DATA = (byte) (PPBB_OFFSET_ACCUMULATOR_2_UPPER_LIMIT + 6); // 78
    static final byte PPBB_OFFSET_ADDITIONAL_CHECK_TABLE_LENGTH_IN_CDOL1_RELATED_DATA = (byte) (PPBB_OFFSET_ADDITIONAL_CHECK_TABLE_POSITION_IN_CDOL1_RELATED_DATA + 1); // 79
    static final byte PPBB_OFFSET_ADDITIONAL_CHECK_TABLE_NUMBER_OF_ENTRIES = (byte) (PPBB_OFFSET_ADDITIONAL_CHECK_TABLE_LENGTH_IN_CDOL1_RELATED_DATA + 1); // 80
    static final byte PPBB_OFFSET_ADDITIONAL_CHECK_TABLE_ENTRIES_BIT_MASK = (byte) (PPBB_OFFSET_ADDITIONAL_CHECK_TABLE_NUMBER_OF_ENTRIES + 1); // 81
    static final byte PPBB_OFFSET_CDOL1_RELATED_DATA_LENGTH = (byte) (PPBB_OFFSET_ADDITIONAL_CHECK_TABLE_POSITION_IN_CDOL1_RELATED_DATA + 18); // 96
    static final byte PPBB_OFFSET_COUNTER_1_LOWER_LIMIT = (byte) (PPBB_OFFSET_CDOL1_RELATED_DATA_LENGTH + 1); // 97
    static final byte PPBB_OFFSET_COUNTER_1_UPPER_LIMIT = (byte) (PPBB_OFFSET_COUNTER_1_LOWER_LIMIT + 1); // 98
    static final byte PPBB_OFFSET_COUNTER_2_LOWER_LIMIT = (byte) (PPBB_OFFSET_COUNTER_1_UPPER_LIMIT + 1); // 99
    static final byte PPBB_OFFSET_COUNTER_2_UPPER_LIMIT = (byte) (PPBB_OFFSET_COUNTER_2_LOWER_LIMIT + 1); // 100
    static final byte PPBB_OFFSET_CRM_COUNTRY_CODE = (byte) (PPBB_OFFSET_COUNTER_2_UPPER_LIMIT + 1); // 101
    static final byte PPBB_OFFSET_KEY_DERIVATION_INDEX = (byte) (PPBB_OFFSET_CRM_COUNTRY_CODE + 2); // 103
    static final byte PPBB_OFFSET_MCHIP_CVM_CARDHOLDER_OPTIONS = (byte) (PPBB_OFFSET_KEY_DERIVATION_INDEX + 1); // 104
    static final byte PPBB_OFFSET_MCHIP_CVM_ISSUER_OPTIONS = (byte) (PPBB_OFFSET_MCHIP_CVM_CARDHOLDER_OPTIONS + 1); // 105
    static final byte PPBB_OFFSET_CVM_RESET_TIMEOUT = (byte) (PPBB_OFFSET_MCHIP_CVM_ISSUER_OPTIONS + 1); // 106
    static final byte PPBB_OFFSET_ACK_RESET_TIMEOUT = (byte) (PPBB_OFFSET_CVM_RESET_TIMEOUT + 2); // 108
    static final byte PPBB_OFFSET_DUAL_TAP_RESET_TIMEOUT = (byte) (PPBB_OFFSET_ACK_RESET_TIMEOUT + 2); // 110
    static final byte PPBB_OFFSET_OFFLINE_CHANGE_PIN_REQUIRED = (byte) (PPBB_OFFSET_DUAL_TAP_RESET_TIMEOUT + 2); // 112
    static final byte PPBB_OFFSET_MAGSTRIPE_CVM_CARDHOLDER_OPTIONS = (byte) (PPBB_OFFSET_OFFLINE_CHANGE_PIN_REQUIRED + 1); // 113
    static final byte PPBB_OFFSET_MAGSTRIPE_CVM_ISSUER_OPTIONS = (byte) (PPBB_OFFSET_MAGSTRIPE_CVM_CARDHOLDER_OPTIONS + 1); // 114
    static final byte PPBB_OFFSET_CIAC_DECLINE_ON_PPMS = (byte) (PPBB_OFFSET_MAGSTRIPE_CVM_ISSUER_OPTIONS + 1); // 115
    static final byte PPBB_OFFSET_ICC_PUB_KEY_MODULUS_LENGTH = (byte) (PPBB_OFFSET_CIAC_DECLINE_ON_PPMS + 2); // 117
    static final byte PPBB_OFFSET_ICC_PIN_ENC_PUB_KEY_MODULUS_LENGTH = (byte) (PPBB_OFFSET_ICC_PUB_KEY_MODULUS_LENGTH + 1); // 118
    static final byte PPBB_OFFSET_PREVIOUS_TRANSACTION_HISTORY = (byte) (PPBB_OFFSET_ICC_PIN_ENC_PUB_KEY_MODULUS_LENGTH + 1); // 119
    static final byte PPBB_OFFSET_APPLICATION_TRANSACTION_COUNTER_LIMIT = (byte) (PPBB_OFFSET_PREVIOUS_TRANSACTION_HISTORY + 1); // 120
    static final byte PPBB_OFFSET_LIM_AC = (byte) (PPBB_OFFSET_APPLICATION_TRANSACTION_COUNTER_LIMIT + 2); // 122
    static final byte PPBB_OFFSET_LIM_SMI = (byte) (PPBB_OFFSET_LIM_AC + 2); // 124
    static final byte PPBB_OFFSET_BAD_CRYPTOGRAM_LIMIT = (byte) (PPBB_OFFSET_LIM_SMI + 2); // 126
    // > 127
    static final short PPBB_OFFSET_IVCVC3_TRACK1 = (short) (PPBB_OFFSET_BAD_CRYPTOGRAM_LIMIT + 2); // 128
    static final short PPBB_OFFSET_IVCVC3_TRACK2 = (short) (PPBB_OFFSET_IVCVC3_TRACK1 + 2); // 130
    static final short PPBB_OFFSET_PIN_IVCVC3_TRACK1 = (short) (PPBB_OFFSET_IVCVC3_TRACK2 + 2); // 132
    static final short PPBB_OFFSET_PIN_IVCVC3_TRACK2 = (short) (PPBB_OFFSET_PIN_IVCVC3_TRACK1 + 2); // 134
    static final short PPBB_OFFSET_PIN_TRY_COUNTER = (short) (PPBB_OFFSET_PIN_IVCVC3_TRACK2 + 2); // 136
    static final short PPBB_OFFSET_PIN_TRY_LIMIT = (short) (PPBB_OFFSET_PIN_TRY_COUNTER + 1); // 137
    static final short PPBB_OFFSET_APPLICATION_LIFE_CYCLE_DATA = (short) (PPBB_OFFSET_PIN_TRY_LIMIT + 1); // 138
    static final short PPBB_OFFSET_PWD = (short) (PPBB_OFFSET_APPLICATION_LIFE_CYCLE_DATA + 48); // 186
    static final short PPBB_OFFSET_PUK = (short) (PPBB_OFFSET_PWD + 16); // 202
    static final short PPBB_OFFSET_REFERENCE_PIN = (short) (PPBB_OFFSET_PUK + 8); // 210
    // Errata 3
    // TODO: Remove Security Limits, the three limits that make it already exist.
    static final short PPBB_OFFSET_SECURITY_LIMITS = (short) (PPBB_OFFSET_REFERENCE_PIN + 8); // 218
    static final short PPBB_OFFSET_SECURITY_WORD = (short) (PPBB_OFFSET_SECURITY_LIMITS + 6); // 224
    static final short PPBB_OFFSET_SWITCH_MODE_INFO = (short) (PPBB_OFFSET_SECURITY_WORD + 16); // 240
    static final short PPBB_OFFSET_WCOTA = (short) (PPBB_OFFSET_SWITCH_MODE_INFO + 20); // 260
    static final short PPBB_OFFSET_WCOTN = (short) (PPBB_OFFSET_WCOTA + 6); // 266
    static final short PPBB_OFFSET_DATA_ENVELOPE_LENGTH = (short) (PPBB_OFFSET_WCOTN + 1); // 267
    static final short PPBB_OFFSET_DATA_ENVELOPE = (short) (PPBB_OFFSET_DATA_ENVELOPE_LENGTH + 1); // 268
    static final short SIZE_PPBB = (short) (PPBB_OFFSET_DATA_ENVELOPE + 32); // 300

    // 'transientByteBuffer' constants.
    // TBB (transient byte buffer)
    static final byte TBB_OFFSET_STATE = (byte) 0;
    // 'transientByteBuffer' constants used after personalization.
    static final byte TBB_OFFSET_ACTIVE_MODE_FLAG = (byte) (TBB_OFFSET_STATE + 1); // 1
    // TODO: Remove TBB_OFFSET_GET_CHALLENGE_FLAG.
    static final byte TBB_OFFSET_GET_CHALLENGE_FLAG = (byte) (TBB_OFFSET_ACTIVE_MODE_FLAG + 1); // 2
    static final byte TBB_OFFSET_CVR_BYTE_1 = (byte) (TBB_OFFSET_GET_CHALLENGE_FLAG + 1); // 3
    static final byte TBB_OFFSET_CVR_BYTE_2 = (byte) (TBB_OFFSET_CVR_BYTE_1 + 1); // 4
    static final byte TBB_OFFSET_CVR_BYTE_3 = (byte) (TBB_OFFSET_CVR_BYTE_2 + 1); // 5
    static final byte TBB_OFFSET_CVR_BYTE_4 = (byte) (TBB_OFFSET_CVR_BYTE_3 + 1); // 6
    static final byte TBB_OFFSET_CVR_BYTE_5 = (byte) (TBB_OFFSET_CVR_BYTE_4 + 1); // 7
    static final byte TBB_OFFSET_CVR_BYTE_6 = (byte) (TBB_OFFSET_CVR_BYTE_5 + 1); // 8
    static final byte TBB_OFFSET_FIRST_AC = (byte) (TBB_OFFSET_CVR_BYTE_1 + 6); // 9
    static final byte TBB_OFFSET_ICC_DYNAMIC_NUMBER = (byte) (TBB_OFFSET_FIRST_AC + 8); // 17
    static final byte TBB_OFFSET_ICC_UNPREDICTABLE_NUMBER = (byte) (TBB_OFFSET_ICC_DYNAMIC_NUMBER + 8); // 25
    static final byte TBB_OFFSET_OFFLINE_CHANGE_PIN_STATUS = (byte) (TBB_OFFSET_ICC_UNPREDICTABLE_NUMBER + 8); // 33
    static final byte TBB_OFFSET_RAND = (byte) (TBB_OFFSET_OFFLINE_CHANGE_PIN_STATUS + 1); // 34
    static final byte TBB_OFFSET_RECOVER_AC_PERFORMED_FLAG = (byte) (TBB_OFFSET_RAND + 8); // 42
    static final byte TBB_OFFSET_SMC_CSK_KEY_PRESENT_FLAG = (byte) (TBB_OFFSET_RECOVER_AC_PERFORMED_FLAG + 1); // 43
    static final byte TBB_OFFSET_SMI_CSK_KEY_PRESENT_FLAG = (byte) (TBB_OFFSET_SMC_CSK_KEY_PRESENT_FLAG + 1); // 44
    // CDOL 1 Related Data length is stored at PPBB_OFFSET_CDOL1_RELATED_DATA_LENGTH.
    // NOTE: Maximum CDOL1 Related Data length is 53 as the minimum. It can be 180 - 45 = 135 bytes. Report as 128.
    /*
    PDOL Data[1]
    CDOL1 Related Data := Transaction Related Data
    Amount, Authorized (Numeric) := Transaction Related Data[1 : 6]
    Amount, Other (Numeric) := Transaction Related Data[7 : 12]
    Terminal Country Code := Transaction Related Data[13 : 14]
    Terminal Verification Results := Transaction Related Data[15 : 19]
    Transaction Currency Code := Transaction Related Data[20 : 21]
    Transaction Date := Transaction Related Data[22 : 24]
    Transaction Type := Transaction Related Data[25]
    Unpredictable Number := Transaction Related Data[26 : 29]
    Terminal Type := Transaction Related Data[30]
    Data Authentication Code := Transaction Related Data[31 : 32]
    ICC Dynamic Number (Terminal) := Transaction Related Data[33 : 40]
    CVM Results := Transaction Related Data[41 : 43]
    CDOL1 Extension := Transaction Related Data[44 : CDOL 1 Related Data Length]
    Note: CDOL1 Extension may be empty
    */
    static final byte TBB_OFFSET_PDOL_DATA = (byte) (TBB_OFFSET_SMI_CSK_KEY_PRESENT_FLAG + 1); // 45
    static final byte TBB_OFFSET_CDOL1_RELATED_DATA = (byte) (TBB_OFFSET_PDOL_DATA + 1); // 46
    static final byte TBB_OFFSET_AMOUNT_AUTHORIZED = TBB_OFFSET_CDOL1_RELATED_DATA; // 47
    static final byte TBB_OFFSET_AMOUNT_OTHER = (byte) (TBB_OFFSET_AMOUNT_AUTHORIZED + 6); // 52
    static final byte TBB_OFFSET_TERMINAL_COUNTRY_CODE = (byte) (TBB_OFFSET_AMOUNT_OTHER + 6); // 58
    static final byte TBB_OFFSET_TVR = (byte) (TBB_OFFSET_TERMINAL_COUNTRY_CODE + 2); // 60 (not required by spec)
    static final byte TBB_OFFSET_TRANSACTION_CURRENCY_CODE = (byte) (TBB_OFFSET_TVR + 5); // 65
    static final byte TBB_OFFSET_TRANSACTION_DATE = (byte) (TBB_OFFSET_TRANSACTION_CURRENCY_CODE + 2); // 67
    static final byte TBB_OFFSET_TRANSACTION_TYPE = (byte) (TBB_OFFSET_TRANSACTION_DATE + 3); // 70
    static final byte TBB_OFFSET_UNPREDICTABLE_NUMBER = (byte) (TBB_OFFSET_TRANSACTION_TYPE + 1); // 71 (not required by spec)
    static final byte TBB_OFFSET_TERMINAL_TYPE = (byte) (TBB_OFFSET_UNPREDICTABLE_NUMBER + 4); // 75 (not required by spec)
    static final byte TBB_OFFSET_DATA_AUTHENTICATION_CODE = (byte) (TBB_OFFSET_TERMINAL_TYPE + 1); // 76
    static final byte TBB_OFFSET_ICC_DYNAMIC_NUMBER_TERMINAL = (byte) (TBB_OFFSET_DATA_AUTHENTICATION_CODE + 2); // 78 (not required by spec)
    static final byte TBB_OFFSET_CVM_RESULTS = (byte) (TBB_OFFSET_ICC_DYNAMIC_NUMBER_TERMINAL + 8); // 86 (not required by spec)
    static final byte TBB_OFFSET_CDOL1_EXTENSION = (byte) (TBB_OFFSET_CVM_RESULTS + 3); // 89 (not required by spec)
    static final short TBB_OFFSET_SCRATCH = (short) 180;
    // 'transientByteBuffer' constants used during personalization.
    static final byte TBB_OFFSET_SEQUENCE_NUMBER = (byte) (TBB_OFFSET_STATE + 1); // 1
    static final byte TBB_OFFSET_FULL_DGI_LENGTH = (byte) (TBB_OFFSET_SEQUENCE_NUMBER + 1); // 2
    static final byte TBB_OFFSET_PREV_PARTIAL_DGI_LENGTH = (byte) (TBB_OFFSET_FULL_DGI_LENGTH + 1); // 3
    static final byte TBB_OFFSET_PREV_PARTIAL_DGI_DATA = (byte) (TBB_OFFSET_PREV_PARTIAL_DGI_LENGTH + 1); // 4
    static final short SIZE_TBB = (short) 272;

    /*** End of data location definitions. ***/

}
