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

import java.io.Serializable;

import javacard.framework.Util;

/**
 * Define data objects for SFI records and Transaction Log records.
 * 
 * @author SimplyTapp, Inc.
 * @version 1.0
 */
final class Records implements Serializable {

    private static final long serialVersionUID = 1L;

    static final byte SFI_NOT_FOUND = (byte) 0x00;
    static final byte SFI_FOUND     = (byte) 0x01;
    static final byte RECORD_FOUND  = (byte) 0x02;

    // NOTE: Maximum record length supported needs to be between 180 and 247.
    private static final short MAX_SFI_RECORD_LENGTH = (short) 247;
    //private static final short MAX_SFI_RECORD_LENGTH = (short) 254;

    private Record[] sfiRecords;
    private short sfiRecordCounter;

    private Record foundRecord;

    /**
     * Constructor for records.
     * 
     * @param maxSFIRecords
     */
    Records(short maxSFIRecords) {
        this.sfiRecords = new Record[maxSFIRecords];
        this.sfiRecordCounter = (short) 0;
    }

    // DEBUG
    short debugGetSFIRecordCounter() {
        return this.sfiRecordCounter;
    }

    /**
     * Find SFI record.
     * 
     * @param sfi
     * @param recordNumber
     * @param record
     * @return
     */
    byte findSFIRecord(byte sfi, short recordNumber) {
        this.foundRecord = null;
        byte result = SFI_NOT_FOUND;

        // Search SFI records.
        short recordOffset = (short) 0;
        while (recordOffset < this.sfiRecordCounter) {
            Record record = this.sfiRecords[recordOffset++];
            if (record.sfi == sfi) {
                result = SFI_FOUND;

                if (record.recordNumber == recordNumber) {
                    this.foundRecord = record;
                    result = RECORD_FOUND;

                    break;
                }
            }
        }

        // result = 0x00 if SFI not found.
        // result = 0x01 if SFI found, record number not found.
        // result = 0x02 if SFI found, record number found.
        return result;
    }

    /**
     * Return maximum data length for found record.
     * 
     * @return
     */
    short getFoundRecordMaxLength() {
        if (this.foundRecord == null) {
            return (short) 0;
        }

        return (short) this.foundRecord.data.length;
    }

    /**
     * Update SFI record.
     * 
     * @param data
     * @param dataOffset
     * @param dataLength
     */
    void updateRecord(byte[] data, short dataOffset, short dataLength) {
        if (this.foundRecord == null) {
            return;
        }

        Util.arrayCopyNonAtomic(data, dataOffset, this.foundRecord.data, (short) 0, dataLength);
        this.foundRecord.dataLength = dataLength;
    }

    /**
     * Add SFI Record.
     * 
     * @param sfi
     * @param recordNumber
     * @param data
     * @param dataOffset
     * @param dataLength
     */
    void addSFIRecord(byte sfi, byte recordNumber, byte[] data, short dataOffset, short dataLength) {
        // Check if record length is longer than maximum supported length.
        // Check if number of records has already reached maximum number.
        // Check if SFI is not the same as SFI reserved for Transaction Log File.
        if ((dataLength >= MAX_SFI_RECORD_LENGTH) || 
            (this.sfiRecordCounter >= this.sfiRecords.length) || 
            (sfi == Constants.SFI_TRANSACTION_LOG_FILE)) {
            return;
        }

        // Check for duplicate record.
        if (findSFIRecord(sfi, recordNumber) == RECORD_FOUND) {
            // Found duplicate record, do not add record.
            return;
        }

        this.sfiRecords[this.sfiRecordCounter] = new Record(sfi, recordNumber, data, dataOffset, dataLength);

        this.sfiRecordCounter++;
    }

    /**
     * Find record, retrieve record data, return record data.
     * 
     * @param sfi
     * @param recordNumber
     * @param dataBuffer
     * @return
     */
    short getRecordData(byte sfi, short recordNumber, byte[] dataBuffer) {
        byte result = findSFIRecord(sfi, recordNumber);
        if (result == RECORD_FOUND) {
            return Util.arrayCopyNonAtomic(this.foundRecord.data, (short) 0, dataBuffer, (short) 0, this.foundRecord.dataLength);
        }

        // Use offset 1 to indicate error type.
        dataBuffer[(byte) 1] = result;

        // Record not found.
        // dataBuffer[1] = 0x00 if SFI not found.
        //                 0x01 if SFI found, record number not found.
        return (short) -1;
    }

    /**
     * Find record and return record data.
     * 
     * @param sfi
     * @param recordNumber
     * @return
     */
    byte[] getRecord(byte sfi, short recordNumber) {
        byte result = findSFIRecord(sfi, recordNumber);
        if (result == RECORD_FOUND) {
            return this.foundRecord.data;
        }
        else {
            return null;
        }
    }


    /**
     * SFI Record object.
     */
    private final class Record implements Serializable {

        private static final long serialVersionUID = 1L;

        private byte sfi;
        private byte recordNumber;
        private byte[] data;
        private short dataLength;

        /**
         * Constructor for SFI Record object.
         * 
         * @param sfi
         * @param recordNumber
         * @param data
         * @param dataOffset
         * @param dataLength
         */
        private Record(byte sfi, byte recordNumber, byte[] data, short dataOffset, short dataLength) {
            this.sfi = sfi;
            this.recordNumber = recordNumber;

            // Add tag and length to record data.
            short recordLength = (short) (dataLength + (byte) 2);
            if (dataLength > (short) 127) {
                recordLength++;
            }
            this.data = new byte[recordLength];
            // Reuse 'recordLength' to track offset.
            recordLength = (short) 0;
            this.data[recordLength++] = Constants.TAG_READ_RECORD_RESPONSE_MESSAGE_TEMPLATE;
            if (dataLength > (short) 127) {
                this.data[recordLength++] = (byte) 0x81;
            }
            this.data[recordLength++] = (byte) dataLength;
            this.dataLength = Util.arrayCopyNonAtomic(data, dataOffset, this.data, recordLength, dataLength);
        }

    }

}
