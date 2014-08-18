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
package com.st.vcbp;

public final class DataUtil {

	private final static char NIBBLE_TO_CHAR[] = { 
		'0', '1', '2', '3', '4', '5', '6', '7', 
		'8', '9', 'A', 'B', 'C', 'D', 'E', 'F' 
	};

	private DataUtil() {
	}

	/**
	 * Returns byte values converted to a single hex string value.
	 * <p>
	 * For example, byte values 0x12 0x34 0x56 0x78 0x9A converts to string
	 * value "123456789A".
	 * 
	 * @param data
	 *            byte values
	 * @return hex string value
	 */
	public static String byteArrayToHexString(byte[] data) {
	    if (data == null) {
	        return "";
	    }

	    return byteArrayToHexString(data, 0, data.length);
	}

	/**
	 * Returns byte values converted to a single hex string value.
	 * <p>
	 * For example, byte values 0x12 0x34 0x56 0x78 0x9A converts to string
	 * value "123456789A".
	 * 
	 * @param data
	 *            byte values
	 * @param offset
	 *            offset of first byte value
	 * @param length
	 *            length of byte values
	 * @return hex string value
	 */
	public static String byteArrayToHexString(byte[] data, int offset, int length) {
		StringBuffer buff = new StringBuffer();

		if (data != null) {
			for (int i = offset; i < (int) (offset + length); i++) {
				byte b = data[i];
				int I = ((char) b) & 0xFF;
				buff.append(NIBBLE_TO_CHAR[I >>> 4]);
				buff.append(NIBBLE_TO_CHAR[I & 0x0F]);
			}
		}

		return buff.toString();
	}

	/**
	 * Returns a single hex string value converted to byte values.
	 * <p>
	 * Accepts string values whose hex values are from 0x30 to 0x46.
	 * <p>
	 * For example, string value "123456789A" converts to byte values 0x01 0x02
	 * 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0A.
	 * 
	 * @param data
	 *            hex string value
	 * @return byte values, <code>null</code> if conversion error
	 */
	public static byte[] stringToByteArray(String data) {
		StringBuffer buff = new StringBuffer(data.toUpperCase());
		byte[] convertedString = new byte[buff.length()];

		for (int i = 0; i < convertedString.length; i++) {
			byte currentByte = (byte) buff.charAt(i);
			if ((currentByte >= 0x30) && (currentByte <= 0x40)) {
				convertedString[i] = (byte) (currentByte - 0x30);
			} 
			else if ((currentByte >= 0x41) && (currentByte <= 0x46)) {
				convertedString[i] = (byte) (currentByte - 0x37);
			}
			else {
				return null;
			}
		}

		return convertedString;
	}

	/**
	 * Returns a single hex string value converted to compressed byte values.
	 * Odd number of characters is padded with 'F'.
	 * <p>
	 * Accepts string values whose hex values are from 0x30 to 0x46.
	 * <p>
	 * For example, string value "123456789AB" converts to byte values 0x12 0x34
	 * 0x56 0x78 0x9A 0xBF.
	 * 
	 * @param data
	 *            hex string value
	 * @return byte values, <code>null</code> if conversion error
	 */
	public static byte[] stringToCompressedByteArray(String data) {
		StringBuffer buff = new StringBuffer(data.toUpperCase());
		byte[] convertedString;
		if ((buff.length() % 2) == 0) {
			convertedString = new byte[buff.length() / 2];
		} 
		else {
			convertedString = new byte[(buff.length() / 2) + 1];
		}

		int convertedStringOffset = 0;
		for (int i = 0; i < buff.length(); i++) {
			byte currentByte = (byte) buff.charAt(i);
			if ((currentByte >= 0x30) && (currentByte <= 0x40)) {
				convertedString[convertedStringOffset] = (byte) ((currentByte - 0x30) << 4);
			}
			else if ((currentByte >= 0x41) && (currentByte <= 0x46)) {
				convertedString[convertedStringOffset] = (byte) ((currentByte - 0x37) << 4);
			}
			else {
				return null;
			}

			i++;
			if (i < buff.length()) {
				currentByte = (byte) buff.charAt(i);
				if ((currentByte >= 0x30) && (currentByte <= 0x40)) {
					convertedString[convertedStringOffset++] |= (byte) (currentByte - 0x30);
				}
				else if ((currentByte >= 0x41) && (currentByte <= 0x46)) {
					convertedString[convertedStringOffset++] |= (byte) (currentByte - 0x37);
				}
				else {
					return null;
				}
			}
			else {
				convertedString[convertedStringOffset++] |= (byte) 0x0F;
			}
		}

		return convertedString;
	}

}
