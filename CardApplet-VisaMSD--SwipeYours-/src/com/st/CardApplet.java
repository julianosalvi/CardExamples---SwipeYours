package com.st;
import java.io.IOException;
import java.util.Calendar;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class CardApplet extends Applet {
	
	/*IMPORTANT NOTE
	 * any class that is expected to be persistent
	 * throughly the applet life-cycle should 
	 * implement serializable interface
	 * test that an applet complies at any time 
	 * by running an /atr in the simulator, this
	 * forces serialization and will through an exception
	 * if there is a problem.
	 * 
	 * If any library classes through this exception please 
	 * notify support@simplytapp.com and copy/paste the
	 * exception trace in the email*/

	/*IMPORTANT NOTE 2
	 *notice that the "main" function is located in
	 *cardWrapper.CardWrapper
	 *for simulator debugging to work properly, you must 
	 *configure this in debug configuration*/

	/*IMPORTANT NOTE 3 (simulation tutorial)
	 *using the simulator is simple, just click debug.
	 *some quick hints to installing and testing your
	 *applet from simulator:
	 *
	 * #reset card and select card manager
	 * /card
	 * 
	 * #open a secure channel to card manager
	 * auth
	 * 
	 * #install the PPSE and card applet in this SDK
	 * #the package converted to ascii hex is:  com.st -> 636f6d2e7374
	 * #the PPSE applet module converted to ascii hex is: Ppse2Pay -> 5070736532506179
	 * #the card applet module converted to ascii hex is: CardApplet -> 436172644170706c6574
	 * #try to keep the package name and module name
	 * #to between 5 and 16 characters to make your life easier.
	 * #this example installs the PPSE module as "2PAY.SYS.DDF01" -> 325041592e5359532e4444463031
	 * #this example also installs the card applet as A0000000031010
	 * install -i 325041592e5359532e4444463031 -q C9#() 636f6d2e7374 5070736532506179
	 * install -i A0000000031010 -q C9#() 636f6d2e7374 436172644170706c6574
	 * 
	 * #select them now for testing!
	 * /select |2PAY.SYS.DDF01
	 * /select A0000000031010
	 * 
	 * #see website for more on gpjNG simulation
	 * */

	private static final long serialVersionUID = 1L;
	//these variables define the state of the profile
	//the pre_perso state cannot be an ACTIVE profile
	//the perso state means the card is in personalization mode
	//the alive state means the card is personalized 
	public final byte PRE_PERSO = (byte)0x00;
	public final byte PERSO = (byte)0x01;
	public final byte ALIVE = (byte)0x02;
	public byte STATE = PERSO;
	
	//more state variables
	private byte state = 0;
	private final byte not_alive = (byte)0x01;
	private final byte selected = (byte)0x02;

	//RR - Card Record - this is card specific
	public byte[] RR = new byte[] {
		0x70,	0x02,	0x57,	0x00
	};

	//AID - Application Identifier -
	public final byte[] AID = new byte[] {(byte)0xA0,(byte)0x00,(byte)0x00,(byte)0x00,  //VisaContactless
								(byte)0x03,(byte)0x10,(byte)0x10			};
	//AL - Application Label - 
	public final byte[] AL = new byte[] {0x56,0x49,0x53,0x41,0x20,0x43,0x52,0x45,0x44,0x49,0x54}; //"VISACREDIT"
	//DF - Dedicated File (AID) -
	public final byte[] DF = new byte[] {	(byte)0xA0,(byte)0x00,(byte)0x00,(byte)0x00,  //VisaContactless
								(byte)0x03,(byte)0x10,(byte)0x10			};

	public static String bytArrayToHex(byte[] a) {
		   StringBuilder sb = new StringBuilder();
		   for(byte b: a)
		      sb.append(String.format("%02x", b&0xff));
		   return sb.toString();
		}

	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}

	public static void install(byte[] bArray, short bOffset, byte bLength){
		new CardApplet().register();
	}

	public void process(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		
		if (selectingApplet()) {
			//verify that the class for this instruction is correct
			if((short)(buf[ISO7816.OFFSET_CLA] & 0xFF) != 0x00)
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			//get the rest of the apdu and check length
			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != apdu.setIncomingAndReceive())
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

			//if the active profile state has not been pre-personalized
			//this application cannot be used
			short len;
			if(STATE == PERSO)
			{
				for(short i=0;i<AL.length;i++)
					buf[i] = AL[i];
				len = (short)(AL.length);
				state = not_alive;
				new Thread(new Runnable()
				{
					@Override
					public void run() {
						// TODO Auto-generated method stub
						
					}
				}
				).start();
			}
			else
			{
				//send Visa
				buf[0]=(byte)0x6F; //FCI Template
				buf[1]=(byte)(12 + DF.length + AL.length);   //length
					buf[2]=(byte)0x84; //DF
					buf[3]=(byte)DF.length;    //length
						for(short i=0;i<DF.length;i++)
							buf[4+i] = DF[i];
					buf[4+DF.length]=(byte)0xA5; //FCI Proprietary Template
					buf[5+DF.length]=(byte)(8+AL.length);    //length
						buf[6+DF.length]=(byte)0x50; //AL
						buf[7+DF.length]=(byte)AL.length;   //length
						for(short i=0;i<AL.length;i++)
							buf[8+DF.length+i] = AL[i];
						buf[8+DF.length+AL.length] = (byte)0x9F;
						buf[9+DF.length+AL.length] = (byte)0x38;
						buf[10+DF.length+AL.length] = (byte)0x03;
						buf[11+DF.length+AL.length] = (byte)0x9F;
						buf[12+DF.length+AL.length] = (byte)0x66;
						buf[13+DF.length+AL.length] = (byte)0x02;
						
				len = (short)(14 + AL.length + DF.length);
				state = selected;
			}
		
			apdu.setOutgoingAndSend((short)0,len);
			return;
		}
		
		switch (buf[ISO7816.OFFSET_INS]) {
		
		case (byte) 0xA4: //select AID
			//verify that the class for this instruction is correct
			if((short)(buf[ISO7816.OFFSET_CLA] & 0xFF) != 0x00)
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			//check that P1 & P2 are correct
			if(buf[ISO7816.OFFSET_P1] != (byte) 0x04 || buf[ISO7816.OFFSET_P2] != (byte) 0x00)
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			//get the rest of the apdu and check length
			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != apdu.setIncomingAndReceive())
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			//otherwise, the file name was wrong for this select
			else ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		
		case (byte) 0xA8: //get processing options
			//verify that the class for this instruction is correct
			if((short)(buf[ISO7816.OFFSET_CLA] & 0xFF) != 0x80)
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			//check state - this command only works in selected state
			if(state != selected)
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			//check that P1 & P2 are correct
			if(buf[ISO7816.OFFSET_P1] != (byte) 0x00 || buf[ISO7816.OFFSET_P2] != (byte) 0x00)
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			//check that LC is 0x02
			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != (short) 0x04)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			//get the rest of the apdu and check length
			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != apdu.setIncomingAndReceive())
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			//check PDOL data that it is '83028000'
			if(buf[ISO7816.OFFSET_CDATA] != (byte) 0x83 || buf[ISO7816.OFFSET_CDATA+1] != (byte) 0x02)
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			if(buf[ISO7816.OFFSET_CDATA+2] != (byte) 0x80 || buf[ISO7816.OFFSET_CDATA+3] != (byte) 0x00)
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			
			byte[] GPO = new byte[]{(byte)0x80,0x06,0x00,(byte)0x80,0x08,0x01,0x01,0x00};
			for(short i=0;i<GPO.length;i++)
				buf[i] = GPO[i];
			apdu.setOutgoingAndSend((short)0, (short)GPO.length);
			break;

		case (byte) 0xE2:
			apdu.setIncomingAndReceive();
			String pan = "";
			int num = 0;
			short i;
			boolean d=false;
			short date = 0;
			Calendar exp = Calendar.getInstance();
			for(i=0;i<buf[ISO7816.OFFSET_LC];i++)
			{
				short nib = (short)((short)(buf[ISO7816.OFFSET_CDATA+i]&0xFF)>>4);
				if(!d)
				{
					if(nib==0xd)
						d=true;
					else
					{
						nib+=0x30;
						pan+=(char)(nib);
					}
				}
				else 
				{
					date++;
					if(date==1 || date==3)
						num=(int)nib;
					if(date==2)
					{
						num=nib+num*10+2000;
						exp.set(Calendar.YEAR, num);
					}
					if(date==4)
					{
						num=nib+num*10;
						exp.set(Calendar.MONTH, num-1);
					}
					if(date==4)
						break;
				}
				nib = (short)(buf[ISO7816.OFFSET_CDATA+i]&0xF);
				if(!d)
				{
					if(nib==0xd)
						d=true;
					else
					{
						nib+=0x30;
						pan+=(char)(nib);
					}
				}
				else 
				{
					date++;
					d = true;
					if(date==1 || date==3)
						num=(int)nib;
					if(date==2)
					{
						num=nib+num*10+2000;
						exp.set(Calendar.YEAR, num);
					}
					if(date==4)
					{
						num=nib+num*10;
						exp.set(Calendar.MONTH, num-1);
					}
					if(date==4)
						break;
				}
			}
			try {
				setStatePerso();
				setStatePersonalized(pan, exp, "", "");
			} catch (IOException e) {
			}
			//store the data into the RR
			RR = new byte[((buf[ISO7816.OFFSET_LC]&0xFF)+4)];
			buf[0] = 0x70;
			buf[1] = (byte)(2 + (short)(buf[ISO7816.OFFSET_LC]&0xFF));
			buf[2] = 0x57;
			buf[3] = (byte)((short)(buf[ISO7816.OFFSET_LC]&0xFF));
			Util.arrayCopy(buf,ISO7816.OFFSET_CDATA,buf,(short)4,(short)(buf[ISO7816.OFFSET_LC]&0xFF));
			Util.arrayCopy(buf,(short)0,RR,(short)0,(short)RR.length);
			STATE = ALIVE;
			break;
		case (byte) 0xB2: //read record
			//verify that the class for this instruction is correct
			if((short)(buf[ISO7816.OFFSET_CLA] & 0xFF) != 0x00)
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			//check state - this command only works in selected state
			if(state != selected)
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			//check that P1 & P2 are correct
			if(buf[ISO7816.OFFSET_P1] != (byte) 0x01 || buf[ISO7816.OFFSET_P2] != (byte) 0x0C)
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			//check that LC is 0x02
			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != (short) 0x00)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			//get the rest of the apdu and check length
			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != apdu.setIncomingAndReceive())
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			for(i=0;i<RR.length;i++)
				buf[i] = RR[i];
			apdu.setOutgoingAndSend((short)0,(short)RR.length);
			break;

		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}
