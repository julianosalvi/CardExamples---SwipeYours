package com.simplytapp.cardagent;

import java.io.IOException;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import com.simplytapp.virtualcard.Agent;
import com.simplytapp.virtualcard.CardAgentConnector;
import com.simplytapp.virtualcard.TransceiveData;

public class CardAgent extends Agent {

	private static final long serialVersionUID = 1L;
	private final static byte sentApdu = 0x00;
	private final static byte sendingRrApdu = 0x01;
	private final static byte sendingGpoApdu = 0x02;
	private final static byte sendingSelectApdu = 0x03;
	private final static byte sendingApdu = 0x04;
	transient boolean selected = false;
	transient boolean transactionFailed = false;
	transient byte state = sentApdu;
	transient Thread tLoadCache = null;

	boolean newCache = false;
	Cache cache = null;
	
	public CardAgent() {
		allowSoftTransactions();
		allowNfcTransactions();
		denySocketTransactions();
	}
	
	public static void install(CardAgentConnector cardAgentConnector){
		new CardAgent().register(cardAgentConnector);
	}

	
	private void loadCache()
	{
		
		if(tLoadCache!=null)
			return;
		
		tLoadCache = new Thread(new Runnable(){
			
			public void run()
			{
				boolean busy = false;
				boolean connected = false;
				boolean doTransaction = false;
				try {
					doTransaction = getDoTransactionFlag();
				} catch (IOException e) {
				}
					
				if(doTransaction || cache==null)
				{
					cache = new Cache();
					//create a cache from data
					TransceiveData apdus = new TransceiveData(TransceiveData.NFC_CHANNEL);
					apdus.setTimeout((short)15000);
					apdus.packApdu(new byte[]{0x00,(byte)0xA4,0x04,0x00,0x0E,0x32,0x50,0x41,0x59,0x2E,0x53,0x59,0x53,0x2E,0x44,0x44,0x46,0x30,0x31,0x00}, true);
					apdus.packApdu(new byte[]{0x00,(byte)0xA4,0x04,0x00,0x07,(byte)0xA0,0x00,0x00,0x00,0x03,0x10,0x10,0x00}, true);
					apdus.packApdu(new byte[]{(byte)0x80,(byte)0xA8,0x00,0x00,0x04,(byte)0x83,0x02,(byte)0x80,0x00,0x00}, true);
					apdus.packApdu(new byte[]{0x00,(byte)0xB2,0x01,0x0C,0x00}, true);
					try {
						setBusy();
						busy = true;
						connect();
						connected = true;
						transceive(apdus);
						disconnect();
						connected = false;
						clearBusy();
						busy = false;
					} catch (IOException e) {
						if(connected)
						{
							try {
								disconnect();
								connected = false;
							} catch (IOException e1) {
							}
						}
						if(busy)
						{
							try {
								clearBusy();
								busy = false;
							} catch (IOException e1) {
							}
						}
						tLoadCache = null;
						try {Thread.sleep(2000);} catch (InterruptedException e1) {}
						cache=null;
						loadCache();
						return;
					}
		
					for(short i=0;i<4;i++)
					{
						byte[] rsp = apdus.getNextResponse();
						if(rsp==null || rsp.length<2)
							continue;
						else if(rsp[rsp.length-2]!=0x90 && rsp[rsp.length-1]!=0x00)
							continue;
									
						//don't store the SW in the cache
						byte[] tmp = new byte[rsp.length-2];
						for(short j=0;j<tmp.length;j++)
							tmp[j] = rsp[j];
						rsp = tmp;
							
						byte[] cmd = null;
						if(i==0)
							cmd = new byte[]{0x00,(byte)0xA4,0x04,0x00,0x05,0x32,0x50,0x41,0x59,0x2E};
						else if(i==1)
							cmd = new byte[]{0x00,(byte)0xA4,0x04,0x00,0x05,(byte)0xA0,0x00,0x00,0x00,0x03};
						else if(i==2)
							cmd = new byte[]{(byte)0x80,(byte)0xA8,0x00,0x00,0x00};
						else if(i==3)
							cmd = new byte[]{0x00,(byte)0xB2,0x01,0x0C,0x00};
						cache.addCmd(cmd, rsp);
					}
					try {
						if(getDoTransactionFlag())
							clearDoTransactionFlag();
					} catch (IOException e) {
					}
					//save the state of the class now
					try {
						saveState();
					} catch (IOException e1) {
					}
				}
				tLoadCache=null;
			}
		});
		
		tLoadCache.start();
	}
	
	@Override
	public void create() {
		loadCache();
	}

	@Override
	public void activated(){ //this happens when the card is activated
		if(cache==null)
			loadCache();
	}

	@Override
	public void deactivated(){ //this happens when the card is deactivated
	}
	
	@Override
	public void disconnected(){
	}

	@Override
	public void transactionStarted()
	{
	}
	
	@Override
	public void transactionFinished()
	{
		selected = false;
		state = sentApdu;
		transactionFailed = false;
		if(newCache)
		{
			newCache = false;
			cache = null;
			//update the state of the class
			try {
				saveState();
			} catch (IOException e1) {
			}
			try {
				setDoTransactionFlag();
			} catch (IOException e) {
			}
		}
		if(cache==null)
			loadCache();
	}
	
	@Override
	public void sentApdu()
	{
		switch(state)
		{
		case sendingRrApdu:
			selected = false;
			if(newCache)
			{
				newCache = false;
				cache = null;
				try {
					saveState();
				} catch (IOException e1) {
				}
				try {
					setDoTransactionFlag();
				} catch (IOException e) {
				}
			}
			break;
		case sendingGpoApdu:
			newCache = true;
			break;
		default:
			break;
		}
		state = sentApdu;
	}
	
	void sendApduCFailure() throws ISOException
	{
		state = sendingApdu;
		try {transactionFailure();} catch (IOException e) {}
		transactionFailed = true;
		throw new ISOException(ISO7816.SW_COMMAND_NOT_ALLOWED);
	}
	
	@Override
	public void process(APDU apdu) throws ISOException {
		
		while(state!=sentApdu)  //wait for previous one to complete (thread safe)
		{
			try {
				Thread.sleep(1);
			} catch (InterruptedException e) {
			}
			try {
				if(getTransactionFinished())
				{
					state = sendingApdu;
					throw new ISOException(ISO7816.SW_UNKNOWN);
				}
			} catch (IOException e) {
			}
		}
		
		if(transactionFailed)
		{
			state = sendingApdu;
			throw new ISOException(ISO7816.SW_UNKNOWN);
		}
		
		if((short)(APDU.getProtocol()&0xFF)!=(short)(0xFF&APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A) && 
				(short)(APDU.getProtocol()&0xFF)!=(short)(0xFF&APDU.PROTOCOL_MEDIA_SOCKET) && 
				(short)(APDU.getProtocol()&0xFF)!=(short)(0xFF&APDU.PROTOCOL_MEDIA_SOFT))
			sendApduCFailure();
		
		//receive APDU-C
		short len = apdu.setIncomingAndReceive();
		len+=5;
		
		//validate command format
		if((short)(apdu.getBuffer()[ISO7816.OFFSET_LC]&0xFF)+5!=len)
			throw new ISOException(ISO7816.SW_WRONG_LENGTH);

		//check the cache for a response
		byte[] cmd = new byte[len];
		for(short i=0;i<len;i++)
			cmd[i] = apdu.getBuffer()[i];
		byte[] rsp = null;
		if(cache!=null)
		{
			rsp = cache.getRsp(cmd);
			if(rsp==null)
				sendApduCFailure();
		}
		else
			sendApduCFailure();

		//respond to this APDU-C
		switch(apdu.getBuffer()[ISO7816.OFFSET_INS])
		{
		case (byte) 0xA4:  //select
			if(apdu.getBuffer()[ISO7816.OFFSET_LC]>4 && apdu.getBuffer()[ISO7816.OFFSET_LC+1]==(byte)0xA0 &&
					apdu.getBuffer()[ISO7816.OFFSET_LC+2]==(byte)0x00 && apdu.getBuffer()[ISO7816.OFFSET_LC+3]==(byte)0x00 && 
					apdu.getBuffer()[ISO7816.OFFSET_LC+4]==(byte)0x00 && apdu.getBuffer()[ISO7816.OFFSET_LC+5]==(byte)0x03)
				selected = true;
			else
				selected = false;
			for(short i=0;i<rsp.length;i++)
				apdu.getBuffer()[i] = rsp[i];
			state = sendingSelectApdu;
			apdu.setOutgoingAndSend((short)0, (short)rsp.length);
			break;
		case (byte) 0xA8:  //gpo
			if(selected)
			{
				for(short i=0;i<rsp.length;i++)
					apdu.getBuffer()[i] = rsp[i];
				state = sendingGpoApdu;  //success triggers cache clearing and get new cache after transaction is over
				apdu.setOutgoingAndSend((short)0, (short)rsp.length);
			}
			else
				sendApduCFailure();
			break;
		case (byte) 0xB2:  //read record
			if(selected)
			{
				for(short i=0;i<rsp.length;i++)
					apdu.getBuffer()[i] = rsp[i];
				state = sendingRrApdu;  //success triggers a successful transaction
				apdu.setTransactionSuccess();
				apdu.setOutgoingAndSend((short)0, (short)rsp.length);
			}
			else
				sendApduCFailure();
			break;
		default:
			sendApduCFailure();
		}
	}
}
