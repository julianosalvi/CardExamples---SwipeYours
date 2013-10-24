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
	private final static byte sendingAcApdu = 0x03;
	private final static byte sendingSelectApdu = 0x04;
	private final static byte sendingApdu = 0x05;
	private final static byte RR = 0x00;
	private final static byte GPO = 0x01;
	transient boolean selected = false;
	transient boolean transactionFailed = false;
	transient byte state = sentApdu;
	transient Thread tLoadCache = null;
	transient Thread connectTimer = null;
	

	private Cache cache = new Cache();
	
	public CardAgent() {
		allowSoftTransactions();
		allowNfcTransactions();
		denySocketTransactions();
	}
	
	public static void install(CardAgentConnector cardAgentConnector) {
		new CardAgent().register(cardAgentConnector);
	}

	private void loadLocalCache()
	{
		//add static cmd/rsp if needed
		if(cache.getRsp(new byte[]{0x00,(byte)0xA4,0x04,0x00,0x05,(byte)0x32,0x50,0x41,0x59,(byte)0x2E})==null)
			cache.addCmd(	new byte[]{0x00,(byte)0xA4,0x04,0x00,0x05,(byte)0x32,0x50,0x41,0x59,(byte)0x2E}, 
							new byte[]{0x6F, 0x23, (byte)0x84, 0x0E, 0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46,   
				    			0x30, 0x31, (byte)0xA5, 0x11, (byte)0xBF, 0x0C, 0x0E, 0x61, 0x0C, 0x4F, 0x07, (byte)0xA0, 0x00, 0x00, 0x00, 0x04,   
				    			0x10, 0x10, (byte)0x87, 0x01, 0x01});  //PPSE
	}
	
	private void loadCache(final byte[] apduc, final byte flag)
	{
		
		if(tLoadCache!=null)
			return;
		
		tLoadCache = new Thread(new Runnable(){
			
			public void run()
			{
				//create a cache from data
				TransceiveData apdus = new TransceiveData(TransceiveData.NFC_CHANNEL);
				apdus.setTimeout((short)5000);
				
				//read record cache!
				boolean rrCache = true;
				if(flag==GPO || flag==RR)
				{
					if(flag==GPO)
						apdus.packApdu(apduc, false);
					if(	cache.getRsp(new byte[]{0x00,(byte)0xB2,0x01,0x0C,0x00})==null) 
					{
						rrCache = false;
						apdus.packApdu(new byte[]{0x00,(byte)0xB2,0x01,0x0C,0x00}, true);
					}
				}
				
				try {
					transceive(apdus);
				} catch (IOException e) {
					tLoadCache = null;
					return;
				}
				if(rrCache && (flag==GPO || flag==RR))
				{
					tLoadCache = null;
					return;
				}
				
				for(short i=0;i<1;i++)
				{
					byte[] rsp = apdus.getNextResponse();
					if(rsp==null || rsp.length<2)
						continue;
					else if((short)(rsp[rsp.length-2]&0xFF)!=(short)(0x90&0xFF) || rsp[rsp.length-1]!=0x00)
						continue;
					
					//don't store the SW in the cache
					byte[] tmp = new byte[rsp.length-2];
					for(short j=0;j<tmp.length;j++)
						tmp[j] = rsp[j];
					rsp = tmp;
						
					byte[] cmd = null;
					if(i==0)
						cmd = new byte[]{0x00,(byte)0xB2,0x01,0x0C,0x00};
					cache.addCmd(cmd, rsp);
				}
				tLoadCache=null;
			}
		});
		
		tLoadCache.start();
	}
	
	@Override
	public void create() {
	}

	@Override
	public void activated(){ //this happens when the card is activated
		try {
			setBusy();
			connect();
		} catch (IOException e) {
			try {
				clearBusy();
				postMessage("No Connection Available!",false,null);
				deactivate();
			} catch (IOException e1) {
			}
			return;
		}
		connectTimer = new Thread(new Runnable() {
			@Override
			public void run() {
				try {
					Thread.sleep(120000);
				} catch (InterruptedException e) {
				}
				try {
					disconnect();
				} catch (IOException e) {
				}
				connectTimer = null;
			}});
		connectTimer.start();
		
		try {
			clearBusy();
		} catch (IOException e) {
		}
	}

	@Override
	public void deactivated(){ //this happens when the card is deactivated
		if(connectTimer!=null)
			connectTimer.interrupt();
		try {
			disconnect();
		} catch (IOException e) {
		}
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
		//update the state of the class
		try {
			saveState();
		} catch (IOException e1) {
		}
	}
	
	@Override
	public void sentApdu()
	{
		switch(state)
		{
		case sendingAcApdu:
			selected = false;
			break;
		case sendingGpoApdu:
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

	private byte[] queryCache(APDU apdu, short len)
	{
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
		return rsp;
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

		//respond to this APDU-C
		switch(apdu.getBuffer()[ISO7816.OFFSET_INS])
		{
		case (byte) 0xA4:  //select
			if(apdu.getBuffer()[ISO7816.OFFSET_LC]>4 && apdu.getBuffer()[ISO7816.OFFSET_LC+1]==(byte)0xA0 &&
					apdu.getBuffer()[ISO7816.OFFSET_LC+2]==(byte)0x00 && apdu.getBuffer()[ISO7816.OFFSET_LC+3]==(byte)0x00 && 
					apdu.getBuffer()[ISO7816.OFFSET_LC+4]==(byte)0x00 && apdu.getBuffer()[ISO7816.OFFSET_LC+5]==(byte)0x04)
			{
				byte[] cmd = new byte[len];
				for(short i=0;i<len;i++)
					cmd[i] = apdu.getBuffer()[i];
				try {
					connect();
					TransceiveData reset = new TransceiveData(TransceiveData.NFC_CHANNEL);
					reset.packCardReset(false);
					byte[] rsp = cache.getRsp(cmd);
					if(rsp==null)
					{
						reset.packApdu(cmd, true);
						try{
							transceive(reset);
							rsp = reset.getNextResponse();
							if(rsp!=null && rsp.length>1 && (short)(rsp[rsp.length-2]&0xFF)==(short)(0x90&0xFF) && rsp[rsp.length-1]==0x00)
							{
								//don't store the SW in the cache
								byte[] tmp = new byte[rsp.length-2];
								for(short j=0;j<tmp.length;j++)
									tmp[j] = rsp[j];
								rsp = tmp;
								cache.addCmd(	new byte[]{0x00,(byte)0xA4,0x04,0x00,0x05,(byte)0xA0,0x00,0x00,0x00,0x04}, 
												rsp);  //AID
							}
						} catch (IOException e){
						}
					}
					else
					{
						reset.packApdu(cmd, false);
						try {
							transceive(reset);
						} catch (IOException e){
						}
					}
				} catch (IOException e) {
					if(e.getMessage().equals("ALREADY_CONNECTED"))
					{
						TransceiveData reset = new TransceiveData(TransceiveData.NFC_CHANNEL);
						reset.packCardReset(false);
						byte[] rsp = cache.getRsp(cmd);
						if(rsp==null)
						{
							reset.packApdu(cmd, true);
							try {
								transceive(reset);
								rsp = reset.getNextResponse();
								if(rsp!=null && rsp.length>1 && (short)(rsp[rsp.length-2]&0xFF)==(short)(0x90&0xFF) && rsp[rsp.length-1]==0x00)
								{
									//don't store the SW in the cache
									byte[] tmp = new byte[rsp.length-2];
									for(short j=0;j<tmp.length;j++)
										tmp[j] = rsp[j];
									rsp = tmp;
									cache.addCmd(	new byte[]{0x00,(byte)0xA4,0x04,0x00,0x05,(byte)0xA0,0x00,0x00,0x00,0x04}, 
													rsp);  //AID
								}
							} catch (IOException e1) {
							}
						}
						else
						{
							reset.packApdu(cmd, false);
							try {
								transceive(reset);
							} catch (IOException e1) {
							}
						}
					}
				}
				selected = true;
			}
			else
				selected = false;
			loadLocalCache();		
			byte[] rsp = queryCache(apdu,len);
			for(short i=0;i<rsp.length;i++)
				apdu.getBuffer()[i] = rsp[i];
			state = sendingSelectApdu;
			apdu.setOutgoingAndSend((short)0, (short)rsp.length);
			break;
		case (byte) 0xA8:  //gpo
			if(selected)
			{
				byte[] cmd = new byte[len];
				for(short i=0;i<len;i++)
					cmd[i] = apdu.getBuffer()[i];
				rsp = cache.getRsp(cmd);
				if(rsp==null)
				{
					TransceiveData gpo = new TransceiveData(TransceiveData.NFC_CHANNEL);
					gpo.packApdu(cmd, true);
					try {
						transceive(gpo);
						
						rsp = gpo.getNextResponse();
						if(rsp!=null && rsp.length>1 && (short)(rsp[rsp.length-2]&0xFF)==(short)(0x90&0xFF) && rsp[rsp.length-1]==0x00)
						{
							//don't store the SW in the cache
							byte[] tmp = new byte[rsp.length-2];
							for(short j=0;j<tmp.length;j++)
								tmp[j] = rsp[j];
							rsp = tmp;
							cache.addCmd(	new byte[]{(byte)0x80,(byte)0xA8,0x00,0x00,0x00}, 
											rsp);  //GPO
						}
						loadCache(cmd,RR);
					} catch (IOException e) {
					}
				}
				else
				{
					loadCache(cmd,GPO);
				}
				rsp = queryCache(apdu,len);
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
				byte[] cmd = new byte[len];
				for(short i=0;i<len;i++)
					cmd[i] = apdu.getBuffer()[i];
				rsp  = cache.getRsp(cmd);
				while(rsp==null && tLoadCache!=null)
				{
					try {
						Thread.sleep(1);
					} catch (InterruptedException e) {
					}
				}
				rsp = queryCache(apdu,len);
				for(short i=0;i<rsp.length;i++)
					apdu.getBuffer()[i] = rsp[i];
				state = sendingRrApdu;  
				apdu.setOutgoingAndSend((short)0, (short)rsp.length);
			}
			else
				sendApduCFailure();
			break;
		case (byte) 0x2A:  //application cryptogram
			if(selected)
			{
				while(tLoadCache!=null)
				{
					try {
						Thread.sleep(1);
					} catch (InterruptedException e) {
					}
				}
				byte[] cmd = new byte[len];
				for(short i=0;i<len;i++)
					cmd[i] = apdu.getBuffer()[i];

				TransceiveData genAc = new TransceiveData(TransceiveData.NFC_CHANNEL);
				genAc.packApdu(cmd, true);
				try {
					transceive(genAc);
				} catch (IOException e){
				}
				rsp = genAc.getNextResponse();
				if(rsp!=null && rsp.length>1 && (short)(rsp[rsp.length-2]&0xFF)==(short)(0x90&0xFF) && rsp[rsp.length-1]==0x00)
				{
					//don't store the SW in the cache
					byte[] tmp = new byte[rsp.length-2];
					for(short j=0;j<tmp.length;j++)
						tmp[j] = rsp[j];
					rsp = tmp;
				}
				else
					sendApduCFailure();
				
				for(short i=0;i<rsp.length;i++)
					apdu.getBuffer()[i] = rsp[i];
				state = sendingAcApdu;  //success triggers a successful transaction
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
