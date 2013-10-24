package com.simplytapp.cardagent;

import java.io.Serializable;

public class Cache implements Serializable {
	private static final long serialVersionUID = 1L;
	CmdRsp[] cmdRsp = null;
		
	void rmCmdRsp(short index)
	{
		CmdRsp[] tmp=null;
		for(short i=0;i<cmdRsp.length;i++)
			if(i==index)
			{
				tmp = new CmdRsp[cmdRsp.length-1];
				break;
			}
		if(tmp!=null)
		{
			short j=0;
			for(short i=0;i<cmdRsp.length;i++)
				if(i!=index)
					tmp[j++] = cmdRsp[i];
			cmdRsp = tmp;
		}
	}
		
	short getMatchIndex(byte[] cmd)
	{
		if(cmdRsp==null)
			return -1;
		//check for match in cache for any command
		for(short i=0;i<cmdRsp.length;i++)
		{
			if(cmd!=null && cmd.length>4 && cmdRsp[i].cmd.length>1 && cmd[1] == cmdRsp[i].cmd[1] && 
						(short)(cmd[4]&0xff)+5<=cmd.length && 
						cmdRsp[i].cmd.length<=cmd.length)
			{
				//command code is the same...now compare content
				short j=0;
				short len = (short)cmdRsp[i].cmd.length;
				if(cmdRsp[i].cmd.length>4 && len>((short)(cmdRsp[i].cmd[4]&0xFF)+5))
					len=(short)(5+(short)(cmdRsp[i].cmd[4]&0xFF));
				for(j=0;j<len;j++)
				{
					if(j!=4 && cmd[j]!=cmdRsp[i].cmd[j])  //ignore length byte
						break;
				}
				if(j==len)
				{
					//match!
					return i;
				}
			}
		}
		return -1;
	}
		
	void addCmd(byte[] cmd, byte[] rsp)
	{
		if(cmd==null || rsp==null)
			return;
		short i = getMatchIndex(cmd);
		if(i>-1)
		{
			rmCmdRsp(i);
		}
		if(cmdRsp==null)
			cmdRsp = new CmdRsp[0];
		CmdRsp[] tmp = new CmdRsp[cmdRsp.length+1];
		for(i=0;i<cmdRsp.length;i++)
			tmp[i]=cmdRsp[i];
		tmp[i] = new CmdRsp(cmd,rsp);
		cmdRsp = tmp;
	}
		
	byte[] getRsp(byte[] cmd)
	{
		short i = getMatchIndex(cmd);
		if(i>-1 && i<cmdRsp.length)
			return cmdRsp[i].rsp;
		else
			return null;
	}

}
