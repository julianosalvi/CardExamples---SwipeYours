package com.simplytapp.cardagent;

import java.io.Serializable;

class CmdRsp implements Serializable {
	private static final long serialVersionUID = 1L;
	byte[] cmd = null;
	byte[] rsp = null;
	
	CmdRsp(byte[] cmd, byte[] rsp)
	{
		this.cmd = cmd;
		this.rsp = rsp;
	}
}
