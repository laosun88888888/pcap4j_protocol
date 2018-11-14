package com.base.pacp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

public class TcpStream {

	private String server = "";
	private String client = "";
	boolean iDestroy = false;
	
	private int serverAck=0;
	private int clientAck=0;
	
	private ProtocolListener listener = new TLSProtocolListener();
	private HashMap<String,LinkedList<TcpPacket>> ackSendBuffer=new HashMap<String,LinkedList<TcpPacket>>();
	private HashMap<String,LinkedList<TcpPacket>> ackRecvBuffer=new HashMap<String,LinkedList<TcpPacket>>();
	private HashMap<String,TcpPacket> sendpacketBuffer=new HashMap<String,TcpPacket>();
	private HashMap<String,TcpPacket> recvpacketBuffer=new HashMap<String,TcpPacket>();
	
	public TcpStream(String server,String client)
	{
		this.server = server;
		this.client = client;
	}
	
	public void gotPacket(Packet packet)
	{
		TcpPacket tcppacket =packet.getBuilder().getPayloadBuilder().build().get(TcpPacket.class);
		IpV4Packet ip4packet =packet.get(IpV4Packet.class);
		boolean isSend = false;
		
		if(ip4packet.getHeader().getDstAddr().toString().contains(server))
		{
			isSend = true;
		}else
		{
			isSend = false;
		}
		
		int dataSize = tcppacket.getRawData().length - tcppacket.getHeader().getRawData().length;
		//String ackSeq = Long.toString(tcppacket.getHeader().getAcknowledgmentNumberAsLong());
		String ackSeq = "";
		
			long nextAcKSeq = tcppacket.getHeader().getSequenceNumberAsLong();
			nextAcKSeq = dataSize==0?nextAcKSeq+1:nextAcKSeq+dataSize;
			if(isSend)
			{
				
				sendpacketBuffer.put(Long.toString(nextAcKSeq), tcppacket);
				if(tcppacket.getHeader().getAck())
				{
					ackSeq = Long.toString(tcppacket.getHeader().getAcknowledgmentNumberAsLong());
					tcppacket = recvpacketBuffer.get(ackSeq);
					
					if(tcppacket==null) return;
					
					recvpacketBuffer.remove(ackSeq);
						
					ackSeq =Long.toString(tcppacket.getHeader().getAcknowledgmentNumberAsLong());
					dataSize = tcppacket.getRawData().length - tcppacket.getHeader().getRawData().length;
				}else
				{
					return;
				}
				LinkedList<TcpPacket> ps= ackRecvBuffer.get(ackSeq);
				if(ps == null)
				{
					ps = new LinkedList<TcpPacket>();
					ackRecvBuffer.put(ackSeq, ps);
				}
				ps.add(tcppacket);
				System.out.println("onAckRecv:"+dataSize+" seq="+tcppacket.getHeader().getSequenceNumberAsLong()+" ackseq="+tcppacket.getHeader().getAcknowledgmentNumberAsLong()+" "+tcppacket.getHeader().getPsh() );
			}else
			{
				recvpacketBuffer.put(Long.toString(nextAcKSeq), tcppacket);
				
				if(tcppacket.getHeader().getAck())
				{
					ackSeq = Long.toString(tcppacket.getHeader().getAcknowledgmentNumberAsLong());
					tcppacket = sendpacketBuffer.get(ackSeq);
					
					if(tcppacket==null) return;
					
					sendpacketBuffer.remove(ackSeq);
						
					ackSeq =Long.toString(tcppacket.getHeader().getAcknowledgmentNumberAsLong());
					dataSize = tcppacket.getRawData().length - tcppacket.getHeader().getRawData().length;
				}else
				{
					return;
				}
				LinkedList<TcpPacket> ps= ackSendBuffer.get(ackSeq);
				if(ps == null)
				{
					ps = new LinkedList<TcpPacket>();
					ackSendBuffer.put(ackSeq, ps);
				}
				ps.add(tcppacket);
				System.out.println("onAckSend:"+dataSize+" seq="+tcppacket.getHeader().getSequenceNumberAsLong()+" ackseq="+tcppacket.getHeader().getAcknowledgmentNumberAsLong()+" "+tcppacket.getHeader().getPsh() );
			}
//			if(dataSize>0)
//			{
//		}

		if(tcppacket.getHeader().getPsh())
		{
			if(!isSend)
			{
				int sendCount = tcppacket.getHeader().getSequenceNumber()-
						ackSendBuffer.get(ackSeq).getFirst().getHeader().getSequenceNumber()+
						tcppacket.getRawData().length-tcppacket.getHeader().getRawData().length;
				byte[] buffer = new byte[sendCount];
				int pos = 0;
				for(TcpPacket p:ackSendBuffer.get(ackSeq))
				{
					int packdatalength = p.getRawData().length-p.getHeader().getRawData().length;
					if(packdatalength==0) continue;
					System.arraycopy(p.getRawData(),p.getHeader().getRawData().length,buffer,pos,packdatalength);
					pos += packdatalength;
				}
				this.listener.onSend(ackSeq,buffer);
				buffer = null;
				ackSendBuffer.remove(ackSeq);
			}else
			{
				int recvCount = tcppacket.getHeader().getSequenceNumber()-
						ackRecvBuffer.get(ackSeq).getFirst().getHeader().getSequenceNumber()+
						tcppacket.getRawData().length-tcppacket.getHeader().getRawData().length;
				byte[] buffer = new byte[recvCount];
				int pos = 0;
				for(TcpPacket p:ackRecvBuffer.get(ackSeq))
				{
					int packdatalength = p.getRawData().length-p.getHeader().getRawData().length;
					if(packdatalength==0) continue;
					System.arraycopy(p.getRawData(),p.getHeader().getRawData().length,buffer,pos,packdatalength);
					pos += packdatalength;
				}
				this.listener.onRecv(ackSeq,buffer);
				buffer = null;
				ackRecvBuffer.remove(ackSeq);
			}
			
		}
		if(tcppacket.getHeader().getFin())
		{
			iDestroy = true;
		}
	}
	
	public boolean enDestroy()
	{
		return iDestroy;
	}
}
