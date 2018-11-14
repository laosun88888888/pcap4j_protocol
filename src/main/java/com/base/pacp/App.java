package com.base.pacp;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapIpV4Address;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

public class App 
{
	private static final int PORT = 9123;
	
	static String client ="";
	static HashMap<String, TcpStream> tcpStreamList=new HashMap<String, TcpStream>();
	
    /** 
     * @param args 
     * @throws IOException  
     */  
    public static void main(String[] args) { 
    	 
    	try {
			test1();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    static void test1() throws PcapNativeException, NotOpenException, InterruptedException
    {
    	int tagnetwork = 0;
    	// 获取所有网卡设备
        List<PcapNetworkInterface> alldev = Pcaps.findAllDevs();
        System.out.println("asdk");
        // 根据设备名称初始化抓包接口
        PcapNetworkInterface nif = Pcaps.getDevByName(alldev.get(tagnetwork).getName());
        for(PcapAddress a:nif.getAddresses())
        {
        	if(a instanceof PcapIpV4Address)
        	{
        		client = a.getAddress().toString();
        		break;
        	}
        }
        if(client.equals(""))
        {
        	return;
        }
        // 抓取包长度
        int snaplen = 64 * 1024;
        // 超时50ms
        int timeout = 50;
        // 初始化抓包器
        PcapHandle.Builder phb = new PcapHandle.Builder(nif.getName()).snaplen(snaplen)
            .promiscuousMode(PromiscuousMode.PROMISCUOUS).timeoutMillis(timeout)
            .bufferSize(1 * 1024 * 1024);
        PcapHandle handle = phb.build();
        // handle = nif.openLive(snaplen, PromiscuousMode.NONPROMISCUOUS, timeout);

        /** 设置TCP过滤规则 */
        String filter = "ip and tcp and (port 443)";
        //String filter = "http.host  wx.qq.com";
        
            
        // 设置过滤器
        handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
        
      //初始化listener
        PacketListener listener = new PacketListener() {
        	
            public void gotPacket(Packet packet) {
            	
            	TcpPacket tcppacket =packet.getBuilder().getPayloadBuilder().build().get(TcpPacket.class);
    			IpV4Packet ip4packet =packet.get(IpV4Packet.class);
    			
    			String server = "";
    			String serverPort ="";
    			if(ip4packet.getHeader().getDstAddr().toString().contains(client))
    			{
    				server=ip4packet.getHeader().getSrcAddr().toString();
    				serverPort = tcppacket.getHeader().getSrcPort().valueAsString();
    				
    			}else if(ip4packet.getHeader().getSrcAddr().toString().contains(client))
    			{
    				server=ip4packet.getHeader().getDstAddr().toString();
    				serverPort = tcppacket.getHeader().getDstPort().valueAsString();
    			}else
    			{
    				return;
    			}
    			
    			TcpStream tps =null;
            	if(tcpStreamList.get(server+serverPort) == null)
            	{
            		tps= new TcpStream(server,client);
            		tcpStreamList.put(server+serverPort, tps);
            		tps.gotPacket(packet);

            	}else
            	{
            		tps = tcpStreamList.get(server+serverPort);
            		tps.gotPacket(packet);
            	}
            	
            	if(tps.enDestroy())
            	{
            		tps = null;
            		tcpStreamList.put(server+serverPort, tps);
            		tcpStreamList.remove(server+serverPort);
            		
            	}
            	
//            	TcpPacket tcppacket =packet.getBuilder().getPayloadBuilder().build().get(TcpPacket.class);
//    			IpV4Packet ip4packet =packet.get(IpV4Packet.class);
//    			//System.out.println(packet);
//    			String s = "";
//    			try {
//    				String key = ip4packet.getHeader().getDstAddr().toString()+":"+ tcppacket.getHeader().getDstPort() +"<-"+ip4packet.getHeader().getSrcAddr().toString()+tcppacket.getHeader().getSrcPort();
//    				List<TcpPacket> plist = packetlist.get(key);
//    				if(plist == null)
//    				{
//    					plist = new LinkedList<TcpPacket>(); 
//    				}
//    				plist.add(tcppacket);
//    				int count = 0;
//    				if(packetdataCount.get(key)==null)
//    				{
//    				  count = tcppacket.getRawData().length-tcppacket.getHeader().getRawData().length;
//    				}else
//    				{
//    					count = packetdataCount.get(key).intValue()+ tcppacket.getRawData().length-tcppacket.getHeader().getRawData().length;
//    				}
//    				packetdataCount.put(key,count);
//    				if(plist.size()>1)
//    				{
//    					int fistSeq = plist.get(0).getHeader().getSequenceNumber();
//    					int finSeq = tcppacket.getHeader().getSequenceNumber();
//    					if((finSeq-fistSeq) >count)
//    					{
//    						byte[] buffer = new byte[count];
//    						int src = 0;
//    						for(TcpPacket p:plist)
//    						{
//    							int packdatalength = p.getRawData().length-p.getHeader().getRawData().length;
//    							System.arraycopy(buffer,src,p.getRawData(),p.getHeader().getRawData().length,packdatalength);
//    							src += packdatalength;
//    						}
//    						s = new String(buffer);
//    	    				System.out.println("data:"+s);
//    					}
//    				}
//    				s = ip4packet.getHeader().getDstAddr().toString()+"<-"+ip4packet.getHeader().getSrcAddr().toString();
//    				System.out.println("ip4:"+s);
//    				s = ip4packet.getHeader().toString();
//    				System.out.println("ip4:"+s);
//    				s = tcppacket.getHeader().toString();
//    				System.out.println("tcp:"+s);
//    				String tcpHeader = new String(tcppacket.getHeader().getRawData(),"UTF-8");
//    				
//    				int offset=tcppacket.getHeader().getRawData().length;
//    				int length = tcppacket.getRawData().length;
//    				s = new String(tcppacket.getRawData(),offset,tcppacket.getRawData().length-offset,"UTF-8");
//    				if(!s.equals(""))
//    				{
//    					System.out.println("tcpHeader rawdata:"+tcpHeader);
//    					System.out.println("tcp rawdata:"+s);
//    				}
//    				
//    				
//    			} catch (Exception e) {
//    				// TODO Auto-generated catch block
//    				e.printStackTrace();
//    			}
                
            }

		
        };
        //直接使用loop
        handle.loop(1000000, listener);
    }
    
}
