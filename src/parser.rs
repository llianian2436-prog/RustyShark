use crate::error::SnifferError;

// === 1. 数据链路层 (Layer 2) ===
#[derive(Debug)]
pub struct EthernetFrame<'a> {
    pub src_mac: String,
    pub dest_mac: String,
    pub payload: IpProtocol<'a>,
}

// === 2. 网络层 (Layer 3) ===
#[derive(Debug)]
pub enum IpProtocol<'a> {
    Ipv4(Ipv4Packet<'a>),
    Ipv6,         //  新增：精准识别内核放行的 IPv6 数据包
    Arp,          //  新增：局域网 ARP 寻址广播
    Unknown(u16), //  升级：未知协议直接把 2 字节的 EtherType 编码带出去
}

#[derive(Debug)]
pub struct Ipv4Packet<'a> {
    pub src_ip: String,
    pub dest_ip: String,
    pub protocol: u8, 
    pub transport: TransportProtocol<'a>, 
}

// === 3. 传输层 (Layer 4) ===
#[derive(Debug)]
pub enum TransportProtocol<'a> {
    Tcp(TcpHeader<'a>),
    Udp(UdpHeader<'a>),
    Unknown(&'a [u8]), 
}

#[derive(Debug)]
pub struct TcpHeader<'a> {
    pub src_port: u16,
    pub dest_port: u16,
    pub seq: u32,
    pub ack_num: u32,
    pub flags: TcpFlags,
    pub payload: &'a [u8], 
}

#[derive(Debug)]
pub struct UdpHeader<'a> {
    pub src_port: u16,
    pub dest_port: u16,
    pub len: u16,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

fn format_mac(bytes: &[u8; 6]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(":")
}

// 解析以太网帧
pub fn parse_ethernet(packet_data: &[u8]) -> Result<EthernetFrame<'_>, SnifferError> {
    if packet_data.len() < 14 {
        return Err(SnifferError::InvalidLength);
    }

    let mut dest_mac_bytes = [0u8; 6];
    let mut src_mac_bytes = [0u8; 6];
    dest_mac_bytes.copy_from_slice(&packet_data[0..6]);
    src_mac_bytes.copy_from_slice(&packet_data[6..12]);

    let ether_type = u16::from_be_bytes([packet_data[12], packet_data[13]]);

    //  核心升级：根据以太网规范，精准匹配上层身份证
    let payload = match ether_type {
        0x0800 => {
            match parse_ipv4(&packet_data[14..]) {
                Ok(ipv4) => IpProtocol::Ipv4(ipv4),
                Err(_) => IpProtocol::Unknown(0x0800),
            }
        },
        0x86DD => IpProtocol::Ipv6, // IPv6 身份证
        0x0806 => IpProtocol::Arp,  // ARP 身份证
        _ => IpProtocol::Unknown(ether_type), // 其它协议直接记录其 16 进制类型
    };

    Ok(EthernetFrame {
        src_mac: format_mac(&src_mac_bytes),
        dest_mac: format_mac(&dest_mac_bytes),
        payload,
    })
}

fn parse_ipv4(data: &[u8]) -> Result<Ipv4Packet<'_>, SnifferError> {
    if data.len() < 20 {
        return Err(SnifferError::InvalidLength);
    }

    let protocol = data[9];
    let src_ip = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
    let dest_ip = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);
    
    let ihl = (data[0] & 0x0F) as usize * 4;
    if data.len() < ihl {
        return Err(SnifferError::InvalidLength);
    }

    let raw_payload = &data[ihl..];

    let transport = match protocol {
        6 => parse_tcp(raw_payload).unwrap_or(TransportProtocol::Unknown(raw_payload)),
        17 => parse_udp(raw_payload).unwrap_or(TransportProtocol::Unknown(raw_payload)),
        _ => TransportProtocol::Unknown(raw_payload),
    };

    Ok(Ipv4Packet {
        src_ip,
        dest_ip,
        protocol,
        transport,
    })
}

fn parse_tcp(data: &[u8]) -> Result<TransportProtocol<'_>, SnifferError> {
    if data.len() < 20 {
        return Err(SnifferError::InvalidLength);
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dest_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    let data_offset = ((data[12] >> 4) & 0x0F) as usize * 4;
    if data.len() < data_offset {
        return Err(SnifferError::InvalidLength);
    }

    let flags_byte = data[13];
    let flags = TcpFlags {
        fin: (flags_byte & 0x01) != 0,
        syn: (flags_byte & 0x02) != 0,
        rst: (flags_byte & 0x04) != 0,
        psh: (flags_byte & 0x08) != 0,
        ack: (flags_byte & 0x10) != 0,
        urg: (flags_byte & 0x20) != 0,
    };

    let payload = &data[data_offset..];

    Ok(TransportProtocol::Tcp(TcpHeader {
        src_port,
        dest_port,
        seq,
        ack_num,
        flags,
        payload,
    }))
}

fn parse_udp(data: &[u8]) -> Result<TransportProtocol<'_>, SnifferError> {
    if data.len() < 8 {
        return Err(SnifferError::InvalidLength);
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dest_port = u16::from_be_bytes([data[2], data[3]]);
    let len = u16::from_be_bytes([data[4], data[5]]);
    
    let payload = if data.len() >= 8 { &data[8..] } else { &[] };

    Ok(TransportProtocol::Udp(UdpHeader {
        src_port,
        dest_port,
        len,
        payload,
    }))
}