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
    Unknown,
}

#[derive(Debug)]
pub struct Ipv4Packet<'a> {
    pub src_ip: String,
    pub dest_ip: String,
    pub protocol: u8, 
    pub transport: TransportProtocol<'a>, // 升级：不再是盲目的 payload，而是解析后的传输层
}

// === 3. 传输层 (Layer 4) ===
#[derive(Debug)]
pub enum TransportProtocol<'a> {
    Tcp(TcpHeader<'a>),
    Udp(UdpHeader<'a>),
    Unknown(&'a [u8]), // 如果是 ICMP 或其他协议，暂时保留原始字节
}

#[derive(Debug)]
pub struct TcpHeader<'a> {
    pub src_port: u16,
    pub dest_port: u16,
    pub seq: u32,
    pub ack_num: u32,
    pub flags: TcpFlags,
    pub payload: &'a [u8], // TCP 携带的应用层数据 (如 HTTP 报文)
}

#[derive(Debug)]
pub struct UdpHeader<'a> {
    pub src_port: u16,
    pub dest_port: u16,
    pub len: u16,
    pub payload: &'a [u8],
}

// TCP 核心标志位（大作业的高分秀点）
#[derive(Debug, Clone, Copy)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

// 格式化 MAC 地址
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

    let payload = match ether_type {
        0x0800 => {
            match parse_ipv4(&packet_data[14..]) {
                Ok(ipv4) => IpProtocol::Ipv4(ipv4),
                Err(_) => IpProtocol::Unknown,
            }
        },
        _ => IpProtocol::Unknown,
    };

    Ok(EthernetFrame {
        src_mac: format_mac(&src_mac_bytes),
        dest_mac: format_mac(&dest_mac_bytes),
        payload,
    })
}

// 解析 IPv4 报文
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

    // 根据 IP 首部的 protocol 字段，无缝递进解析传输层
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

// 核心新增：深度解构 TCP 首部
fn parse_tcp(data: &[u8]) -> Result<TransportProtocol<'_>, SnifferError> {
    if data.len() < 20 {
        return Err(SnifferError::InvalidLength);
    }

    // 1. 提取端口 (大端序前2字节和后2字节)
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dest_port = u16::from_be_bytes([data[2], data[3]]);

    // 2. 提取序号和确认号 (u32)
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    // 3. 计算 TCP 首部长度 (Data Offset 在第12字节的高4位)
    let data_offset = ((data[12] >> 4) & 0x0F) as usize * 4;
    if data.len() < data_offset {
        return Err(SnifferError::InvalidLength);
    }

    // 4. 利用位运算解剖第13字节的 Flags 标志位
    let flags_byte = data[13];
    let flags = TcpFlags {
        fin: (flags_byte & 0x01) != 0,
        syn: (flags_byte & 0x02) != 0,
        rst: (flags_byte & 0x04) != 0,
        psh: (flags_byte & 0x08) != 0,
        ack: (flags_byte & 0x10) != 0,
        urg: (flags_byte & 0x20) != 0,
    };

    // 5. 切割出应用层载荷
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

// 核心新增：深度解构 UDP 首部
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