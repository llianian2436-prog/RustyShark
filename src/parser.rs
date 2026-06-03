use crate::error::SnifferError;

// 定义解析后的结构化数据
#[derive(Debug)]
pub struct EthernetFrame<'a> {
    pub src_mac: String,
    pub dest_mac: String,
    pub payload: IpProtocol<'a>,
}

#[derive(Debug)]
pub enum IpProtocol<'a> {
    Ipv4(Ipv4Packet<'a>),
    Unknown,
}

#[derive(Debug)]
pub struct Ipv4Packet<'a> {
    pub src_ip: String,
    pub dest_ip: String,
    pub protocol: u8, // 6 代表 TCP, 17 代表 UDP
    pub payload: &'a [u8],
}

// 格式化 MAC 地址
fn format_mac(bytes: &[u8; 6]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(":")
}

// 解析以太网帧
pub fn parse_ethernet(packet_data: &[u8]) -> Result<EthernetFrame, SnifferError> {
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
fn parse_ipv4(data: &[u8]) -> Result<Ipv4Packet, SnifferError> {
    if data.len() < 20 {
        return Err(SnifferError::InvalidLength);
    }

    let protocol = data[9];
    let src_ip = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
    let dest_ip = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);
    
    // IHL (Internet Header Length) 确定 IP 首部长度
    let ihl = (data[0] & 0x0F) as usize * 4;
    if data.len() < ihl {
        return Err(SnifferError::InvalidLength);
    }

    Ok(Ipv4Packet {
        src_ip,
        dest_ip,
        protocol,
        payload: &data[ihl..], // 借用生命周期，零拷贝
    })
}