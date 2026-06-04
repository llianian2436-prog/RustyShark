mod error;
mod parser;
mod capture;

use tokio::sync::mpsc;
use pcap::Device;
use std::io::{self, Write};

#[tokio::main]
async fn main() {
    println!("=== RustyShark 深度解析版启动 ===");

    // 1. 列出系统所有可用网卡
    let devices = Device::list().expect("无法获取网卡列表");
    println!("可用网卡列表:");
    for (i, d) in devices.iter().enumerate() {
        println!("[{}] 名字: {} | 描述: {:?}", i, d.name, d.desc);
    }

    if devices.is_empty() {
        println!("未找到任何网卡，程序退出。");
        return;
    }

    // 2. 交互式选择网卡
    print!("\n请选择要抓包的网卡编号 (默认 0): ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("读取输入失败");
    
    let choice: usize = input.trim().parse().unwrap_or(0);
    let index = if choice < devices.len() { choice } else { 0 };

    let target_device = &devices[index].name;
    println!("成功选中网卡: {}", target_device);

    // 3. 创建异步通道
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);

    // 4. 启动后台抓包
    if let Err(e) = capture::CaptureEngine::start_capture(target_device, tx) {
        eprintln!("启动抓包失败: {:?}", e);
        return;
    }

    println!("[Main] 正在等待接收并解析网络数据包...\n");
    let mut packet_count = 0;

    // 5. 核心循环：接收并展示套娃协议
    while let Some(raw_data) = rx.recv().await {
        packet_count += 1;
        println!("--------------------------------------------------");
        println!("收到第 {} 个原始数据包, 长度: {} 字节", packet_count, raw_data.len());

        match parser::parse_ethernet(&raw_data) {
            Ok(frame) => {
                println!("  [Layer 2] MAC: {} -> {}", frame.src_mac, frame.dest_mac);
                
                match frame.payload {
                    parser::IpProtocol::Ipv4(ip) => {
                        println!("  [Layer 3] IPv4: {} -> {}", ip.src_ip, ip.dest_ip);
                        
                        // 🌟 炫技高光：优雅地匹配传输层
                        match ip.transport {
                            parser::TransportProtocol::Tcp(tcp) => {
                                // 拼接出可读性极强的 Flags 字符串
                                let mut f_str = Vec::new();
                                if tcp.flags.syn { f_str.push("SYN"); }
                                if tcp.flags.ack { f_str.push("ACK"); }
                                if tcp.flags.fin { f_str.push("FIN"); }
                                if tcp.flags.rst { f_str.push("RST"); }
                                if tcp.flags.psh { f_str.push("PSH"); }
                                
                                println!("  [Layer 4] TCP 端口: {} -> {} | Seq: {} | Ack: {}", 
                                    tcp.src_port, tcp.dest_port, tcp.seq, tcp.ack_num);
                                println!("            标志位: [{}] | Payload大小: {} 字节", 
                                    f_str.join("|"), tcp.payload.len());
                            },
                            parser::TransportProtocol::Udp(udp) => {
                                println!("  [Layer 4] UDP 端口: {} -> {} | 报文长度: {}", 
                                    udp.src_port, udp.dest_port, udp.len);
                            },
                            parser::TransportProtocol::Unknown(_) => {
                                println!("  [Layer 4] 未知或暂不支持的传输层协议 (Protocol ID: {})", ip.protocol);
                            }
                        }
                    },
                    parser::IpProtocol::Unknown => {
                        println!("  [Layer 3] 非 IPv4 协议，跳过解析");
                    }
                }
            },
            Err(e) => eprintln!("  [Error] 解析失败: {:?}", e),
        }

        if packet_count >= 20 { // 调整为演示前 20 个包
            println!("\n已成功拦截并深度解析 20 个数据包，本次内功修炼圆满结束。");
            break;
        }
    }
}