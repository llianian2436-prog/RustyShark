mod error;
mod parser;
mod capture;

use tokio::sync::mpsc;
use pcap::Device;

#[tokio::main]
async fn main() {
    println!("=== Rust-Sniffer 雏形启动 ===");

    // 1. 列出系统所有可用网卡，供你选择
    let devices = Device::list().expect("无法获取网卡列表");
    println!("可用网卡列表:");
    for (i, d) in devices.iter().enumerate() {
        println!("[{}] 名字: {} | 描述: {:?}", i, d.name, d.desc);
    }

    // 为了演示方便，这里默认选中第 0 个网卡
    // 如果你连 eNSP，请在这里修改成对应的网卡名字或让用户手动输入
    if devices.is_empty() {
        println!("未找到任何网卡，程序退出。");
        return;
    }
    let target_device = &devices[0].name;
    println!("\n默认选中网卡: {}", target_device);

    // 2. 创建异步通道 (容量为 100 缓存)
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);

    // 3. 启动后台抓包
    if let Err(e) = capture::CaptureEngine::start_capture(target_device, tx) {
        eprintln!("启动抓包失败: {:?}", e);
        return;
    }

    // 4. 主线程（异步接收数据并调用解析模块）
    println!("[Main] 正在等待接收并解析网络数据包...\n");
    let mut packet_count = 0;

    while let Some(raw_data) = rx.recv().await {
        packet_count += 1;
        println!("--------------------------------------------------");
        println!("收到第 {} 个原始数据包, 长度: {} 字节", packet_count, raw_data.len());

        // 调用解析模块
        match parser::parse_ethernet(&raw_data) {
            Ok(frame) => {
                println!("  [Layer 2] 源 MAC: {} -> 目的 MAC: {}", frame.src_mac, frame.dest_mac);
                match frame.payload {
                    parser::IpProtocol::Ipv4(ip) => {
                        let proto_str = match ip.protocol {
                            6 => "TCP",
                            17 => "UDP",
                            1 => "ICMP",
                            _ => "Unknown",
                        };
                        println!("  [Layer 3] IPv4 报文: {} -> {} | 协议: {}", ip.src_ip, ip.dest_ip, proto_str);
                    },
                    parser::IpProtocol::Unknown => {
                        println!("  [Layer 3] 非 IPv4 协议，跳过深度解析");
                    }
                }
            },
            Err(e) => eprintln!("  [Error] 解析失败: {:?}", e),
        }

        // 仅演示前 10 个包，防止控制台刷屏
        if packet_count >= 10 {
            println!("\n已成功拦截并解析 10 个数据包，雏形演示结束。");
            break;
        }
    }
}