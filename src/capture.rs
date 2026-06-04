use pcap::{Capture, Device};
use tokio::sync::mpsc;
use crate::error::SnifferError;

pub struct CaptureEngine;

impl CaptureEngine {
    pub fn start_capture(device_name: &str, tx: mpsc::Sender<Vec<u8>>) -> Result<(), SnifferError> {
        // 查找指定网卡
       let main_device = Device::list()?
        .into_iter()
        .find(|d| d.name == device_name)
        .ok_or(SnifferError::DeviceNotFound)?;

        // 打开网卡设备激活抓包
        let mut cap = Capture::from_device(main_device)?
            .promisc(true) // 开启混杂模式
            .snaplen(65535)
            .timeout(1000)
            .open()?;

        // 开辟独立线程循环抓包
        std::thread::spawn(move || {
            println!("[Capture] 后台抓包线程已启动...");
            
            loop {
                match cap.next_packet() {
                    Ok(packet) => {
                        if tx.blocking_send(packet.data.to_vec()).is_err() {
                            break; // Channel 关闭则退出线程
                        }
                    }
                    // 🌟 就在这里：把原本的 Timeout 改成 TimeoutExpired 
                    Err(pcap::Error::TimeoutExpired) => {
                        continue;
                    }
                    Err(e) => {
                        eprintln!("[Capture] 后台抓包遭遇致命错误: {:?}", e);
                        break;
                    }
                }
            }
            println!("[Capture] 后台抓包线程已安全退出。");
        });

        Ok(())
    }
}