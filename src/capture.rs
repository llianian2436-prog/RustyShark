use pcap::{Capture, Device};
use tokio::sync::mpsc;
use crate::error::SnifferError;

pub struct CaptureEngine;

impl CaptureEngine {
    //  升级接口：增加 filter_str 参数接收过滤规则字符串
    pub fn start_capture(device_name: &str, filter_str: &str, tx: mpsc::Sender<Vec<u8>>) -> Result<(), SnifferError> {
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

        //  核心硬核改动：如果用户输入了规则，直接将 BPF 表达式下发给操作系统内核
        // 第二个参数 true 代表开启表达式底层编译优化
        if !filter_str.is_empty() {
            cap.filter(filter_str, true)?;
        }

        // 开辟独立线程循环抓包
        std::thread::spawn(move || {
            // 彻底移除此行的打印，防止破坏精美的全屏 TUI 面板
            
            loop {
                match cap.next_packet() {
                    Ok(packet) => {
                        if tx.blocking_send(packet.data.to_vec()).is_err() {
                            break; // Channel 关闭则退出线程
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        continue;
                    }
                    Err(e) => {
                        eprintln!("[Capture] 后台抓包遭遇致命错误: {:?}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }
}