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
        .ok_or(SnifferError::DeviceNotFound)?; // <- 改成返回我们自己的错误类型！

        // 打开网卡设备激活抓包
        let mut cap = Capture::from_device(main_device)?
            .promisc(true) // 开启混杂模式（能抓到 eNSP 里的别人流量）
            .snaplen(65535)
            .timeout(1000)
            .open()?;

        // 开辟独立线程循环抓包（因为 pcap 的 next_packet 是阻塞的）
        std::thread::spawn(move || {
            println!("[Capture] 后台抓包线程已启动...");
            while let Ok(packet) = cap.next_packet() {
                // 将数据包复制成 Vec<u8> 通过异步通道发送出去
                if tx.blocking_send(packet.data.to_vec()).is_err() {
                    break; // Channel 关闭则退出线程
                }
            }
        });

        Ok(())
    }
}