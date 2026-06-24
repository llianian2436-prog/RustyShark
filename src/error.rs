use thiserror::Error;

#[derive(Error, Debug)]
pub enum SnifferError {
    #[error("Pcap 底层错误: {0}")]
    PcapError(#[from] pcap::Error),

    #[error("找不到指定的网卡设备")]
    DeviceNotFound,

    #[error("数据包长度不足以解析首部")]
    InvalidLength,
}
