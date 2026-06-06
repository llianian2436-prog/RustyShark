mod error;
mod parser;
mod capture;

// 🌟 1. 补齐了完整的标准库和 Tokio 导入
use tokio::sync::mpsc;
use pcap::Device;
use std::io::{self, stdout, Write};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

// 🌟 2. 补齐了 Ratatui 界面、样式、颜色的完整导入（消灭 Style/Color/List 报错）
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ----------------------------------------------------------------
    // 1. 网卡交互选择
    // ----------------------------------------------------------------
    println!("=== RustyShark TUI 深度进化版 ===");
    let devices = Device::list().expect("无法获取网卡列表");
    println!("可用网卡列表:");
    for (i, d) in devices.iter().enumerate() {
        println!("[{}] 名字: {} | 描述: {:?}", i, d.name, d.desc);
    }
    if devices.is_empty() { return Ok(()); }

    print!("\n请选择要抓包的网卡编号 (默认 4): ");
    io::Write::flush(&mut io::stdout()).unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("读取输入失败");
    let choice: usize = input.trim().parse().unwrap_or(4);
    let index = if choice < devices.len() { choice } else { 0 };
    let target_device = devices[index].name.clone();

    // ----------------------------------------------------------------
    // 2. 初始化 TUI 全屏原始模式
    // ----------------------------------------------------------------
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 3. 启动后台抓包线程
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
    if let Err(e) = capture::CaptureEngine::start_capture(&target_device, tx) {
        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        eprintln!("启动抓包失败: {:?}", e);
        return Ok(());
    }

    // 🌟 3. 核心基础变量（消灭 raw_packets 和 list_state 报错）
    let mut raw_packets: Vec<Vec<u8>> = Vec::new(); // 存储所有原始包字节
    let mut list_state = ListState::default();       // 管理中部列表的“选中行”状态
    list_state.select(Some(0));                      // 默认选中第一行

    // ----------------------------------------------------------------
    // 4. 事件主循环
    // ----------------------------------------------------------------
    loop {
        // 🎨 绘制全屏界面
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),      // 状态栏
                    Constraint::Percentage(50), // 滚动列表
                    Constraint::Percentage(47), // 深度解析
                ])
                .split(f.size());

            // ① 状态栏
            let status_text = format!(" 📡 网卡: {}  |  🟢 状态: 实时抓包中...  |  📦 已拦截: {} 包", target_device, raw_packets.len());
            let status_bar = Paragraph::new(status_text)
                .block(Block::default().title("【 RustyShark 状态面板 】").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)));
            f.render_widget(status_bar, chunks[0]);

            // ② 中部滚动列表
            let mut list_items = Vec::new();
            for (idx, raw_data) in raw_packets.iter().enumerate() {
                let brief = match parser::parse_ethernet(raw_data) {
                    Ok(frame) => match frame.payload {
                        parser::IpProtocol::Ipv4(ip) => {
                            let proto = match ip.transport {
                                parser::TransportProtocol::Tcp(_) => "TCP",
                                parser::TransportProtocol::Udp(_) => "UDP",
                                parser::TransportProtocol::Unknown(_) => "IPv4",
                            };
                            format!("[{:03}] 协议: {:<5} | {} -> {}", idx + 1, proto, ip.src_ip, ip.dest_ip)
                        },
                        parser::IpProtocol::Unknown => format!("[{:03}] 非IPv4帧 | MAC: {} -> {}", idx + 1, frame.src_mac, frame.dest_mac),
                    },
                    Err(_) => format!("[{:03}] 损坏的数据包", idx + 1),
                };
                list_items.push(ListItem::new(brief));
            }

            let packet_list = List::new(list_items)
                .block(Block::default().title(" 📥 数据包瀑布流 (使用 [↑/↓] 键浏览) ").borders(Borders::ALL))
                .highlight_style(Style::default().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD))
                .highlight_symbol("▶ ");
            
            f.render_stateful_widget(packet_list, chunks[1], &mut list_state);

            // ③ 下部：深度协议树解析栏
            let details_text = if raw_packets.is_empty() {
                " 📭 暂无数据，请在浏览器里刷新网页制造一些流量...".to_string()
            } else if let Some(selected_idx) = list_state.selected() {
                if selected_idx < raw_packets.len() {
                    let target_raw = &raw_packets[selected_idx];
                    
                    match parser::parse_ethernet(target_raw) {
                        Ok(frame) => {
                            let mut tree = format!(" ├─ [Layer 2] 以太网帧: MAC ({}) -> ({})\n", frame.src_mac, frame.dest_mac);
                            match frame.payload {
                                parser::IpProtocol::Ipv4(ip) => {
                                    tree.push_str(&format!(" ├─ [Layer 3] 互联网协议 (IPv4): {} -> {}\n", ip.src_ip, ip.dest_ip));
                                    
                                    match ip.transport {
                                        parser::TransportProtocol::Tcp(tcp) => {
                                            let mut f_str = Vec::new();
                                            if tcp.flags.syn { f_str.push("SYN"); }
                                            if tcp.flags.ack { f_str.push("ACK"); }
                                            if tcp.flags.fin { f_str.push("FIN"); }
                                            if tcp.flags.rst { f_str.push("RST"); }
                                            if tcp.flags.psh { f_str.push("PSH"); }
                                            
                                            tree.push_str(&format!(" └─ [Layer 4] 传输控制协议 (TCP)\n"));
                                            tree.push_str(&format!("      ├── 源端口: {} ──> 目的端口: {}\n", tcp.src_port, tcp.dest_port));
                                            tree.push_str(&format!("      ├── 序列号 (Seq): {} | 确认号 (Ack): {}\n", tcp.seq, tcp.ack_num));
                                            tree.push_str(&format!("      └── 控制标志位: [{}] | 载荷大小: {} 字节", f_str.join("|"), tcp.payload.len()));
                                        },
                                        parser::TransportProtocol::Udp(udp) => {
                                            tree.push_str(&format!(" └─ [Layer 4] 用户数据报协议 (UDP)\n"));
                                            tree.push_str(&format!("      └── 源端口: {} ──> 目的端口: {} | 长度: {} 字节", udp.src_port, udp.dest_port, udp.len));
                                        },
                                        parser::TransportProtocol::Unknown(raw) => {
                                            tree.push_str(&format!(" └─ [Layer 4] 未知传输层协议 | 原始载荷大小: {} 字节", raw.len()));
                                        }
                                    }
                                },
                                parser::IpProtocol::Unknown => {
                                    tree.push_str(" └─ [Layer 3] 非 IPv4 协议，停止递进解析");
                                }
                            }
                            tree
                        },
                        Err(e) => format!(" 解析失败: {:?}", e),
                    }
                } else { " 选中项越界".to_string() }
            } else { " 未选中任何包".to_string() };

            let details_panel = Paragraph::new(details_text)
                .block(Block::default().title(" ⚙️ 协议树深度明细 (随上方选中项实时解剖) ").borders(Borders::ALL).border_style(Style::default().fg(Color::Green)));
            f.render_widget(details_panel, chunks[2]);
        })?;

        // 🧠 异步双路复用
        tokio::select! {
            // 接收新数据包
            Some(raw_data) = rx.recv() => {
                raw_packets.push(raw_data);
                if let Some(selected) = list_state.selected() {
                    if selected == raw_packets.len().saturating_sub(2) {
                        list_state.select(Some(raw_packets.len() - 1));
                    }
                }
            }

            // 监听键盘按键
            res = tokio::task::spawn_blocking(|| event::poll(std::time::Duration::from_millis(40))) => {
                if let Ok(Ok(true)) = res {
                    if let Event::Key(key) = event::read()? {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Char('Q') => break,
                            KeyCode::Down => {
                                if !raw_packets.is_empty() {
                                    let curr = list_state.selected().unwrap_or(0);
                                    if curr < raw_packets.len() - 1 {
                                        list_state.select(Some(curr + 1));
                                    }
                                }
                            },
                            KeyCode::Up => {
                                if !raw_packets.is_empty() {
                                    let curr = list_state.selected().unwrap_or(0);
                                    if curr > 0 {
                                        list_state.select(Some(curr - 1));
                                    }
                                }
                            },
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    // ----------------------------------------------------------------
    // 5. 归还终端
    // ----------------------------------------------------------------
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    println!("=== RustyShark 已安全退出 ===");
    Ok(())
}