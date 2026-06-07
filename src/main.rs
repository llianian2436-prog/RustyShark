mod error;
mod parser;
mod capture;

use tokio::sync::mpsc;
use pcap::Device;
use std::io::{self, stdout, Write};
use std::time::Duration;
use std::fs::File; // 🌟 新增：用于创建导出文件
use crossterm::{
    event::{self, Event, KeyCode, MouseButton, MouseEventKind, EnableMouseCapture, DisableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
};

// 定义清晰的用户级抓包状态机
#[derive(PartialEq, Clone, Copy)]
enum CaptureState {
    Running, // 🟢 运行中
    Paused,  // 🟡 已暂停
    Stopped, // 🔴 已停止
}

// 🌟 核心硬核函数：手动构建标准 Libpcap 二进制文件格式 (Wireshark 官方格式)
fn export_to_pcap(raw_packets: &[Vec<u8>]) -> std::io::Result<()> {
    let file_name = "rusty_shark.pcap";
    let mut file = File::create(file_name)?;
    
    // 1. 写入 PCAP 全局文件头 (24 字节)
    file.write_all(&0xa1b2c3d4u32.to_le_bytes())?; // Magic Number (标识小端序 pcap)
    file.write_all(&2u16.to_le_bytes())?;          // Major Version (主版本号: 2)
    file.write_all(&4u16.to_le_bytes())?;          // Minor Version (副版本号: 4)
    file.write_all(&0i32.to_le_bytes())?;          // Timezone (当地时区修正: 0)
    file.write_all(&0u32.to_le_bytes())?;          // Sigfigs (时间戳精度: 0)
    file.write_all(&65535u32.to_le_bytes())?;      // Snaplen (最大捕获长度: 64KB)
    file.write_all(&1u32.to_le_bytes())?;          // Network (链路层类型: 1 代表以太网 Ethernet)
    
    // 获取当前系统时间戳作为基础时间
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as u32;
    let usecs = now.subsec_micros() as u32;

    // 2. 循环写入每一个数据包
    for packet in raw_packets {
        let len = packet.len() as u32;
        // 写入每个数据包的专属头部 (16 字节)
        file.write_all(&secs.to_le_bytes())?;      // 时间戳：秒
        file.write_all(&usecs.to_le_bytes())?;     // 时间戳：微秒
        file.write_all(&len.to_le_bytes())?;       // 捕获到的数据长度
        file.write_all(&len.to_le_bytes())?;       // 报文原始真实长度
        
        // 写入数据包纯原始裸字节
        file.write_all(packet)?;
    }
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ----------------------------------------------------------------
    // 1. 网卡交互选择
    // ----------------------------------------------------------------
    println!("=== RustyShark 智能网络嗅探器 ===");
    let devices = Device::list().expect("无法获取网卡列表");
    println!("可用网卡列表:");
    for (i, d) in devices.iter().enumerate() {
        println!("[{}] 名字: {} | 描述: {:?}", i, d.name, d.desc);
    }
    if devices.is_empty() { return Ok(()); }

    print!("\n请选择要抓包的网卡编号 (默认 4): ");
    stdout().flush().unwrap(); 
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("读取输入失败");
    let choice: usize = input.trim().parse().unwrap_or(4);
    let index = if choice < devices.len() { choice } else { 0 };
    let target_device = devices[index].name.clone();

    // ----------------------------------------------------------------
    // 2. 初始化 TUI 全屏模式 + 鼠标捕获
    // ----------------------------------------------------------------
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?; 
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 3. 启动通道
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1000);
    if let Err(e) = capture::CaptureEngine::start_capture(&target_device, tx) {
        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
        eprintln!("启动抓包失败: {:?}", e);
        return Ok(());
    }

    let (event_tx, mut event_rx) = mpsc::channel::<crossterm::event::Event>(100);
    std::thread::spawn(move || {
        loop {
            if let Ok(ev) = event::read() {
                if event_tx.blocking_send(ev).is_err() { break; }
            }
        }
    });

    // 核心状态管理变量
    let mut raw_packets: Vec<Vec<u8>> = Vec::new(); 
    let mut selected_idx = 0;   
    let mut scroll_offset = 0;  
    let mut capture_state = CaptureState::Running; 
    let mut info_message = String::new(); // 🌟 新增：界面动态系统提示弹窗文本

    // 30 FPS 控频定时器
    let mut fps_timer = tokio::time::interval(Duration::from_millis(33));
    let mut should_redraw = true; 

    // ----------------------------------------------------------------
    // 4. 事件主循环
    // ----------------------------------------------------------------
    loop {
        if should_redraw {
            terminal.draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3),      // 0: 顶部状态栏
                        Constraint::Percentage(50), // 1: 中部滚动列表
                        Constraint::Percentage(35), // 2: 协议深度解析
                        Constraint::Length(3),      // 3: 底部鼠标按钮控制栏
                    ])
                    .split(f.size());

                let list_chunk = chunks[1];
                let max_visible = (list_chunk.height as usize).saturating_sub(2);

                if selected_idx >= scroll_offset + max_visible {
                    scroll_offset = selected_idx + 1 - max_visible;
                }
                if selected_idx < scroll_offset {
                    scroll_offset = selected_idx;
                }

                // ① 状态栏
                let state_str = match capture_state {
                    CaptureState::Running => "🟢 运行中",
                    CaptureState::Paused  => "🟡 已暂停",
                    CaptureState::Stopped => "🔴 已停止",
                };
                let status_text = format!(" 📡 监听网卡: {}  |  当前状态: {}  |  📦 已捕获: {} 包", target_device, state_str, raw_packets.len());
                let status_bar = Paragraph::new(status_text)
                    .block(Block::default().title("【 RustyShark 状态面板 】").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)));
                f.render_widget(status_bar, chunks[0]);

                // ② 中部滚动列表
                let mut list_items = Vec::new();
                let start = scroll_offset;
                let end = std::cmp::min(raw_packets.len(), scroll_offset + max_visible);

                for idx in start..end {
                    let raw_data = &raw_packets[idx];
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

                let mut display_state = ListState::default();
                if !raw_packets.is_empty() {
                    display_state.select(Some(selected_idx.saturating_sub(scroll_offset)));
                }

                let packet_list = List::new(list_items)
                    .block(Block::default().title(" 📥 数据包瀑布流 (鼠标左键点击任意行可深度解剖) ").borders(Borders::ALL))
                    .highlight_style(Style::default().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD))
                    .highlight_symbol("▶ ");
                f.render_stateful_widget(packet_list, list_chunk, &mut display_state);

                // ③ 下部：深度协议树解析栏
                let details_text = if raw_packets.is_empty() {
                    " 📭 暂无数据，整个系统已归零。请点击下方 [开始/恢复] 重新触发流量...".to_string()
                } else {
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
                };
                let details_panel = Paragraph::new(details_text)
                    .block(Block::default().title(" ⚙️ 协议树深度明细 ").borders(Borders::ALL).border_style(Style::default().fg(Color::Green)));
                f.render_widget(details_panel, chunks[2]);

                // ④ 🌟 按钮网格：横向均匀拆分出 6 个整齐的控制格
                let btn_chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([
                        Constraint::Length(16), // [ ▶ 开始/恢复 ]
                        Constraint::Length(1),  
                        Constraint::Length(16), // [ ⏸ 暂停抓包 ]
                        Constraint::Length(1),  
                        Constraint::Length(16), // [ ⏹ 停止抓包 ]
                        Constraint::Length(1),  
                        Constraint::Length(16), // [  一键清空  ]
                        Constraint::Length(1),  
                        Constraint::Length(16), // [ 💾 导出文件 ] 🌟 新增按钮位置
                        Constraint::Length(1),  
                        Constraint::Length(16), // [ ❌ 退出程序 ]
                        Constraint::Min(0),     
                    ])
                    .split(chunks[3]);

                // 按钮 1：开始/恢复
                let start_style = if capture_state == CaptureState::Running { Style::default().fg(Color::Green).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::White) };
                let btn_start = Paragraph::new("  ▶ 开始/恢复 ")
                    .block(Block::default().borders(Borders::ALL).border_style(start_style));
                f.render_widget(btn_start, btn_chunks[0]);

                // 按钮 2：暂停
                let pause_style = if capture_state == CaptureState::Paused { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::White) };
                let btn_pause = Paragraph::new("  ⏸ 暂停抓包 ")
                    .block(Block::default().borders(Borders::ALL).border_style(pause_style));
                f.render_widget(btn_pause, btn_chunks[2]);

                // 按钮 3：终止
                let stop_style = if capture_state == CaptureState::Stopped { Style::default().fg(Color::Red).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::White) };
                let btn_stop = Paragraph::new("  ⏹ 停止抓包 ")
                    .block(Block::default().borders(Borders::ALL).border_style(stop_style));
                f.render_widget(btn_stop, btn_chunks[4]);

                // 按钮 4：一键清空
                let clear_style = if capture_state != CaptureState::Running && !raw_packets.is_empty() { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::DarkGray) };
                let btn_clear = Paragraph::new("    一键清空   ")
                    .block(Block::default().borders(Borders::ALL).border_style(clear_style));
                f.render_widget(btn_clear, btn_chunks[6]);

                // 按钮 5：🌟 导出文件按钮渲染
                let export_style = if !raw_packets.is_empty() { Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::DarkGray) };
                let btn_export = Paragraph::new("  💾 导出文件 ")
                    .block(Block::default().borders(Borders::ALL).border_style(export_style));
                f.render_widget(btn_export, btn_chunks[8]);

                // 按钮 6：退出程序
                let btn_quit = Paragraph::new("  ❌ 退出程序 ")
                    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::LightRed)));
                f.render_widget(btn_quit, btn_chunks[10]);

                // 右侧动态系统提示弹窗区
                let tip_text = if info_message.is_empty() {
                    "  💡 提示：使用鼠标左键点击下方按钮操作。".to_string()
                } else {
                    format!("  ✨ 状态反馈: {}", info_message)
                };
                let tip_msg = Paragraph::new(tip_text)
                    .style(Style::default().fg(Color::LightYellow));
                f.render_widget(tip_msg, btn_chunks[11]);
            })?;
            
            should_redraw = false;
        }

        // 🧠 异步多路复用
        tokio::select! {
            _ = fps_timer.tick() => {
                should_redraw = true;
            }

            // 流量注入
            Some(raw_data) = rx.recv() => {
                if capture_state == CaptureState::Running {
                    let old_len = raw_packets.len();
                    let was_at_bottom = selected_idx == old_len.saturating_sub(1);
                    raw_packets.push(raw_data);
                    if was_at_bottom {
                        selected_idx = raw_packets.len() - 1;
                    }
                }
            }

            Some(ev) = event_rx.recv() => {
                should_redraw = true; 
                
                match ev {
                    Event::Key(key) => {
                        if key.code == KeyCode::Char('q') || key.code == KeyCode::Char('Q') { break; }
                        if key.code == KeyCode::Down && !raw_packets.is_empty() && selected_idx < raw_packets.len() - 1 { selected_idx += 1; }
                        if key.code == KeyCode::Up && selected_idx > 0 { selected_idx -= 1; }
                    }

                    Event::Mouse(mouse) => {
                        match mouse.kind {
                            MouseEventKind::Down(MouseButton::Left) => {
                                if let Ok(size) = terminal.size() {
                                    let layout_chunks = Layout::default()
                                        .direction(Direction::Vertical)
                                        .constraints([
                                            Constraint::Length(3),
                                            Constraint::Percentage(50),
                                            Constraint::Percentage(35),
                                            Constraint::Length(3),
                                        ])
                                        .split(size);
                                    
                                    let list_chunk = layout_chunks[1];
                                    let max_visible = (list_chunk.height as usize).saturating_sub(2);

                                    // A 面板：戳中数据列表
                                    if mouse.row > list_chunk.y && mouse.row < list_chunk.y + list_chunk.height - 1
                                       && mouse.column > list_chunk.x && mouse.column < list_chunk.x + list_chunk.width - 1
                                    {
                                        let clicked_visible_idx = (mouse.row - list_chunk.y - 1) as usize;
                                        let target_idx = scroll_offset + clicked_visible_idx;
                                        let current_end = std::cmp::min(raw_packets.len(), scroll_offset + max_visible);
                                        if target_idx < current_end {
                                            selected_idx = target_idx;
                                        }
                                    }

                                    // B 面板：🌟 精准解算点击 6 个按钮
                                    let btn_bar_chunk = layout_chunks[3];
                                    if mouse.row >= btn_bar_chunk.y && mouse.row < btn_bar_chunk.y + btn_bar_chunk.height {
                                        let sub_btn_chunks = Layout::default()
                                            .direction(Direction::Horizontal)
                                            .constraints([
                                                Constraint::Length(16), // 0: 开始
                                                Constraint::Length(1),
                                                Constraint::Length(16), // 2: 暂停
                                                Constraint::Length(1),
                                                Constraint::Length(16), // 4: 停止
                                                Constraint::Length(1),
                                                Constraint::Length(16), // 6: 清空
                                                Constraint::Length(1),
                                                Constraint::Length(16), // 8: 导出 🌟 新增
                                                Constraint::Length(1),
                                                Constraint::Length(16), // 10: 退出
                                                Constraint::Min(0),
                                            ])
                                            .split(btn_bar_chunk);

                                        let click_col = mouse.column;

                                        // ① 点击“开始/恢复”
                                        let b_start = sub_btn_chunks[0];
                                        if click_col >= b_start.x && click_col < b_start.x + b_start.width {
                                            capture_state = CaptureState::Running;
                                            info_message = "监听引擎已唤醒，正在捕获最新流量...".to_string();
                                        }

                                        // ② 点击“暂停抓包”
                                        let b_pause = sub_btn_chunks[2];
                                        if click_col >= b_pause.x && click_col < b_pause.x + b_pause.width {
                                            if capture_state == CaptureState::Running {
                                                capture_state = CaptureState::Paused;
                                                info_message = "抓包已暂停，你可以自由翻阅和导出当前数据。".to_string();
                                            }
                                        }

                                        // ③ 点击“停止抓包”
                                        let b_stop = sub_btn_chunks[4];
                                        if click_col >= b_stop.x && click_col < b_stop.x + b_stop.width {
                                            capture_state = CaptureState::Stopped;
                                            info_message = "抓包已彻底终止。".to_string();
                                        }

                                        // ④ 点击“一键清空”
                                        let b_clear = sub_btn_chunks[6];
                                        if click_col >= b_clear.x && click_col < b_clear.x + b_clear.width {
                                            if capture_state != CaptureState::Running {
                                                raw_packets.clear();
                                                selected_idx = 0;
                                                scroll_offset = 0;
                                                info_message = "缓冲区已清空，系统重置归零。".to_string();
                                            } else {
                                                info_message = "⚠️ 警告：请先暂停或停止抓包再清空数据！".to_string();
                                            }
                                        }

                                        // ⑤ 🌟 点击“导出文件”事件拦截
                                        let b_export = sub_btn_chunks[8];
                                        if click_col >= b_export.x && click_col < b_export.x + b_export.width {
                                            if raw_packets.is_empty() {
                                                info_message = "❌ 导出失败：当前没有任何捕获到的包数据！".to_string();
                                            } else {
                                                // 执行二进制级 pcap 文件导出
                                                match export_to_pcap(&raw_packets) {
                                                    Ok(_) => info_message = "💾 成功导出标准文件: rusty_shark.pcap !".to_string(),
                                                    Err(e) => info_message = format!("❌ 导出文件系统出错: {:?}", e),
                                                }
                                            }
                                        }

                                        // ⑥ 点击“退出程序”
                                        let b_quit = sub_btn_chunks[10];
                                        if click_col >= b_quit.x && click_col < b_quit.x + b_quit.width {
                                            break; 
                                        }
                                    }
                                }
                            }
                            MouseEventKind::ScrollUp => { if selected_idx > 0 { selected_idx -= 1; } }
                            MouseEventKind::ScrollDown => { if !raw_packets.is_empty() && selected_idx < raw_packets.len() - 1 { selected_idx += 1; } }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // ----------------------------------------------------------------
    // 5. 归还终端
    // ----------------------------------------------------------------
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    println!("=== RustyShark 已安全退出 ===");
    Ok(())
}