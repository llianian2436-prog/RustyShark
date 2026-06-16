mod error;
mod parser;
mod capture;

use tokio::sync::mpsc;
use pcap::Device;
use std::io::{self, stdout, Write};
use std::time::Duration;
use std::fs::File;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use crossterm::{
    event::{self, Event, KeyCode, MouseButton, MouseEventKind, EnableMouseCapture, DisableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
    Terminal,
};

#[derive(PartialEq, Clone, Copy)]
enum CaptureState {
    Running, 
    Paused,  
    Stopped, 
}

fn export_to_pcap(raw_packets: &[Vec<u8>]) -> std::io::Result<()> {
    let file_name = "rusty_shark.pcap";
    let mut file = File::create(file_name)?;
    
    file.write_all(&0xa1b2c3d4u32.to_le_bytes())?; 
    file.write_all(&2u16.to_le_bytes())?;          
    file.write_all(&4u16.to_le_bytes())?;          
    file.write_all(&0i32.to_le_bytes())?;          
    file.write_all(&0u32.to_le_bytes())?;          
    file.write_all(&65535u32.to_le_bytes())?;      
    file.write_all(&1u32.to_le_bytes())?;          
    
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as u32;
    let usecs = now.subsec_micros() as u32;

    for packet in raw_packets {
        let len = packet.len() as u32;
        file.write_all(&secs.to_le_bytes())?;      
        file.write_all(&usecs.to_le_bytes())?;     
        file.write_all(&len.to_le_bytes())?;       
        file.write_all(&len.to_le_bytes())?;       
        file.write_all(packet)?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ----------------------------------------------------------------
    // 1. 网卡交互选择 + BPF 表达式获取
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

    print!("请输入 BPF 过滤表达式 (直接回车不过滤，例如 'tcp'): ");
    stdout().flush().unwrap();
    let mut filter_input = String::new();
    io::stdin().read_line(&mut filter_input).expect("读取过滤表达式失败");
    let filter_str = filter_input.trim().to_string();

    // ----------------------------------------------------------------
    // 2. 初始化 TUI 全屏模式 + 鼠标捕获
    // ----------------------------------------------------------------
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?; 
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // ----------------------------------------------------------------
    // 3. 启动双引擎通道
    // ----------------------------------------------------------------
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1000);
    if let Err(e) = capture::CaptureEngine::start_capture(&target_device, &filter_str, tx) {
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        let _ = disable_raw_mode();
        eprintln!("\n❌ 启动抓包失败 (BPF语法错误): {:?}", e);
        return Ok(());
    }

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    let (event_tx, mut event_rx) = mpsc::channel::<crossterm::event::Event>(100);
    std::thread::spawn(move || {
        while running_clone.load(Ordering::SeqCst) {
            if let Ok(true) = event::poll(Duration::from_millis(20)) {
                if let Ok(ev) = event::read() {
                    if event_tx.blocking_send(ev).is_err() { break; }
                }
            }
        }
    });

    // 核心状态管理变量
    let mut raw_packets: Vec<Vec<u8>> = Vec::new(); 
    let mut selected_idx = 0;   
    let mut scroll_offset = 0;  
    let mut capture_state = CaptureState::Running; 
    let mut info_message = String::new(); 

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
                        Constraint::Length(3),      
                        Constraint::Percentage(50), 
                        Constraint::Percentage(35), 
                        Constraint::Length(3),      
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
                let status_text = format!("  监听网卡: {}  |  当前状态: {}  |   已捕获: {} 包", target_device, state_str, raw_packets.len());
                let status_bar = Paragraph::new(status_text)
                    .block(Block::default().title("【 RustyShark 状态面板 】").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)));
                f.render_widget(status_bar, chunks[0]);

                // ② 中部滚动列表 核心精进：全自动致敬 Wireshark 的灵魂染色矩阵！
                let mut list_items = Vec::new();
                let start = scroll_offset;
                let end = std::cmp::min(raw_packets.len(), scroll_offset + max_visible);

                for idx in start..end {
                    let raw_data = &raw_packets[idx];
                    let mut item_color = Color::White; // 默认初始化颜色
                    
                    let brief = match parser::parse_ethernet(raw_data) {
                        Ok(frame) => match frame.payload {
                            parser::IpProtocol::Ipv4(ip) => {
                                match ip.transport {
                                    parser::TransportProtocol::Tcp(tcp) => {
                                        //  拦截 TCP RST 强制断开标志位
                                        if tcp.flags.rst {
                                            item_color = Color::Red; // 异常流：刺眼暗红色
                                            format!("[{:03}] 协议: TCP(RST) | {} -> {} [异常断开连接]", idx + 1, ip.src_ip, ip.dest_ip)
                                        } else {
                                            item_color = Color::LightBlue; // 标准 TCP：经典淡蓝色
                                            format!("[{:03}] 协议: TCP   | {} -> {}", idx + 1, ip.src_ip, ip.dest_ip)
                                        }
                                    },
                                    parser::TransportProtocol::Udp(_) => {
                                        item_color = Color::LightYellow; //  标准 UDP：经典淡黄色
                                        format!("[{:03}] 协议: UDP   | {} -> {}", idx + 1, ip.src_ip, ip.dest_ip)
                                    },
                                    parser::TransportProtocol::Unknown(_) => {
                                        item_color = Color::White;
                                        format!("[{:03}] 协议: IPv4  | {} -> {}", idx + 1, ip.src_ip, ip.dest_ip)
                                    },
                                }
                            },
                            parser::IpProtocol::Ipv6 => {
                                item_color = Color::LightMagenta; //  IPv6 协议网络包：炫酷浅紫色
                                format!("[{:03}] 协议: IPv6  | MAC: {} -> {}", idx + 1, frame.src_mac, frame.dest_mac)
                            },
                            parser::IpProtocol::Arp => {
                                item_color = Color::LightGreen; //  ARP 局域网寻址广播包：生机淡绿色
                                format!("[{:03}] 协议: ARP   | MAC: {} -> {}", idx + 1, frame.src_mac, frame.dest_mac)
                            },
                            parser::IpProtocol::Unknown(eth_type) => {
                                item_color = Color::DarkGray; // 未知小众网络帧：沉稳暗灰色
                                format!("[{:03}] 未知(0x{:04X}) | MAC: {} -> {}", idx + 1, eth_type, frame.src_mac, frame.dest_mac)
                            },
                        },
                        Err(_) => {
                            item_color = Color::Red; //  驱动或链路解包损坏：刺眼暗红色
                            format!("[{:03}] 损坏的数据包", idx + 1)
                        },
                    };
                    
                    //  核心魔法：将动态计算出来的颜色灌注给当前的 ListItem
                    list_items.push(ListItem::new(brief).style(Style::default().fg(item_color)));
                }

                let mut display_state = ListState::default();
                if !raw_packets.is_empty() {
                    display_state.select(Some(selected_idx.saturating_sub(scroll_offset)));
                }

                let packet_list = List::new(list_items)
                    .block(Block::default().title("  数据包瀑布流 (支持鼠标点击/拖拽滚动条) ").borders(Borders::ALL))
                    .highlight_style(Style::default().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD))
                    .highlight_symbol("▶ ");
                f.render_stateful_widget(packet_list, list_chunk, &mut display_state);

                // 渲染滚动条外观
                let scrollbar = Scrollbar::default()
                    .orientation(ScrollbarOrientation::VerticalRight) 
                    .begin_symbol(Some("▲")) 
                    .end_symbol(Some("▼"))   
                    .track_symbol(Some("│")) 
                    .thumb_symbol("█");      

                let mut scrollbar_state = ScrollbarState::new(raw_packets.len()).position(selected_idx);
                f.render_stateful_widget(scrollbar, list_chunk, &mut scrollbar_state);

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
                                parser::IpProtocol::Ipv6 => {
                                    tree.push_str(" └─ [Layer 3] 互联网协议第六版 (IPv6) | 后台内核已基于 BPF 规则完成筛选");
                                },
                                parser::IpProtocol::Arp => {
                                    tree.push_str(" └─ [Layer 3] 地址解析协议 (ARP) | 用于局域网内 IP 与 MAC 地址的动态映射寻址");
                                },
                                parser::IpProtocol::Unknown(eth_type) => {
                                    tree.push_str(&format!(" └─ [Layer 3] 未知上层网络协议 (EtherType: 0x{:04X})，停止递进解析", eth_type));
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

                // ④ 按钮控制网格
                let btn_chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([
                        Constraint::Length(16), 
                        Constraint::Length(1),  
                        Constraint::Length(16), 
                        Constraint::Length(1),  
                        Constraint::Length(16), 
                        Constraint::Length(1),  
                        Constraint::Length(16), 
                        Constraint::Length(1),  
                        Constraint::Length(16), 
                        Constraint::Length(1),  
                        Constraint::Length(16), 
                        Constraint::Min(0),     
                    ])
                    .split(chunks[3]);

                let start_style = if capture_state == CaptureState::Running { Style::default().fg(Color::Green).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::White) };
                let btn_start = Paragraph::new("  ▶ 开始/恢复 ")
                    .block(Block::default().borders(Borders::ALL).border_style(start_style));
                f.render_widget(btn_start, btn_chunks[0]);

                let pause_style = if capture_state == CaptureState::Paused { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::White) };
                let btn_pause = Paragraph::new("  ⏸ 暂停抓包 ")
                    .block(Block::default().borders(Borders::ALL).border_style(pause_style));
                f.render_widget(btn_pause, btn_chunks[2]);

                let stop_style = if capture_state == CaptureState::Stopped { Style::default().fg(Color::Red).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::White) };
                let btn_stop = Paragraph::new("  ⏹ 停止抓包 ")
                    .block(Block::default().borders(Borders::ALL).border_style(stop_style));
                f.render_widget(btn_stop, btn_chunks[4]);

                let clear_style = if capture_state != CaptureState::Running && !raw_packets.is_empty() { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::DarkGray) };
                let btn_clear = Paragraph::new("    一键清空   ")
                    .block(Block::default().borders(Borders::ALL).border_style(clear_style));
                f.render_widget(btn_clear, btn_chunks[6]);

                let export_style = if !raw_packets.is_empty() { Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::DarkGray) };
                let btn_export = Paragraph::new("   导出文件 ")
                    .block(Block::default().borders(Borders::ALL).border_style(export_style));
                f.render_widget(btn_export, btn_chunks[8]);

                let btn_quit = Paragraph::new("  ❌ 退出程序 ")
                    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::LightRed)));
                f.render_widget(btn_quit, btn_chunks[10]);

                let tip_text = if info_message.is_empty() {
                    "  💡 提示：使用鼠标左键点击或按住拖拽右侧滚动条。".to_string()
                } else {
                    format!("  ✨ 状态反馈: {}", info_message)
                };
                let tip_msg = Paragraph::new(tip_text)
                    .style(Style::default().fg(Color::LightYellow));
                f.render_widget(tip_msg, btn_chunks[11]);
            })?;
            
            should_redraw = false;
        }

        tokio::select! {
            _ = fps_timer.tick() => {
                should_redraw = true;
            }

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
                            MouseEventKind::Down(MouseButton::Left) | MouseEventKind::Drag(MouseButton::Left) => {
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

                                    if mouse.column == list_chunk.x + list_chunk.width - 1
                                       && mouse.row >= list_chunk.y && mouse.row < list_chunk.y + list_chunk.height
                                    {
                                        if !raw_packets.is_empty() {
                                            let total_packets = raw_packets.len();
                                            if mouse.row == list_chunk.y {
                                                if selected_idx > 0 { selected_idx -= 1; }
                                            } else if mouse.row == list_chunk.y + list_chunk.height - 1 {
                                                if selected_idx < total_packets - 1 { selected_idx += 1; }
                                            } else {
                                                let track_height = list_chunk.height.saturating_sub(2) as f32;
                                                if track_height > 1.0 {
                                                    let rel_row = (mouse.row - list_chunk.y - 1) as f32;
                                                    let progress = (rel_row / track_height).clamp(0.0, 1.0);
                                                    let target = (progress * (total_packets - 1) as f32).round() as usize;
                                                    selected_idx = target.min(total_packets - 1);
                                                }
                                            }
                                        }
                                    }
                                    else if mouse.row > list_chunk.y && mouse.row < list_chunk.y + list_chunk.height - 1
                                       && mouse.column > list_chunk.x && mouse.column < list_chunk.x + list_chunk.width - 1
                                    {
                                        if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
                                            let clicked_visible_idx = (mouse.row - list_chunk.y - 1) as usize;
                                            let target_idx = scroll_offset + clicked_visible_idx;
                                            let current_end = std::cmp::min(raw_packets.len(), scroll_offset + max_visible);
                                            if target_idx < current_end {
                                                selected_idx = target_idx;
                                            }
                                        }
                                    }
                                    else if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
                                        let btn_bar_chunk = layout_chunks[3];
                                        if mouse.row >= btn_bar_chunk.y && mouse.row < btn_bar_chunk.y + btn_bar_chunk.height {
                                            let sub_btn_chunks = Layout::default()
                                                .direction(Direction::Horizontal)
                                                .constraints([
                                                    Constraint::Length(16), 
                                                    Constraint::Length(1),
                                                    Constraint::Length(16), 
                                                    Constraint::Length(1),
                                                    Constraint::Length(16), 
                                                    Constraint::Length(1),
                                                    Constraint::Length(16), 
                                                    Constraint::Length(1),
                                                    Constraint::Length(16), 
                                                    Constraint::Length(1),
                                                    Constraint::Length(16), 
                                                    Constraint::Min(0),
                                                ])
                                                .split(btn_bar_chunk);

                                            let click_col = mouse.column;

                                            let b_start = sub_btn_chunks[0];
                                            if click_col >= b_start.x && click_col < b_start.x + b_start.width {
                                                capture_state = CaptureState::Running;
                                                info_message = "监听引擎已唤醒，正在捕获最新流量...".to_string();
                                            }

                                            let b_pause = sub_btn_chunks[2];
                                            if click_col >= b_pause.x && click_col < b_pause.x + b_pause.width {
                                                if capture_state == CaptureState::Running {
                                                    capture_state = CaptureState::Paused;
                                                    info_message = "抓包已暂停，你可以自由翻阅和导出当前数据。".to_string();
                                                }
                                            }

                                            let b_stop = sub_btn_chunks[4];
                                            if click_col >= b_stop.x && click_col < b_stop.x + b_stop.width {
                                                capture_state = CaptureState::Stopped;
                                                info_message = "抓包已彻底终止。".to_string();
                                            }

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

                                            let b_export = sub_btn_chunks[8];
                                            if click_col >= b_export.x && click_col < b_export.x + b_export.width {
                                                if raw_packets.is_empty() {
                                                    info_message = "❌ 导出失败：当前没有任何捕获到的包数据！".to_string();
                                                } else {
                                                    match export_to_pcap(&raw_packets) {
                                                        Ok(_) => info_message = "💾 成功导出标准文件: rusty_shark.pcap !".to_string(),
                                                        Err(e) => info_message = format!("❌ 导出文件系统出错: {:?}", e),
                                                    }
                                                }
                                            }

                                            let b_quit = sub_btn_chunks[10];
                                            if click_col >= b_quit.x && click_col < b_quit.x + b_quit.width {
                                                break; 
                                            }
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
    running.store(false, Ordering::SeqCst); 
    std::thread::sleep(Duration::from_millis(40)); 

    execute!(std::io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
    disable_raw_mode()?;
    
    println!("=== RustyShark 已安全退出 ===");
    Ok(())
}