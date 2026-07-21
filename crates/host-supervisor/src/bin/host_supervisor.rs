// host-supervisor 二进制 stub —— M0 起接 vsock listener + audit sink daemon。
// 当前 (M1 之前) 只空骨架, 让 workspace 编译可生成 bin。

fn main() {
    eprintln!(
        "host-supervisor: M0/M1 阶段 trait + sink 在位, 无 listener 实现。See crates/host-supervisor/src/lib.rs"
    );
}
