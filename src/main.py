import sys


def generate_asm(name: str) -> str:
    base_addr = 32  # 0x20
    trimmed = name[:10]  # Limit to first 10 characters
    lines = ["; Auto-generated program to write name and jump into it\n"]

    for i, char in enumerate(trimmed):
        lines.append(f"    MOV A, '{char}'")
        lines.append(f"    MOV [{base_addr + i}], A")

    lines.append(
        f"\n    JMP {base_addr}  ; Jump to start of name and crash gloriously\n"
    )
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python gen_name_jump.py <YourName>")
        sys.exit(1)

    name = sys.argv[1]
    asm_code = generate_asm(name)
    print(asm_code)
