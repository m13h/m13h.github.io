# Burning skullz

> The principle is dead simple - Guess the secret to get the flag
>
> Hint: The flag might not reside in clear-text in the WASM.
> Hint 2: I guess the flag is somehow encrypted. If only we had a secret key 🤷‍♂️.
>
> Author: fabian|nviso

The challenge description links to a web site, upon entering it we are presented with an interactive burning skull 3D model and a text input field labeled "SECRET". Apparently we are supposed to enter some sort of secret. Trying random input we get a "Hash incorrect" response.

I noticed that when the page loads there is a GET request for a file "index.wasm", so this is probably a wasm reverse challenge. The page source also contains the following:

```javascript
var f = Module.cwrap('breakTheSkull', 'string', ['string']);

function notify() {
var input = $("#inputPassword").val();
alert(f(input));
}

$("button").on( "click", notify );
```

Ok, so we are looking for a function called 'breakTheSkull', which is probably inside index.wasm. There is also an `index.js` that you can look through to confirm it.

To disassemble / decompile index.wasm I used [wabt](https://github.com/WebAssembly/wabt). It contains both a decompiler to a C-like language, and a disassembler outputting a WAT file. I ended up using both.

Looking at the output from wasm-decompile, we see that there is a lot of code, around 18000 lines. We find the breakTheSkull function:

```javascript
export function breakTheSkull(a:int):int {
  var b:int = g_a;
  var c:int = 16;
  var d:int_ptr = b - c;
  g_a = d;
  var e:int = 1952;
  d[3] = a;
  d[2] = e;
  var f:int = 1;
  d[0] = f;
  var g:int = 1046;
  f_pc(g, d);
  var h:int = 1;
  var i:int_ptr = 0;
  i[624] = h;
  var j:int_ptr = 0;
  var k:int = j[624];
  var l:int = d[3];
  var m:int = d[2];
  var n:int = call_indirect(l, m, k);
  var o:int = 16;
  var p:int = d + o;
  g_a = p;
  return n;
}
```

I couldn't figure out the `f_pc` function at first, so I focused on the `call_indirect` call. To understand how `call_indirect` works, I read up on it at [https://developer.mozilla.org/en-US/docs/WebAssembly/Understanding_the_text_format](https://developer.mozilla.org/en-US/docs/WebAssembly/Understanding_the_text_format), which is a really great resource. The function invoked by `call_indirect` is specified by an index into a table defined by `elem`, which contains function IDs. The index for the call in breakTheSkull is given by the third argument to `call_indirect`, which is 1.

Since I couldn't find the values of the elem table in the decompiled output, I looked at the disassembly:

```wat
(elem (;0;) (i32.const 1) func 11 69 70 91 90 92)
```

`i32.const 1` means the table starts at index 1, so we want function 11. Locating that function in the disassembly reveals that it is the function just below breakTheSkull, which is called `f_l` in the decompiled output. Tracing through `f_l` and its calls to other functions, we see that it malloc's some buffers of 20 bytes. Already here I guessed sha1 based on the "Invalid hash" message. Checking some of the constants used confirms it is sha1.

So it calculates sha1 of the input, XORs it with a 20 byte constant found at offset 1088 in the data section. The data sections of the wasm program is given by several byte arrays found in the decompiled/disassembled outputs:

```javascript
data d_bbbbbbbbbbbbbbbbsaltplk3UQgi(offset: 1024) = 
  "bbbbbbbbbbbbbbbb\00salt\00%p\0a\00\00\00\00\00\00\00\9fl\df#\f4k:3*\ad"
  "\e3;+\ea\0cU\9b\13Q\f7\00\00\00\00\00\00\00\00\00\00\00\00g\c6isQ\ffJ\ec"
  ")\cd\ba\ab\f2\fb\e3F|\c2T\f8Hash incorrect\00\00\00\00\00\00\00\00\00\00"
  etc
```

The XOR key is then at offset 1088 - 1024 = 64 in this array. This result is compared against another 20 byte constant, and outputs the "Incorrect hash" message if it doesn't match. From this we can recover the hash of the correct secret.

Further, we see the hashed secret along with the "bbbbbbbbbbbbbbbb" constant used as input to a function that looks like the key scheduler function of a symmetric cipher (called `f_na`), followed by a function which takes what looks like a ciphertext as input (called `f_ta`). The suspected ciphertext can be found in the second data array at offset 1968 - 1952 = 16:

```javascript
data d_10009zKAV_XItg3P(offset: 1952) = 
  "10.0.0.9\00\00\00\00\00\00\00\00\fc\a7\9c\e0\0c\8a\bazK\fbA\06\19\e8V_"
  "X\c8\fe\89\b9I^}\ef\ee\b1\f9\0f:\10\f3,\9c\e7\ac\f5\99$\c5t\c5\b1\a3;["
  "g(\fd\1f\b0\003\00\00\00\00\00\00\00\00\00\00\00\80\00\00\00\00\00\00\00"
```

Looking closer at the first function I recognized it as a 10-round AES key scheduler, we also see the AES sbox constants being used.

The ciphertext is 51 bytes long, so it's natural to assume a streaming mode is used, which is confirmed by a closer look at the encryption function. I tried different modes and OFB mode decrypts the first block correctly:

```
b'CSR{Linux ...bec6\xa7\x98SV\x81yV\x1fq\xf4\x18\x9e\x03F\xfdh-\xf4\xbb*\x84\xdeE\xa8\xe25i\x98\xbeZn\xa2\xda*'
```

At this point I forwarded it to my team mate fsh/tope; he realized that it was a variant of CTR mode using "bbbbbbbbbbbbbbbb" as the initial nonce/counter. The below code then decrypts the flag.

```python
from Crypto.Cipher import AES

hash1 = bytes.fromhex("9f6cdf23f46b3a332aade33b2bea0c559b1351f7")
hash2 = bytes.fromhex("67c6697351ff4aec29cdbaabf2fbe3467cc254f8")

key = bytes([x^y for x,y in zip(hash1,hash2)])[:16]
iv = bytearray(b"b"*16)

cipher_text = b'\xfc\xa7\x9c\xe0\x0c\x8a\xbazK\xfbA\x06\x19\xe8V_X\xc8\xfe\x89\xb9I^}\xef\xee\xb1\xf9\x0f:\x10\xf3,\x9c\xe7\xac\xf5\x99$\xc5t\xc5\xb1\xa3;[g(\xfd\x1f\xb0'
block_count = (len(cipher_text)+15) // 16

aes = AES.new(key, AES.MODE_ECB)

key_stream = b""
for _ in range(block_count):
    key_stream += aes.encrypt(iv)
    iv[15] += 1

plain_text = [c^k for c,k in zip(cipher_text,key_stream)]
print(bytes(plain_text))
```

```
b'CSR{Linux ...because life is too short for reboots}'
```
