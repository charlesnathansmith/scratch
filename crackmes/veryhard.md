## Cracker7525's Very Hard Crackme

https://crackmes.one/crackme/64a0841c33c5d460c17f1f6d

## Challenge
64-bit console application
No apparent packing or obfuscation

Prompt
"Enter the password (Base64 encoded):"

Response
Incorrect answers either return:

```
Wrong password! You failed the crackme test.
```

Or just crash the program.
Validly encoded base64 answers may crash or give the "Wrong password" message with no apparent pattern.

## Diving in
String search in IDA reveals the following code addresses making interesting references:

```
.text:0000000140017281	"Enter the password (Base64 encoded):"
.text:00000001400173D6	"Correct password! You passed the crackme test."
.text:0000000140017490	"Wrong password! You failed the crackme test."
```

Also of note is the "Hidden string": "Eðer bunu görüyorsan þanslýsýn"
Which translates to "If you're seeing this you're in luck", so that's a good start I guess.
Apparently we get this after the "Correct password" message.

The conditional jmp that decides if we succeeded occurs in the last 3 instructions of this section:

```
.text:00000001400173BB                 mov     rcx, [rbp+3D0h+var_298]
.text:00000001400173C2                 call    sub_14001145B
.text:00000001400173C7                 movzx   eax, [rbp+3D0h+var_23C]
.text:00000001400173CE                 test    eax, eax
.text:00000001400173D0                 jz      loc_140017490
```

With the 0-condition being a fail.

There are two paths leading into the comparison section.
One falls out of the decoding loop when a zero condition isn't met and sets the fail condition:

```
.text:00000001400173AB                 jz      short loc_1400173B6
.text:00000001400173AD                 mov     [rbp+3D0h+var_23C], 0
.text:00000001400173B4                 jmp     short loc_1400173BB
```

Another breaks out of the decoding loop with a success condition still set in var_23C:

```
.text:0000000140017323                 mov     eax, [rbp+3D0h+var_31C]
.text:0000000140017329                 cmp     [rbp+3D0h+var_21C], eax
.text:000000014001732F                 jge     loc_1400173BB
```

Before we tackle the decoding loop, we need to know where the password we provide gets stored:

```
.text:0000000140017299                 mov     r8d, eax
.text:000000014001729C                 mov     edx, 1
.text:00000001400172A1                 mov     rcx, cs:?cin@std@@3V?$basic_istream@DU?$char_traits@D@std@@@1@A ; std::basic_istream<char,std::char_traits<char>> std::cin
.text:00000001400172A8                 call    cs:?ignore@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@_JH@Z ; std::basic_istream<char,std::char_traits<char>>::ignore(__int64,int)
.text:00000001400172AE                 lea     rdx, [rbp+3D0h+var_3C8]
.text:00000001400172B2                 mov     rcx, cs:?cin@std@@3V?$basic_istream@DU?$char_traits@D@std@@@1@A ; std::basic_istream<char,std::char_traits<char>> std::cin
.text:00000001400172B9                 call    sub_14001140B
.text:00000001400172BE                 lea     rdx, [rbp+3D0h+var_3C8]
.text:00000001400172C2                 lea     rcx, [rbp+3D0h+var_278]
.text:00000001400172C9                 call    sub_140011140
```

cin is used to read our password into a char buffer.
I'm not going to pretend to know exactly what's happening here,
as I thought the call to sub_14001140B actually read the password into the buffer,
but when I set a breakpoint there lated and it was reached, the password was already loaded into a buffer pointed to by r9.

That's good enough for us, all we care about is where it's going anyway.

If we take a cursory look at sub_140011140, it appears to do the base64 decoding,
presumably putting the result in a buffer pointed to by var_278.

Since that's what we expect to happen, we'll just take it at face value for now that's what it does.
The presumed base64 decoded password gets passed to another function:

```
.text:00000001400172DD                 lea     rcx, [rbp+3D0h+var_278]
.text:00000001400172E4                 call    sub_1400110B4
```

Which gets a pointer the the decoded string buffer.

This would be a good time to hop over into a debugger and start verifying some of our assumptions.
We can open it in x64dbg, and let it run passing exceptions until it reaches the password prompt.
It would probably make for a better work flow just debug it through IDA, but I know my way around x64dbg better.

As mentioned above, I set a breakpoint on the call to sub_14001140B.
The running code is based to a different address than the listing in IDA, but we can still easily locate instructions by file offset.

For the password, we need to enter a value that doesn't completely crash the program.
I settled on "ZmFzZGFzZg==" which decodes to "fasdasf".
It's not very pretty, but it works and we won't mistake any other string we see for it.

We may sometimes break somewhere in the middle of NT code.
This is probably from routine exception handling they use for one reason or another.
If we hit play or execute until return a few times, we eventually make it back to our breakpoint.

When the breakpoint was hit, the encoded password was stored at 22F42137A00, which happened to be in r9 before the call.

We step over the call and step up to the call to the presumed base64 decode function (sub_140011140).
rcx points to uninitialized memory as expected.
rdx looks like this:

```
0000007DF6DAF688  00 03 13 42 2F 02 00 00 6D 46 7A 5A 47 46 7A 5A  ...B/...mFzZGFzZ  
0000007DF6DAF698  67 3D 3D 00 00 00 00 00 0B 00 00 00 00 00 00 00  g==.............  
```

Which appears to be a std::string holding our password sans the first character.
Now it's starting to make sense why the cin calls were giving confusing results.
It reads and ignores the first character, then stores the rest in a string.

This also means if we want to locate our base64-decoded password in memory, we're going to have to add a throwaway character to the beginning of it.

We set our break here right before the base64 decode call, then restart the program and feed it this password: "AZmFzZGFzZg=="
Which is the same as before, just with an extra character at the beginning that will get discarded.

Now when we hit our breakpoint, rdx looks like this:

```
0000003D4B3DF698  A0 0D 0D 4F A5 01 00 00 5A 6D 46 7A 5A 47 46 7A  ...O¥...ZmFzZGFz  
0000003D4B3DF6A8  5A 67 3D 3D 00 00 00 00 0C 00 00 00 00 00 00 00  Zg==............  
```

Which will hopefully decode correctly. We point one of our dumps to rcx and step over the call to sub_140011140.
After the call, the memory passed in via rcx looks like this:

```
0000003D4B3DF7E8  20 0B 0D 4F A5 01 00 00 66 61 73 64 61 73 66 00   ..O¥...fasdasf.  
0000003D4B3DF7F8  00 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00  ................  
```

Awesome.  A std::string holding our decoded password!

```
.text:00000001400172CF                 movsxd  rax, [rbp+3D0h+var_31C]
.text:00000001400172D6                 mov     [rbp+3D0h+Size], rax
.text:00000001400172DD                 lea     rcx, [rbp+3D0h+var_278]
.text:00000001400172E4                 call    sub_1400110B4
```

The value 0xA00 gets copied into the variable that will be used as size in a memcpy (more on this size later.)
var_278 is our std:string with the decoded password, which gets passed to sub_1400110B4.
sub_1400110B4 just returns a pointer to the string's ASCII char buffer

```
.text:00000001400172E9                 mov     rcx, [rbp+3D0h+Size]
.text:00000001400172F0                 mov     r8, rcx         ; Size
.text:00000001400172F3                 mov     rdx, rax        ; Src
.text:00000001400172F6                 mov     rcx, [rbp+3D0h+var_298] ; void *
.text:00000001400172FD                 call    j_memcpy
```

The ASCII decoded password gets memcpy'd to a buffer at rbp+138 (along with a lot of other junk, since the size is 0xA00).
During my run, this new buffer is at 1A54F0D6010.

I occasionally into exceptions buried in libc or wherever memcpy came from when trying to step over it, so I just set a breakpoint after and ran until I cleared it.
The memcpy does exactly what we expect it to, and our decoded password is now in its new buffer.

Finishing up the setup we have:

```
.text:0000000140017302                 mov     [rbp+3D0h+var_23C], 1
.text:0000000140017309                 mov     [rbp+3D0h+var_21C], 0
.text:0000000140017313                 jmp     short loc_140017323
```

Where var_23C = 1 is our "Correct password" flag that gets 0'd out if something happens in the verification loop it doesn't like,
and var_21C is a counter.

Now that we've got all that down, let's go decompile the verification loop in Ghidra and see if we can make some sense out of what data it's working on:

```
local_244 = '\x01';
for (local_224 = 0; local_224 < local_324; local_224 = local_224 + 1) {
  local_34 = (uint)*(char *)((longlong)local_2a0 + (longlong)local_224);
  local_30 = (size_t)local_224;
  local_28 = thunk_FUN_140016c10((longlong)local_3d0);
  pcVar3 = (char *)thunk_FUN_1400148f0((longlong)local_3d0,local_30 % local_28);
  if (local_34 != (*pcVar3 + local_224 ^ local_224 + 1U)) {
	local_244 = '\0';
	break;
  }
}
```

We have to go back a bit through the decompilation and figure out what it's calling variables we've already idendified.
After renaming and retyping what we can, we end up with this:

```
flag = '\x01';
for (count = 0; count < buf_size; count = count + 1) {
  local_34 = (uint)decoded_ascii_pass[count];
  local_30 = (size_t)count;
  local_28 = thunk_FUN_140016c10((longlong)str_b64pass);
  pcVar3 = (char *)thunk_FUN_1400148f0((longlong)str_b64pass,local_30 % local_28);
  if (local_34 != (*pcVar3 + count ^ count + 1U)) {
	flag = '\0';
	break;
  }
}
```

Where str_b64pass is a pointer to the std::string struct holding our base64-encoded password (minus the first character still.)
If we look at thunk_FUN_140016c10((longlong)str_b64pass), we see it returns str_b64pass+0x18, which is a pointer to the strlen of the encoded password.

Now we just need to know what thunk_FUN_1400148f0 is doing.
It gets passed the str_b64pass std::string pointer, and also local_30 % local_28, which is count % str_b64pass.size().
As count increases, in theory this second argument just keeps looping around from 0 to str_b64pass.size() - 1

In reality, the decoded password should always be shorter than the encoded password, so this wrap-around should never occur.

By glancing at the body of thunk_FUN_140016c10 and errors it throws, I think we can be fairly confident it's just the string indexing operator [].
It's returning a char*, but it gets dereferenced in the actual comparison, so it's just retrieving a single character at a position.

Putting all of this together, and treating str_b64pass as a string rather than a string pointer this time, we get:

```
for (count = 0; count < buf_size; count = count + 1) {
  uint cur_ascii_char = (uint)decoded_ascii_pass[count];
  char cur_b64_char = str_b64pass[count % str_b64pass.size()]
  if (cur_ascii_char != (cur_b64_char + count) ^ (count + 1)) {
	flag = '\0';
	break;
  }
}
```

I added parentheses to the comparison because order of operations with bitwise operators always throws me off.
I checked against the assembly to make sure they're ordered correctly here.

Something seems off with buf_size to me.  On my runs, it was still 0xA00 from the memcpy, which is way too big.
It's going to be pulling in all kinds of junk past the end of the ASCII password buffer.

Tracing it back to where it's set, we run into this madness:

```
local_350 = local_2e0.tm_mday;
iStack_34c = local_2e0.tm_mon + 1;
iStack_348 = local_2e0.tm_year + 0x76c;
if (iStack_348 == 0x7e7) {
	iVar1 = local_2e0.tm_mday + iStack_34c + 0x7e7;
	buf_size = ((int)(iVar1 + (iVar1 >> 0x1f & 7U)) >> 3) * 10
	...
```

Yep.  We have to set our system date to a particular value to control the buffer size.

## The Buffer Size Problem

The first question is can we just make buf_size = 0? That would skip the verification loop entirely.

Our friend likely already thought of that, as access is only allowed when tm_year + 0x76c == 0x7e7,
which means only dates in 2023 are valid since tm_year = 0 represents 1900.

We can generate a table and see what kind of sizes we do have to work with:

```
/*---------- Buffer Size Generator ----------*/
#include <iostream>
#include <map>

constexpr size_t year = 2023 - 1900;
constexpr size_t num_days[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
constexpr char month_names[12][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

struct date { size_t month, day; };

size_t buf_size(size_t month, size_t day)
{
	size_t iVar1 = day + (month + 1) + 0x7e7;
	return ((iVar1 + (iVar1 >> 0x1f & 7)) >> 3) * 10;
}

int main()
{
	std::map<size_t, date> sizes;

	for (size_t month = 0; month < 12; month++)
		for (size_t day = 1; day <= num_days[month]; day++)
			sizes[buf_size(month, day)] = { month, day };

	std::cout << "Size (dec)\tMonth\tDay\n";

	for (auto& it : sizes)
		std::cout << it.first << "\t\t" << month_names[it.second.month] << '\t' << it.second.day << '\n';

	return 0;
}
/*-------------------------------------------*/
```

Here are the results:

```
Size (dec)      Month   Day
2530            Jul     1
2540            Dec     4
2550            Dec     12
2560            Dec     20
2570            Dec     28
2580            Dec     31
```

So much for a 0-sized buffer.
The other days of the year map to one of the same buffer sizes and so are irrelevant.

It appears we are going to have to generate a massive password that base64 decodes into something that passes the verification char by char.

## Examining the validation loop

Let's look at how base64 encoding works.

To encode an input string or byte stream, it is broken into 6-bit segments, and each segment is treated as a number that indexes into a table of printable characters,
which you can see in full here: https://datatracker.ietf.org/doc/html/rfc4648#page-6

What makes the verification loop so difficult to deal with here is that each byte (8 bits) of the encoded password only translates into 6 bits of a decoded byte,
and this misalignment becomes increasingly skewed as we progress through each buffer.

Let's try to manually work out a few bytes then see if we can automate the rest.
As a reminder, the condition we have to meet is:

```
cur_ascii_char == (cur_b64_char + count) ^ (count + 1)
```

To make this section easier to follow, let's rephrase this as follows:

```
decoded[count] == (encoded[count] + count) ^ (count + 1)
```

For the first pass of the loop, count = 0, so this reduces to:

```
decoded[0] == encoded[0] ^ 1
```

We need to keep in mind that the encoded byte only affects the first 6-bits of the decoded byte,
with the last 2 bits being determined by the next encoded byte.
All pairs that meet the following condition are potentially a valid start:

```
decoded[0] & b11111100 == (encoded[0] ^ 1) & b11111100 = encoded[0] & b11111100

which is equivalent to

decoded[0] & 0xfc == b64decode(encoded[0]) << 2
```

Searching for matches:

```
constexpr char encoded[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::cout << std::hex;

for (char i = 0; i < 64; i++)
    if ( (i << 2) == (encoded[i] & 0xfc) )
        std::cout << encoded[i] << '\t' << ((unsigned int) i << 2) << '\n';
```

The only pair we get is 'V' (b01010110) decoding to 010101xx

Since there is only one match, we can plug this back into the comparison to find what the last 2 bits of the decoded value must be:


```
decoded[0] == encoded[0] ^ 1
b010101xx  == (b01010110 ^ 1) = b01010111
```

Those last two bits have to be considered when finding the 2nd encoded char since they are derived from it.
Solving the second pair takes a bit more care.
There are two conditions we need to be mindful of.

We need to satisfy the last two bits of decoded[0]:

```
b64decode(encoded[1]) >> 4 == decoded[0] & b00000011 = b11
```

And pass the comparison for this round of the loop.
Count is now 1, but we can use any encoded/decoded pair that match by the first 4 bits,
since the next 4 bits will be derived from encoded[2].

```
decoded[1] == (encoded[1] + 1) ^ (1 + 1)
decoded[1] & b11110000 == ((encoded[1] + 1) ^ 2) & b11110000
```

And... this has no solution.
Not with base64 digits as inputs, at least.

Let's look at how the decoding function handles '=' padding and non-base64 characters.

## Diving deeper

We can go back and break on the call to base64 decode and start feeding in malformed inputs to see what comes out.
I've gone ahead and renamed everything here by this point for clarity:

```
.text:00000001400172BE                 lea     rdx, [rbp+3D0h+str_encoded]
.text:00000001400172C2                 lea     rcx, [rbp+3D0h+str_decoded]
.text:00000001400172C9                 call    j_base64_decode
```

Let's try the password "Aabc=defghijklmnopqrstuv", where the leading A is the throwaway character that gets ignored, and the '=' padding is invalidly placed.
Here is the output string produced:

```
00000040CEAFF4D8  C0 03 F2 DE C0 01 00 00 69 B7 00 00 00 00 00 00  À.òÞÀ...i·......  
00000040CEAFF4E8  00 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00  ................  
00000040CEAFF4F8  0F 00 00 00 00 00 00 00 CC CC CC CC CC CC CC CC  ........ÌÌÌÌÌÌÌÌ  
```

It decodes up to the padding byte then stops, and the size (decoded_string + 0x18) is set to 02, even though the input is much longer.
This potentially lets us start breaking the requirement that the values being compared each loop be related via base64 encoding,
at least so a certain extent.

This would potentially be useful if it were the decoded string that gets read in a loop, instead of the encoded one (via "count % str_b64pass.size()").

We can generate null decoded strings easily with password inputs like "A=abcedfg...." or "A*abcdef..."
```
0000007F133AF608  70 4D 1A D6 40 02 00 00 00 00 00 00 00 00 00 00  pM.Ö@...........  
0000007F133AF618  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................  
0000007F133AF628  0F 00 00 00 00 00 00 00 CC CC CC CC CC CC CC CC  ........ÌÌÌÌÌÌÌÌ  
0000007F133AF638  CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC  ÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌ  
0000007F133AF648  CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC  ÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌ  
0000007F133AF658  CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC  ÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌ  
0000007F133AF668  CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC  ÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌ  
0000007F133AF678  CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC  ÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌ  
0000007F133AF688  CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC  ÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌ  
0000007F133AF698  CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC  ÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌ  
0000007F133AF6A8  CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC  ÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌ  
0000007F133AF6B8  CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC  ÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌ  
0000007F133AF6C8  CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC  ÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌ  
0000007F133AF6D8  CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC  ÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌ  
0000007F133AF6E8  CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC  ÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌÌ  
0000007F133AF6F8  C0 07 9A 76 FD 7F 00 00 D0 F1 19 D6 40 02 00 00  À..vý...Ðñ.Ö@...  
```

If we knew what the string's memory from the beginning of it's buffer out to 2530 bytes looked like,
then we could easily generate a working password without issue, but unfortunately we run into dynamic data after around 238 bytes.

I'm stuck at this point.  I haven't thoroughly fuzzed or reverse engineered the base64 decoding function to make sure there isn't some other anomalous behavior that would be exploitable, but I've thrown quite a bit at it and don't see a way forward there.

The memcpy of the decoded string seems odd and maybe deserve a second look as well.
