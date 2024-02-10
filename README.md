# Limbo's Gate

## In the beginning...

There was [Heaven's Gate](https://amethyst.systems/zines/valhalla/Valhalla%20%231/articles/HEAVEN.TXT) by Roy G Biv and DefJam, and it was good.
Hackers were granted the ability to break free of the chains of SysWOW64 and burst into 64-bit mode.

Then syscalls got popular and there was [Hell's Gate](https://github.com/am0nsec/HellsGate) by smelly and am0nsec, and it was good. Hackers could now
joyously copy the technique for their EDR evasion kink, celebrating in the shadow of the Bypass.

Then hackers continued to be annoyed as hell at the fact that antivirus keeps hooking The Good Shit and preventing us from collecting our Well 
Deserved Syscalls, and there was [Halo's Gate](https://blog.sektor7.net/#!res/2021/halosgate.md) by rb, and it was good. It is absolutely rude when
antivirus interrupts our hard worked virus development, and this advanced us further toward celebrating the Bypass.

Then Google made searching for any fucking prior research on these godforsaken subjects absolutely impossible and I have no fucking clue if
anyone has actually implemented the use-case I had to develop a new technique for, and so, there was **Limbo's Gate**, and I don't know if it's
worth being called "good" since this is literally just a 32-bit remix of prior research, but hey, Hell's Gate on 32-bit can't be bad, right?

## How It Works

I would strongly encourage you to check out Hell's Gate's paper in particular, as they lay out a lot of the groundwork for why Hell's Gate as a
technique exists. However, its implementation was purely 64-bit, and Windows, being the utter goddamn dinosaur that it is, still supports the
32-bit architecture. In some cases, you need to target 32-bit in particular, either for legitimate for nefarious purposes. If you're digging this
fucking deep into Hell's Gate, you're probably being nefarious for a variety of reasons. Welcome!

If the paper is too long for you, here's how it works. In every exports within ntdll.dll that leads to a kernel syscall, there is a specific
pattern:

```asm
mov eax, syscall_id
mov edx, wow64_syscall_bridge
call edx
ret
```

This ultimately takes a syscall ID and transfers us to 64-bit to perform a kernel syscall, then returns. It's basically the exact same
scenario as described in the Hell's Gate paper, with a sprinkling of Heaven's Gate to really glue things together. Thus, Limbo's Gate,
as Limbo is the first layer of Hell, according to Dante's Inferno.

Anyhow, when importing from the NTDLL PEB entry, syscalls are lifted from kernel-specific functions for us to call later when we need,
thus liberating the syscall from the chains of predictability.

This is absolutely not worthy of a brand-new paper on the subject, and as such, is just a shitpost for you to ponder and potentially use
in your other projects.

## Building

You will need:

* [NASM](https://nasm.us/)
* [Visual Studio with C/C++ support](https://visualstudio.microsoft.com/)
* [CMake](https://cmake.org)

Once everything is installed, simply execute the following commands in the repo's root directory:

```
$ mkdir build
$ cmake ../ -A Win32
$ cmake --build ./ --config Release
```

If all goes well, you should get an exit code of 0.

## Credits

The test program to demonstrate Limbo's Gate is pretty much a copycat of the test program for Hell's Gate, and let's face it, this technique is just a 32-bit remix
of Hell's Gate to begin with, so a majority of the credit goes to smelly and am0nsec for publicizing the technique.
