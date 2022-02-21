# iOS kernel heap memory profiler


![](gif.gif)

Watch your iOS kernel heap live as you groom it.

This is a kernel heap memory profiler built onto [xnuspy](https://github.com/jsherman212/xnuspy/) that allows you to trace kernel heap allocations and freeing done through some of the (not all) allocator/freeing functions.

Hooks:
- `kernel_memory_allocate`
- `kmem_free`
to log them to syslog.

## Requirements

1. Your device must be [checkra1n](https://checkra.in/)'able.

## Usage

1. Grab kernelcache for your device/iOS version (You can extract it from [ipsw](https://ipsw.me/) files).
2. Open [kernel_hooks.c](kernel_hooks.c). You'll see a bunch of hardcoded addresses (iPhone X iOS 14.6). You'll need to change them with the ones you obtained from your own kernelcache.
3. Open kernelcache of your own device in a reverse engineering tool (IDA, Ghidra etc.).
    1. Search for string `kernel_memory_allocate: VM is not ready`. The only xref to that is the function `kernel_memory_allocate()`. Set `ADDROF_KERNEL_MEMORY_ALLOCATE` in `kernel_hooks.c` with that.
    2. Search for string `kmem_free`. The only xref to that is the function `kmem_free()`. Set `ADDROF_KMEM_FREE` in `kernel_hooks.c` with that.
    3. Search for string `trying to kalloc(Z_NOFAIL) with a large size (%zd)`. The only xref to that is a function that has 2 calls to `kernel_memory_allocate()` (note: IDA may fail decompiling this function (`kalloc_large()`), use IDA's disassembler; or Ghidra). Return address of the first `kernel_memory_allocate()` (that is, the address of first instruction right below the `BL kernel_memory_allocate`) is the indicator we use to detect kalloc_map allocations. Set `ADDROF_KALLOC_MAP_INDICATOR` with that return address.
    4. While at it, set `ADDROF_KALLOC_MAP_IS_FULL_INDICATOR` with the return address of the second call to `kernel_memory_allocate()` ([This code in the XNU](https://github.com/apple/darwin-xnu/blob/a1babec6b135d1f35b2590a1990af3c5c5393479/osfmk/kern/kalloc.c#L803-L814) is what we use to detect kalloc_map/kernel_map allocations).
4. Run `make` to compile `kernel_hooks`.
5. Download and compile [xnuspy](https://github.com/jsherman212/xnuspy/).
6. Install xnuspy pongoOS module to your device as described in [xnuspy's usage](https://github.com/jsherman212/xnuspy/#usage).
7. Upload [`klog` of xnuspy](https://github.com/jsherman212/xnuspy/#logging) to your device (`klog` is like `dmesg` with live feed).
8. Upload `kernel_hooks` to your device (to e.g `/var/root/`).
9. SSH into the device and run `./kernel_hooks`. If kernel panics while installing hooks, reinstall xnuspy module to your device (step 6) and re-run `./kernel_hooks`. Keep this terminal open (press ctrl+c anytime to uninstall hooks).
10. On a second terminal, run `klog` on the device, `grep` our logs, and `tee` its output into your pc for further analysis; like:
    1. `ssh -p2222 root@localhost "stdbuf -o0 ./klog | grep 'caller: '" | tee /tmp/klog_data`
11. On a third terminal, run `python3 ./analyzer/spray_analyze.py /tmp/klog_data` to get a live heap layout overview.

## Limitations & Bugs

- Since we hook only two functions, the profiling is not that much precise. This way we only track big chunks (such as size > 0x4000). If you want to track smaller allocations, you'll probably need to hook `kalloc_ext` and possibly some others. But thinking of how many calls to `kalloc_ext` is performed in a second, your device may run into an unstable/slow state and your syslog file size may blow up.
- xnuspy may run into an unstable state after running for a long time (e.g half a day). If you notice this, rebooting is what you need to do.
- Verbatim from xnuspy's README: If you get `open: Resource busy` after running `klog`, run this command `launchctl unload /System/Library/LaunchDaemons/com.apple.syslogd.plist` and try again (P.S: You won't see the error message, due to `grep`ping or not redirecting stderr, you'll just see it's not working. Do it).
- If kernel panics while installing hooks, reinstall xnuspy module to your device (step 6) and re-run `./kernel_hooks`.

## Tips

- If you use iterm2, use "Add trigger" feature of it to highlight/colorize the output as shown in the screenshot above.
- To filter by process name, just add another grep: `stdbuf -o0 ./klog | grep "caller:" | grep <process_name>`

## Credits

- PARS Defense
- Justin Sherman for creating xnuspy 
