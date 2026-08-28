"use strict";

// Wait 10 seconds, then dump a Linux shared library / executable from memory.
// No hooks, no Interceptor, nothing in the module is patched -- so the dumped
// bytes are the real in-memory contents, including correct first instructions
// of every function (important for packed/encrypted binaries that decrypt
// pages on demand).
//
// Usage:
//   frida -U -n <process> -l dump_elf.js
//   frida -U -f /path/to/binary -l dump_elf.js
//   Exercise the app for 10 seconds (trigger the code paths you care about)
//   so the packer decrypts as many code pages as possible. The dump fires
//   automatically after 10 seconds.
//
// Output:
//   /tmp/<modname>_0x<rva>.bin    one file per readable range
//   /tmp/<modname>_meta.txt       base, size, segment list

var moduleName = "local_server";          // <-- change to the .so / executable name
var outDir     = "./";
var DELAY_MS   = 10000;

function dumpModule() {
    var mod = Process.findModuleByName(moduleName);
    if (!mod) {
        console.log("[-] " + moduleName + " not loaded");
        return;
    }
    var modBase = mod.base;
    var modEnd  = mod.base.add(mod.size);
    console.log("[*] " + moduleName + " base=" + modBase +
                " size=0x" + mod.size.toString(16));

    // Trim the trailing .so / .dll / .bin off the module name for the prefix.
    var stem = moduleName.replace(/\.[^.]+$/, "");
    var outPrefix = outDir + "/" + stem + "_";

    var ranges = Process.enumerateRanges('r--').filter(function (r) {
        return r.base.compare(modBase) >= 0 && r.base.compare(modEnd) < 0;
    });
    console.log("[*] " + ranges.length + " readable ranges");

    var totalBytes = 0;
    ranges.forEach(function (r) {
        var off      = r.base.sub(modBase);
        var filename = outPrefix + "0x" + off.toString(16) + ".bin";
        try {
            var f = new File(filename, "wb");
            var pos = 0;
            var remaining = r.size;
            var chunkSize = 4 * 1024 * 1024;
            while (remaining > 0) {
                var n = Math.min(remaining, chunkSize);
                f.write(r.base.add(pos).readByteArray(n));
                pos       += n;
                remaining -= n;
            }
            f.close();
            totalBytes += r.size;
            console.log("  [+] " + filename + " (" +
                        Math.round(r.size / 1024) + "KB " + r.protection + ")");
        } catch (e) {
            console.log("  [-] " + filename + ": " + e.message);
        }
    });

    try {
        var mf = new File(outPrefix + "meta.txt", "w");
        mf.write("module=" + moduleName + "\n");
        mf.write("base=" + modBase + "\n");
        mf.write("size=0x" + mod.size.toString(16) + "\n");
        ranges.forEach(function (r, idx) {
            mf.write("seg" + idx +
                     " off=0x"  + r.base.sub(modBase).toString(16) +
                     " size=0x" + r.size.toString(16) +
                     " prot="   + r.protection + "\n");
        });
        mf.close();
    } catch (e) {
        console.log("[-] meta.txt: " + e.message);
    }

    console.log("\n[*] " + Math.round(totalBytes / 1024 / 1024) + "MB written to " +
                outPrefix + "*");
    console.log("[*] You can detach Frida now and rebuild with rebuild_elf.py");
}

function waitForModuleAndArm() {
    var mod = Process.findModuleByName(moduleName);
    if (!mod) {
        setTimeout(waitForModuleAndArm, 200);
        return;
    }
    console.log("[*] " + moduleName + " loaded at " + mod.base +
                "  size=0x" + mod.size.toString(16));
    console.log("[*] dumping in " + (DELAY_MS / 1000) +
                "s -- exercise the app NOW to decrypt as many pages as possible");
    setTimeout(dumpModule, DELAY_MS);
}

waitForModuleAndArm();
