"use strict";

// Wait 10 seconds, then dump bambu_networking.dll. No hooks, no Interceptor,
// nothing in the module is patched -- so the dumped bytes are the real
// in-memory contents, including correct first instructions of every function.
//
// Usage:
//   frida -U -n "bambu-studio.exe" -l dump_dll_clean.js
//   Use the app for 10 seconds (log in, open Devices, send a job, etc.) so
//   the packer decrypts as many code pages as possible. The dump fires
//   automatically after 10 seconds.

var moduleName = "bambu_networking.dll";
var outPrefix  = "C:\\temp\\bambu_net4_";
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
    console.log("[*] You can detach Frida now and rebuild with rebuild_dll.py");
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
