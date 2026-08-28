"use strict";

setTimeout(function() {
    var libapp = null;
    Process.enumerateModules().forEach(function(m) {
        if (m.name === "libapp.so" && m.size > 0x100000) libapp = m;
    });
    console.log("[*] libapp.so: " + libapp.base + " size=0x" + libapp.size.toString(16));

    var appRanges = Process.enumerateRanges('r--').filter(function(r) {
        return r.base.compare(libapp.base) >= 0 &&
               r.base.compare(libapp.base.add(libapp.size)) < 0;
    });
    console.log("[*] Mapped ranges: " + appRanges.length);

    // Get application package name dynamically
    var packageName = null;
    try {
        // Simplest way to get package name
        var currentApplication = Java.use('android.app.ActivityThread').currentApplication();
        var context = currentApplication.getApplicationContext();
        packageName = context.getPackageName().toString();
    } catch(e) {
        // Fallback to common package names if Java environment is not accessible
        var possiblePackages = ['com.bambulab.creator', 'com.example.app'];
        for (var i = 0; i < possiblePackages.length; i++) {
            try {
                var testPath = '/data/data/' + possiblePackages[i] + '/cache';
                var testFile = new File(testPath + '/test_write', 'w');
                testFile.write('test');
                testFile.close();
                packageName = possiblePackages[i];
                break;
            } catch(e) {}
        }
    }

    var outDir = null;
    if (packageName) {
        outDir = '/data/data/' + packageName + '/cache';
        try {
            // Test if we can write to the directory
            var testFile = new File(outDir + '/test_write', 'w');
            testFile.write('test');
            testFile.close();
            console.log('[*] Using output dir: ' + outDir);
        } catch(e) {
            console.log('[-] Cannot write to ' + outDir + ', trying alternatives');
            // Fallback to other directories if cache directory is not writable
            var fallbackDirs = ['/data/local/tmp', '/sdcard/Download'];
            for (var i = 0; i < fallbackDirs.length; i++) {
                try {
                    var testFile = new File(fallbackDirs[i] + '/test_write', 'w');
                    testFile.write('test');
                    testFile.close();
                    outDir = fallbackDirs[i];
                    console.log('[*] Using fallback output dir: ' + outDir);
                    break;
                } catch(e) {}
            }
        }
    }
    
    if (!outDir) { console.log('[-] No writable directory found!'); return; }

    // Dump each range
    var totalDumped = 0;
    appRanges.forEach(function(r, idx) {
        var offset = r.base.sub(libapp.base);
        var offsetInt = 0;
        try { offsetInt = offset.toInt32(); } catch(e) { offsetInt = parseInt(offset.toString()); }

        var filename = outDir + "/libapp_0x" + offsetInt.toString(16) + ".bin";
        try {
            // Dump in chunks to avoid memory issues
            var chunkSize = 4 * 1024 * 1024;  // 4MB chunks
            var f = new File(filename, "wb");
            var remaining = r.size;
            var pos = 0;
            while (remaining > 0) {
                var toRead = Math.min(remaining, chunkSize);
                var data = r.base.add(pos).readByteArray(toRead);
                f.write(data);
                pos += toRead;
                remaining -= toRead;
            }
            f.close();
            totalDumped += r.size;
            console.log("  [+] " + filename + " (0x" + r.size.toString(16) + " = " +
                        Math.round(r.size / 1024) + "KB, off=0x" + offsetInt.toString(16) + ")");
        } catch(e) {
            console.log("  [-] " + filename + ": " + e.message);
        }
    });

    // Write metadata
    try {
        var mf = new File(outDir + "/libapp_meta.txt", "w");
        mf.write("base=0x" + libapp.base + "\n");
        mf.write("size=0x" + libapp.size.toString(16) + "\n");
        appRanges.forEach(function(r, idx) {
            var off = r.base.sub(libapp.base);
            mf.write("seg" + idx + " off=0x" + off.toString(16) +
                     " size=0x" + r.size.toString(16) + " prot=" + r.protection + "\n");
        });
        mf.close();
        console.log("  [+] metadata written");
    } catch(e) {}

    console.log("\n[*] Total dumped: " + Math.round(totalDumped / 1024 / 1024) + "MB");
    console.log("[*] Pull files from: " + outDir + "/libapp_*");
}, 10000);