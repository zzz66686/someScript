/*
 * dex_dump.js — Android 内存 DEX dump + 少量主动调用还原（FART-lite）
 *
 * 适用场景
 * --------
 * 1. 普通内存 DEX dump；
 * 2. 方法抽取壳：方法第一次进入时，壳才把 code_item 回填到 ART 的执行副本；
 * 3. 对少量指定类逐方法反射调用，补充 App 正常流程没有覆盖的方法，再 dump 全部副本。
 *
 * 快速使用
 * --------
 * 1. 修改下方 CFG：至少填写 PKG；如需主动调用，再填写 TARGET_CLASSES 或 SWEEP_RE。
 * 2. 以 spawn 模式启动（不要 attach 到已经运行的进程）：
 *
 *      frida -U -f com.example.app -l dex_dump.js
 *
 *    命令里的包名必须与 CFG.PKG 一致。如果 CLI 停在 spawn 状态，输入 %resume。
 * 3. 等日志出现 "DUMP DONE"。文件保存在：
 *
 *      /data/data/<包名>/dexdump_<地址>_<大小>_q<quickScore>.dex
 *
 * 4. 使用 root 权限复制后拉回电脑，例如：
 *
 *      adb shell su -c 'cp /data/data/com.example.app/dexdump_*.dex /data/local/tmp/'
 *      adb pull /data/local/tmp/
 *
 * 输出说明
 * --------
 * - DEDUP=false：会保留同一逻辑 DEX 的所有内存副本，避免误删壳已回填的执行副本。
 * - q<quickScore> 是 quickened opcode 数量。抽取壳的已恢复执行副本通常 q 更高；最终仍应
 *   比较同组副本，选择抽取 return 桩最少的一份，不要无条件选择低 q 副本。
 * - 主动调用只应设置真正关心的类。过宽扫描可能触发 fakeClass/蜜罐，甚至进入 native 后崩溃。
 *
 * Frida 17
 * --------
 * Frida 17 的裸 Python create_script() 不再内置 Java bridge；直接使用带 Java bridge 的
 * frida-tools CLI，或在调用本脚本前注入 frida_tools/bridges/java.js。即使 Java bridge 不可用，
 * 15 秒兜底仍会执行纯 native 内存 DEX dump，但不会进行主动调用。
 *
 * 仅用于已获授权的 App、设备和安全研究。
 */
'use strict';

/* 可直接修改的单文件配置。外部 runner 也可以在本脚本前预置全局 CFG 覆盖它。 */
var CFG = (typeof CFG !== 'undefined') ? CFG : {
  PKG: "com.example.app",

  // 精确目标优先；只写确实需要补执行的方法所在类。空数组表示不做精确目标调用。
  TARGET_CLASSES: [
    // "com.example.app.crypto.KeyManager",
    // "com.example.app.crypto.Signer"
  ],

  // targeted：TARGET_CLASSES + 已加载类中匹配 SWEEP_RE 的类；推荐。
  // all：再遍历各 App ClassLoader 声明的未加载类，覆盖更广但风险更高。
  RESTORE_MODE: "targeted",

  // JavaScript 正则源码；默认永不匹配，即只处理 TARGET_CLASSES。
  SWEEP_RE: "(?!x)x",
  EXCLUDE_RE: "(?!x)x",
  SWEEP_MAX: 60,
  RESTORE_CTORS: true,

  // App 初始化等待时间，以及主动调用结束后等待 ART 回填稳定的时间。
  WARMUP_MS: 9000,
  DUMP_AFTER_RESTORE_MS: 1500
};

var PKG           = CFG.PKG || "com.example.app";
var TARGET_CLASSES= CFG.TARGET_CLASSES || [];
var SWEEP_RE      = new RegExp(CFG.SWEEP_RE || "(?!x)x");
var SWEEP_MAX     = CFG.SWEEP_MAX || 60;
var WARMUP_MS     = CFG.WARMUP_MS || 9000;
var DUMP_AFTER_RESTORE_MS = CFG.DUMP_AFTER_RESTORE_MS || 1500;
var RESTORE_MODE  = CFG.RESTORE_MODE || 'targeted';
var EXCLUDE_RE    = new RegExp(CFG.EXCLUDE_RE || "(?!x)x");
var RESTORE_CTORS = (CFG.RESTORE_CTORS !== false);

var OUT_DIR = "/data/data/" + PKG;
var SKIP_FRAMEWORK = true;
var DEEP = false;
var DEDUP = false;   // 保留全部副本；抽取壳恢复后的执行副本通常不是低 quickScore 那份。

function log(s) { try { send("" + s); } catch (e) {} }

/* Android 9+ (API 28) hides greylist/blacklist members from reflection. Un-gate so
 * setAccessible + invoke work on framework-adjacent internals across versions. No-op pre-28. */
function unGateHiddenApi() {
  try {
    var VMRuntime = Java.use('dalvik.system.VMRuntime');
    var rt = VMRuntime.getRuntime();
    rt.setHiddenApiExemptions(Java.array('java.lang.String', ['L']));
    log('  [*] hidden-API exemptions set (L)');
  } catch (e) { /* pre-28 or already exempt — ignore */ }
}

/* ============================================================
 * 1) active-invoke / FART-lite restore
 * ========================================================== */

var BOX = null;
function initBox() {
  BOX = {
    'boolean': function () { return Java.use('java.lang.Boolean').$new.overload('boolean')(false); },
    'byte':    function () { return Java.use('java.lang.Byte').$new.overload('byte')(0); },
    'char':    function () { return Java.use('java.lang.Character').$new.overload('char')(0); },
    'short':   function () { return Java.use('java.lang.Short').$new.overload('short')(0); },
    'int':     function () { return Java.use('java.lang.Integer').$new.overload('int')(0); },
    'long':    function () { return Java.use('java.lang.Long').$new.overload('long')(0); },
    'float':   function () { return Java.use('java.lang.Float').$new.overload('float')(0); },
    'double':  function () { return Java.use('java.lang.Double').$new.overload('double')(0); }
  };
}

// primitive -> boxed zero; everything else -> null (still enters the body)
function dummyArg(cls) {
  var n = cls.getName();
  if (BOX[n]) { try { return BOX[n](); } catch (e) { return null; } }
  return null;
}

function getUnsafe() {
  var Unsafe = Java.use('sun.misc.Unsafe');
  var f = Unsafe.class.getDeclaredField('theUnsafe');
  f.setAccessible(true);
  return Java.cast(f.get(null), Unsafe);
}

// Build an instance so instance methods can be entered. Trying real constructors first also
// RESTORES the constructor bodies; Unsafe.allocateInstance is the version-agnostic fallback
// (uninitialized instance — method bodies may NPE on entry, which is fine).
function makeInstance(cls, ctors, unsafe) {
  if (RESTORE_CTORS && ctors) {
    for (var i = 0; i < ctors.length; i++) {
      try {
        ctors[i].setAccessible(true);
        var pts = ctors[i].getParameterTypes(), a = [];
        for (var j = 0; j < pts.length; j++) a.push(dummyArg(pts[j]));
        return ctors[i].newInstance(a);   // enters + restores ctor body, returns instance
      } catch (e) { /* try next ctor */ }
    }
  }
  if (unsafe) { try { return unsafe.allocateInstance(cls); } catch (e) {} }
  return null;
}

function restoreClass(fqn, unsafe, Modifier) {
  var kls;
  try { kls = Java.use(fqn); }
  catch (e) { return; }   // unloadable / not a real class — skip quietly (honeypots often are)

  var cls = kls.class, methods, ctors = null;
  try { methods = cls.getDeclaredMethods(); }
  catch (e) { log('  [skip] getDeclaredMethods ' + fqn + ' : ' + e); return; }
  if (RESTORE_CTORS) { try { ctors = cls.getDeclaredConstructors(); } catch (e) {} }

  var inst = null, triedInst = false, entered = 0, total = 0;
  for (var i = 0; i < methods.length; i++) {
    var m = methods[i], mod;
    try { mod = m.getModifiers(); } catch (e) { continue; }
    if (Modifier.isAbstract(mod) || Modifier.isNative(mod)) continue; // no dex body to restore
    total++;
    try {
      m.setAccessible(true);
      var ptypes = m.getParameterTypes(), args = [];
      for (var j = 0; j < ptypes.length; j++) args.push(dummyArg(ptypes[j]));
      var recv = null;
      if (!Modifier.isStatic(mod)) {
        if (!triedInst) { triedInst = true; inst = makeInstance(cls, ctors, unsafe); }
        if (inst === null) continue;
        recv = inst;
      }
      try { m.invoke(recv, args); } catch (e) {}   // entering triggers restore; NPE inside is fine
      entered++;
    } catch (e) { /* reflection prep failed, skip */ }
  }
  // if no instance method forced a ctor, still enter each ctor once to restore its body
  if (RESTORE_CTORS && ctors && !triedInst) makeInstance(cls, ctors, unsafe);
  log('  [restore] ' + fqn + '  methods entered=' + entered + '/' + total);
}

// List every class name declared by a classloader's dex files. Walks
// BaseDexClassLoader.pathList.dexElements[].dexFile.entries() — this API shape has been stable
// since Android 5, so it reaches NOT-yet-loaded classes portably across versions. (FART uses the
// same walk.) Returns [] for BootClassLoader / non-BaseDexClassLoader.
function classNamesFromLoader(loader) {
  var out = [];
  try {
    if (("" + loader).indexOf("BootClassLoader") >= 0) return out;
    var BaseDexClassLoader = Java.use('dalvik.system.BaseDexClassLoader');
    var DexPathList = Java.use('dalvik.system.DexPathList');
    var Element = Java.use('dalvik.system.DexPathList$Element');
    var DexFile = Java.use('dalvik.system.DexFile');
    var bdcl = Java.cast(loader, BaseDexClassLoader);
    var pathList = Java.cast(bdcl.pathList.value, DexPathList);
    var elements = pathList.dexElements.value;
    for (var i = 0; i < elements.length; i++) {
      try {
        var el = Java.cast(elements[i], Element);
        var dfv = el.dexFile.value;
        if (!dfv) continue;
        var df = Java.cast(dfv, DexFile);
        var e = df.entries();
        while (e.hasMoreElements()) out.push(e.nextElement().toString());
      } catch (inner) { /* split-dex element without a dexFile — skip */ }
    }
  } catch (e) { /* not a BaseDexClassLoader — skip */ }
  return out;
}

// candidate pool of class names. 'targeted' mode: just the already-loaded classes (cheap, and
// the SWEEP_RE filter keeps it tight). 'all' mode: every class declared by every app classloader
// (reaches not-yet-loaded classes) unioned with loaded classes.
function enumerateAllClassNames(mode) {
  var names = {};
  try { Java.enumerateLoadedClassesSync().forEach(function (n) { names[n] = true; }); } catch (e) {}
  if (mode === 'all') {
    try {
      Java.enumerateClassLoadersSync().forEach(function (loader) {
        classNamesFromLoader(loader).forEach(function (n) { names[n] = true; });
      });
    } catch (e) { log('  [!] enumerateClassLoaders: ' + e); }
  }
  return Object.keys(names);
}

function forceRestore() {
  log('[*] force-restore start (mode=' + RESTORE_MODE + ')');
  unGateHiddenApi();
  var Modifier = Java.use('java.lang.reflect.Modifier'), unsafe;
  try { unsafe = getUnsafe(); }
  catch (e) { log('  [!] Unsafe unavailable: ' + e + ' (falling back to constructors only)'); unsafe = null; }
  initBox();

  var done = {};
  TARGET_CLASSES.forEach(function (c) { done[c] = true; restoreClass(c, unsafe, Modifier); });

  // candidate pool: 'all' = every class in every app classloader; 'targeted' = loaded classes only.
  // SWEEP_RE is the INCLUDE filter in both modes (default matches nothing → you must set it).
  var pool;
  try { pool = enumerateAllClassNames(RESTORE_MODE); }
  catch (e) { pool = []; log('  [!] enumerate classes: ' + e); }
  log('  [*] candidate pool: ' + pool.length + ' class names');

  var extra = [];
  for (var i = 0; i < pool.length; i++) {
    var name = pool[i];
    if (done[name]) continue;
    if (EXCLUDE_RE.test(name)) continue;
    if (SWEEP_RE.test(name)) extra.push(name);
  }

  if (extra.length > SWEEP_MAX) {
    log('  [!] ' + extra.length + ' classes matched, capping to ' + SWEEP_MAX + ' (raise SWEEP_MAX if needed)');
    extra = extra.slice(0, SWEEP_MAX);
  } else {
    log('  [*] ' + extra.length + ' extra classes matched');
  }
  extra.forEach(function (c) { restoreClass(c, unsafe, Modifier); });

  log('[*] force-restore done (' + (1 + extra.length) + '+ classes)');
  send('RESTORE_DONE');
}

/* ============================================================
 * 2) in-memory dex dump  (generic; from frida-dexdump)
 * ========================================================== */

function get_maps_address(dexptr, range_base, range_end) {
  var maps_offset = dexptr.add(0x34).readUInt();
  if (maps_offset === 0) return null;
  var maps_address = dexptr.add(maps_offset);
  if (maps_address < range_base || maps_address > range_end) return null;
  return maps_address;
}
function get_maps_end(maps, range_base, range_end) {
  var maps_size = maps.readUInt();
  if (maps_size < 2 || maps_size > 50) return null;
  var maps_end = maps.add(maps_size * 0xC + 4);
  if (maps_end < range_base || maps_end > range_end) return null;
  return maps_end;
}
function get_dex_real_size(dexptr, range_base, range_end) {
  var dex_size = dexptr.add(0x20).readUInt();
  var maps_address = get_maps_address(dexptr, range_base, range_end);
  if (!maps_address) return dex_size;
  var maps_end = get_maps_end(maps_address, range_base, range_end);
  if (!maps_end) return dex_size;
  return maps_end.sub(dexptr).toInt32();
}
function verify_by_maps(dexptr, mapsptr) {
  var maps_offset = dexptr.add(0x34).readUInt(), maps_size = mapsptr.readUInt();
  for (var i = 0; i < maps_size; i++) {
    if (mapsptr.add(4 + i * 0xC).readU16() === 4096) {
      if (maps_offset === mapsptr.add(4 + i * 0xC + 8).readUInt()) return true;
    }
  }
  return false;
}
function verify(dexptr, range, enable_verify_maps) {
  if (range == null) return false;
  var range_end = range.base.add(range.size);
  if (dexptr.add(0x70) > range_end) return false;
  if (enable_verify_maps) {
    var maps_address = get_maps_address(dexptr, range.base, range_end);
    if (!maps_address) return false;
    if (!get_maps_end(maps_address, range.base, range_end)) return false;
    return verify_by_maps(dexptr, maps_address);
  }
  return dexptr.add(0x3C).readUInt() === 0x70;
}
function verify_ids_off(dexptr, dex_size) {
  var s = dexptr.add(0x3C).readUInt(), t = dexptr.add(0x44).readUInt(),
      p = dexptr.add(0x4C).readUInt(), f = dexptr.add(0x54).readUInt(), m = dexptr.add(0x5C).readUInt();
  return s < dex_size && s >= 0x70 && t < dex_size && t >= 0x70 && p < dex_size && p >= 0x70
      && f < dex_size && f >= 0x70 && m < dex_size && m >= 0x70;
}
function searchDex(deepSearch) {
  var result = [];
  Process.enumerateRanges('r--').forEach(function (range) {
    try {
      Memory.scanSync(range.base, range.size, "64 65 78 0a 30 ?? ?? 00").forEach(function (match) {
        var p = range.file ? range.file.path : null;
        if (p) {
          if (p.startsWith("/data/dalvik-cache/")) return;
          if (SKIP_FRAMEWORK && (p.startsWith("/apex/") || p.startsWith("/system/") || p.startsWith("/system_ext/"))) return;
        }
        if (verify(match.address, range, false)) {
          var dex_size = get_dex_real_size(match.address, range.base, range.base.add(range.size));
          result.push({ addr: match.address, size: dex_size, path: range.file ? range.file.path : null });
        }
      });
      if (deepSearch) {
        Memory.scanSync(range.base, range.size, "70 00 00 00").forEach(function (match) {
          var dex_base = match.address.sub(0x3C);
          if (dex_base < range.base) return;
          if (dex_base.readCString(4) != "dex\n" && verify(dex_base, range, true)) {
            var real_dex_size = get_dex_real_size(dex_base, range.base, range.base.add(range.size));
            if (!verify_ids_off(dex_base, real_dex_size)) return;
            result.push({ addr: dex_base, size: real_dex_size, path: range.file ? range.file.path : null });
          }
        });
      }
    } catch (e) {}
  });
  return result;
}
function setReadPermission(base, size) {
  var end = base.add(size);
  Process.enumerateRanges("---").forEach(function (range) {
    if (range.base < base || range.base.add(range.size) > end) return;
    if (!range.protection.startsWith("r")) Memory.protect(range.base, range.size, "r" + range.protection.substr(1, 2));
  });
}
function readUleb(base, o) {
  var r = 0, s = 0, b;
  do { b = base.add(o).readU8(); r |= (b & 0x7f) << s; o++; s += 7; } while (b >= 0x80);
  return [r >>> 0, o];
}
// count quickened opcodes (0xE3-0xF9): the ART execution copy (restored) is full of them.
function quickScore(base) {
  try {
    var clsN = base.add(0x60).readUInt(), clsOff = base.add(0x64).readUInt(), q = 0, checked = 0;
    for (var i = 0; i < clsN; i++) {
      var cdo = base.add(clsOff + i * 32 + 24).readUInt();
      if (cdo === 0) continue;
      var o = cdo, t;
      t = readUleb(base, o); var sf = t[0]; o = t[1];
      t = readUleb(base, o); var iff = t[0]; o = t[1];
      t = readUleb(base, o); var dm = t[0]; o = t[1];
      t = readUleb(base, o); var vm = t[0]; o = t[1];
      var f2 = sf + iff;
      for (var k = 0; k < f2; k++) { t = readUleb(base, o); o = t[1]; t = readUleb(base, o); o = t[1]; }
      var methods = dm + vm;
      for (var mm = 0; mm < methods; mm++) {
        t = readUleb(base, o); o = t[1];
        t = readUleb(base, o); o = t[1];
        t = readUleb(base, o); var co = t[0]; o = t[1];
        if (co === 0) continue;
        var ins = base.add(co + 12).readUInt();
        if (ins === 0 || ins > 0x40000) continue;
        var buf = new Uint8Array(base.add(co + 16).readByteArray(ins * 2));
        for (var pp = 0; pp + 1 < buf.length; pp += 2) { var op = buf[pp]; if (op >= 0xE3 && op <= 0xF9) q++; }
        if (++checked > 4000) return q;
      }
    }
    return q;
  } catch (e) { return 1e9; }
}
function dumpAll() {
  log("[*] search dex in memory (deep=" + DEEP + ") ...");
  var dexes = searchDex(DEEP);
  log("[*] found " + dexes.length + " candidate dex");
  var ok = 0;
  dexes.forEach(function (d) {
    try {
      try { d._q = quickScore(d.addr); } catch (e) { d._q = -1; }
      setReadPermission(d.addr, d.size);
      var bytes = d.addr.readByteArray(d.size);
      var path = OUT_DIR + "/dexdump_" + d.addr + "_" + d.size + "_q" + d._q + ".dex";
      var f = new File(path, "wb"); f.write(bytes); f.flush(); f.close();
      ok++;
      log("[+] " + path + "  size=" + d.size + "  quick=" + d._q + (d.path ? "  from=" + d.path : ""));
    } catch (e) { log("[-] fail @" + d.addr + " size=" + d.size + " : " + e); }
  });
  log("[*] DUMP DONE: dumped " + ok + "/" + dexes.length + " dex -> " + OUT_DIR);
  send('DUMP_DONE');
}

/* ============================================================ */
var HAS_JAVA = (typeof Java !== 'undefined' && Java.available);
log("[*] Java bridge typeof=" + (typeof Java) + (typeof Java !== 'undefined' ? " available=" + Java.available : ""));
log("[*] agent loaded for " + PKG + ", waiting " + (WARMUP_MS / 1000) + "s for warmup ...");
/* Memory dump is native — do NOT nest it in Java.perform. On some packers,
 * Java.perform after resume can hang forever; ART copies are still in maps. */
setTimeout(function () {
  var dumped = false;
  function doDump(tag) {
    if (dumped) return;
    try {
      log("[*] dump start (" + tag + ")");
      dumpAll();
      dumped = true;
    } catch (e) {
      log('[!] dumpAll fatal: ' + e);
      send('DUMP_DONE');
      dumped = true;
    }
  }

  if (!HAS_JAVA) {
    log('[!] Java bridge unavailable — skip active-invoke and perform native DEX dump only');
    send('RESTORE_DONE');
    doDump('no-java-bridge');
    return;
  }

  try {
    Java.perform(function () {
      try { forceRestore(); }
      catch (e) { log('[!] forceRestore fatal: ' + e + '\n' + (e.stack || '')); send('RESTORE_DONE'); }
      setTimeout(function () { doDump('after-restore'); }, DUMP_AFTER_RESTORE_MS);
    });
  } catch (e) {
    log('[!] Java.perform threw: ' + e);
    send('RESTORE_DONE');
    doDump('java-perform-threw');
  }
  /* If Java.perform never enters, still dump whatever ART has. */
  setTimeout(function () {
    if (!dumped) {
      log('[!] Java.perform still pending — dumping without restore');
      send('RESTORE_DONE');
      doDump('java-perform-hung');
    }
  }, 15000);
}, WARMUP_MS);
