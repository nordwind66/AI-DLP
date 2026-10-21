//! Minimal, runtime-loaded (dlopen) binding to Hyperscan / Vectorscan (`libhs`).
//!
//! Why dlopen instead of linking: the same binary must run on Windows (where libhs is normally not
//! available) and on Linux hosts without it. If the library cannot be loaded, [`Hyperscan::load`]
//! returns an error and the engine reports the `hyperscan` detector as *degraded* and uses the
//! portable `regex` path. No result depends on Hyperscan being present: it is used strictly as a
//! **prefilter** (HS_FLAG_PREFILTER | SINGLEMATCH). A prefilter may report false positives but
//! never false negatives, and every candidate is re-verified with the exact Go-compatible regex
//! (`eval.rs`), so enabling Hyperscan cannot change which entities are produced.
use libloading::{Library, Symbol};
use parking_lot::Mutex;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::ptr;
use std::sync::Arc;

type HsDb = c_void;
type HsScratch = c_void;
#[repr(C)]
struct HsCompileError {
    message: *mut c_char,
    expression: c_int,
}
type MatchCb = extern "C" fn(id: c_uint, from: u64, to: u64, flags: c_uint, ctx: *mut c_void) -> c_int;

const HS_MODE_BLOCK: c_uint = 1;
pub const HS_FLAG_DOTALL: c_uint = 2;
const HS_FLAG_SINGLEMATCH: c_uint = 8;
const HS_FLAG_UTF8: c_uint = 32;
const HS_FLAG_PREFILTER: c_uint = 128;

struct Api {
    _lib: Library,
    compile_multi: unsafe extern "C" fn(*const *const c_char, *const c_uint, *const c_uint, c_uint, c_uint, *const c_void, *mut *mut HsDb, *mut *mut HsCompileError) -> c_int,
    compile: unsafe extern "C" fn(*const c_char, c_uint, c_uint, *const c_void, *mut *mut HsDb, *mut *mut HsCompileError) -> c_int,
    free_compile_error: unsafe extern "C" fn(*mut HsCompileError) -> c_int,
    alloc_scratch: unsafe extern "C" fn(*const HsDb, *mut *mut HsScratch) -> c_int,
    clone_scratch: unsafe extern "C" fn(*const HsScratch, *mut *mut HsScratch) -> c_int,
    free_scratch: unsafe extern "C" fn(*mut HsScratch) -> c_int,
    free_database: unsafe extern "C" fn(*mut HsDb) -> c_int,
    scan: unsafe extern "C" fn(*const HsDb, *const c_char, c_uint, c_uint, *mut HsScratch, MatchCb, *mut c_void) -> c_int,
    version: unsafe extern "C" fn() -> *const c_char,
}

fn load_api() -> Result<Api, String> {
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(p) = std::env::var("DLP_HYPERSCAN_LIB") {
        candidates.push(p);
    }
    #[cfg(target_os = "windows")]
    candidates.extend(["hs.dll".into(), "libhs.dll".into(), "vectorscan.dll".into()]);
    #[cfg(not(target_os = "windows"))]
    candidates.extend(["libhs.so.5".into(), "libhs.so".into(), "libhs.5.dylib".into()]);
    let mut last = String::from("no candidates");
    for c in candidates {
        match unsafe { Library::new(&c) } {
            Ok(lib) => unsafe {
                macro_rules! sym {
                    ($n:expr) => {{
                        let s: Symbol<_> = lib.get($n).map_err(|e| format!("missing symbol: {e}"))?;
                        *s
                    }};
                }
                let api = Api {
                    compile_multi: sym!(b"hs_compile_multi\0"),
                    compile: sym!(b"hs_compile\0"),
                    free_compile_error: sym!(b"hs_free_compile_error\0"),
                    alloc_scratch: sym!(b"hs_alloc_scratch\0"),
                    clone_scratch: sym!(b"hs_clone_scratch\0"),
                    free_scratch: sym!(b"hs_free_scratch\0"),
                    free_database: sym!(b"hs_free_database\0"),
                    scan: sym!(b"hs_scan\0"),
                    version: sym!(b"hs_version\0"),
                    _lib: lib,
                };
                return Ok(api);
            },
            Err(e) => last = format!("{c}: {e}"),
        }
    }
    Err(format!("Hyperscan library not loadable ({last})"))
}

/// A compiled multi-pattern database with a pool of scratch spaces.
pub struct Hyperscan {
    api: Arc<Api>,
    db: *mut HsDb,
    scratch_proto: *mut HsScratch,
    pool: Mutex<Vec<*mut HsScratch>>,
    /// number of patterns (ids are 0..n)
    pub n_patterns: usize,
    pub version: String,
}
unsafe impl Send for Hyperscan {}
unsafe impl Sync for Hyperscan {}

pub struct CompileReport {
    /// ids (indices into the input slice) that failed to compile, with the library's message
    pub failed: Vec<(usize, String)>,
}

impl Hyperscan {
    pub fn is_available() -> bool {
        load_api().is_ok()
    }

    /// Compile each pattern individually first (failure isolation), then build one database out of
    /// the good ones. `patterns[i]` is `(go-syntax pattern, dotall)`; the id reported by `scan` is `i`.
    pub fn compile(patterns: &[(String, bool)]) -> Result<(Hyperscan, CompileReport), String> {
        let api = Arc::new(load_api()?);
        let version = unsafe { CStr::from_ptr((api.version)()).to_string_lossy().into_owned() };
        let mut ok_idx: Vec<usize> = Vec::new();
        let mut failed: Vec<(usize, String)> = Vec::new();
        let flags_for = |dotall: bool| HS_FLAG_PREFILTER | HS_FLAG_SINGLEMATCH | HS_FLAG_UTF8 | if dotall { HS_FLAG_DOTALL } else { 0 };
        for (i, (p, dotall)) in patterns.iter().enumerate() {
            let c = match CString::new(p.as_str()) {
                Ok(c) => c,
                Err(_) => {
                    failed.push((i, "NUL in pattern".into()));
                    continue;
                }
            };
            let mut db: *mut HsDb = ptr::null_mut();
            let mut err: *mut HsCompileError = ptr::null_mut();
            let rc = unsafe { (api.compile)(c.as_ptr(), flags_for(*dotall), HS_MODE_BLOCK, ptr::null(), &mut db, &mut err) };
            if rc == 0 {
                unsafe { (api.free_database)(db) };
                ok_idx.push(i);
            } else {
                let msg = if err.is_null() {
                    format!("rc={rc}")
                } else {
                    let m = unsafe { CStr::from_ptr((*err).message).to_string_lossy().into_owned() };
                    unsafe { (api.free_compile_error)(err) };
                    m
                };
                failed.push((i, msg));
            }
        }
        if ok_idx.is_empty() {
            return Err("no pattern compiled".into());
        }
        let cstrs: Vec<CString> = ok_idx.iter().map(|&i| CString::new(patterns[i].0.as_str()).unwrap()).collect();
        let ptrs: Vec<*const c_char> = cstrs.iter().map(|c| c.as_ptr()).collect();
        let flags: Vec<c_uint> = ok_idx.iter().map(|&i| flags_for(patterns[i].1)).collect();
        let ids: Vec<c_uint> = ok_idx.iter().map(|&i| i as c_uint).collect();
        let mut db: *mut HsDb = ptr::null_mut();
        let mut err: *mut HsCompileError = ptr::null_mut();
        let rc = unsafe { (api.compile_multi)(ptrs.as_ptr(), flags.as_ptr(), ids.as_ptr(), ptrs.len() as c_uint, HS_MODE_BLOCK, ptr::null(), &mut db, &mut err) };
        if rc != 0 {
            let msg = if err.is_null() { format!("rc={rc}") } else { unsafe { CStr::from_ptr((*err).message).to_string_lossy().into_owned() } };
            return Err(format!("hs_compile_multi: {msg}"));
        }
        let mut scratch: *mut HsScratch = ptr::null_mut();
        let rc = unsafe { (api.alloc_scratch)(db, &mut scratch) };
        if rc != 0 {
            unsafe { (api.free_database)(db) };
            return Err(format!("hs_alloc_scratch rc={rc}"));
        }
        Ok((
            Hyperscan { api, db, scratch_proto: scratch, pool: Mutex::new(Vec::new()), n_patterns: patterns.len(), version },
            CompileReport { failed },
        ))
    }

    fn take_scratch(&self) -> Result<*mut HsScratch, String> {
        if let Some(s) = self.pool.lock().pop() {
            return Ok(s);
        }
        let mut s: *mut HsScratch = ptr::null_mut();
        let rc = unsafe { (self.api.clone_scratch)(self.scratch_proto, &mut s) };
        if rc != 0 {
            return Err(format!("hs_clone_scratch rc={rc}"));
        }
        Ok(s)
    }

    /// Mark every pattern id that has (or may have) a match. `hit.len()` must be `n_patterns`.
    pub fn scan_candidates(&self, text: &str, hit: &mut [bool]) -> Result<(), String> {
        if text.len() > u32::MAX as usize {
            return Err("text too large for hs_scan".into());
        }
        extern "C" fn cb(id: c_uint, _from: u64, _to: u64, _flags: c_uint, ctx: *mut c_void) -> c_int {
            // SAFETY: ctx points at the `&mut [bool]` passed below; id < n_patterns by construction.
            let hit = unsafe { &mut *(ctx as *mut &mut [bool]) };
            if let Some(h) = hit.get_mut(id as usize) {
                *h = true;
            }
            0
        }
        let scratch = self.take_scratch()?;
        let mut slice: &mut [bool] = hit;
        let rc = unsafe {
            (self.api.scan)(self.db, text.as_ptr() as *const c_char, text.len() as c_uint, 0, scratch, cb, &mut slice as *mut &mut [bool] as *mut c_void)
        };
        self.pool.lock().push(scratch);
        if rc != 0 {
            return Err(format!("hs_scan rc={rc}"));
        }
        Ok(())
    }
}

impl Drop for Hyperscan {
    fn drop(&mut self) {
        unsafe {
            for s in self.pool.lock().drain(..) {
                (self.api.free_scratch)(s);
            }
            (self.api.free_scratch)(self.scratch_proto);
            (self.api.free_database)(self.db);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prefilter_roundtrip_if_available() {
        if !Hyperscan::is_available() {
            eprintln!("hyperscan not available; skipping");
            return;
        }
        let pats = vec![(r"\bAKIA[0-9A-Z]{16}\b".to_string(), false), (r"foo(?i)bar".to_string(), false), (r"(unclosed".to_string(), false)];
        let (hs, rep) = Hyperscan::compile(&pats).unwrap();
        assert_eq!(rep.failed.len(), 1);
        assert_eq!(rep.failed[0].0, 2);
        let mut hit = vec![false; 3];
        hs.scan_candidates("key=AKIAABCDEFGHIJKLMNOP end", &mut hit).unwrap();
        assert!(hit[0] && !hit[1]);
    }
}
