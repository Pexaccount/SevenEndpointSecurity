import os, sys, json, importlib.util, traceback

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    host_path = None
    for _name in ("SevenEndPoint.py", "Pedefense.pyw"):
        _p = os.path.join(base_dir, _name)
        if os.path.exists(_p):
            host_path = _p
            break
    if not host_path:
        sys.stderr.write("scan_worker: host module not found (SevenEndPoint.py)\n")
        sys.exit(1)
    _real_stdout = sys.stdout
    sys.stdout = sys.stderr
    try:
        spec = importlib.util.spec_from_file_location("sevenendpoint_worker_mod", host_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        scanner = mod.Scanner()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
    finally:
        sys.stdout = _real_stdout
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    stdin = sys.stdin
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        fp = req.get("path")
        quick = req.get("quick", False)
        if fp is None:
            break
        try:
            if quick and hasattr(scanner, "scan_file_quick"):
                res, conf, vt = scanner.scan_file_quick(fp)
            else:
                res, conf, vt = scanner.scan_file(fp)
        except Exception:
            res, conf, vt = "ERROR", 0, ""
        out = {"path": fp, "result": res, "conf": conf, "vt": vt}
        try:
            _real_stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
            _real_stdout.flush()
        except Exception:
            break

if __name__ == "__main__":
    main()
