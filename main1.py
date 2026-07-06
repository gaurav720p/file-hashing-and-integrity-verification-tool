import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
from pathlib import Path
from datetime import datetime
import json



# ============================
# Shared Algorithms
# ============================
ALGORITHMS = [
    "MD5", "SHA1", "SHA256", "SHA384", "SHA512",
    "SHA3-256", "SHA3-384", "SHA3-512", "RIPEMD160"
]


# ============================
# Home Screen
# ============================
class HomeScreen:
    def __init__(self, root):
        self.root = root
        self.root.title("FIle Hashing and Integrity Verification Tool")
        self.root.geometry("550x600")
        self.root.configure(bg="#0f172a")

        tk.Label(root, text="🔐 FIle Hashing and Integrity Verification Tool",
                 font=("Segoe UI", 18, "bold"),
                 fg="#38bdf8", bg="#0f172a").pack(pady=25)

        tk.Label(root, text="Select a module",
                 font=("Segoe UI", 18),
                 fg="#e5e7eb", bg="#0f172a").pack(pady=10)

        self.create_btn("🔐 File Hashing ", self.open_hashing)
        self.create_btn("🔍 Compare Hash ", self.open_compare_hash)
        self.create_btn("🧬 Side-by-Side Compare ", self.open_side_by_side)
        self.create_btn("📄 Checksum Module ", self.open_checksum)
        self.create_btn("📂 Directory Monitor ", self.open_directory)
        self.create_btn("🦠 VirusTotal Scanner ", self.open_virustotal)

    def create_btn(self, text, cmd):
        tk.Button(
            self.root, text=text, command=cmd,
            font=("Segoe UI", 13, "bold"),
            fg="white", bg="#2563eb",
            activebackground="#1d4ed8",
            relief="flat", width=32, pady=10
        ).pack(pady=8)

    def open_hashing(self):
        FileHashingModule(tk.Toplevel(self.root))

    def open_compare_hash(self):
        CompareHashModule(tk.Toplevel(self.root))

    def open_side_by_side(self):
        SideBySideCompareModule(tk.Toplevel(self.root))

    def open_checksum(self):
        ChecksumModule(tk.Toplevel(self.root))

    
    def open_directory(self):
        DirectoryMonitor(tk.Toplevel(self.root))

    def open_virustotal(self):
        VirusTotalScanner(tk.Toplevel(self.root))





# ==================================================
# File Hashing Module
# ==================================================
class FileHashingModule:
    def __init__(self, root):
        self.root = root
        self.root.title(f"File Hashing")
        self.root.geometry("820x720")
        self.root.configure(bg="#020617")

        self.selected_file = None
        self.hash_values = {}
        self.selected_algo = tk.StringVar(value="SHA256")

        self.build_ui()

    def build_ui(self):
        tk.Label(self.root, text="🔐 File Hashing ",
                 font=("Segoe UI", 20, "bold"),
                 fg="#38bdf8", bg="#020617").pack(pady=10)

        toolbar = tk.Frame(self.root, bg="#020617")
        toolbar.pack(fill="x", padx=20, pady=10)

        tk.Button(toolbar, text="📄 Select File", command=self.select_file,
                  font=("Segoe UI", 11, "bold"),
                  fg="white", bg="#2563eb", relief="flat").pack(side="left", padx=6)

        self.file_label = tk.Label(toolbar, text="No file selected",
                                   fg="#94a3b8", bg="#020617", width=40, anchor="w")
        self.file_label.pack(side="left")

        tk.Label(toolbar, text="⚙ Algorithm",
                 fg="#e5e7eb", bg="#020617").pack(side="left", padx=10)

        ttk.Combobox(toolbar, values=["All"] + ALGORITHMS,
                     textvariable=self.selected_algo,
                     state="readonly", width=14).pack(side="left")

        self.progress = ttk.Progressbar(toolbar, length=180)
        self.progress.pack(side="left", padx=15)

        self.progress_label = tk.Label(toolbar, text="Idle",
                                       fg="#94a3b8", bg="#020617")
        self.progress_label.pack(side="left")

        tk.Button(self.root, text="🧮 Compute Hash", command=self.compute_hash,
                  font=("Segoe UI", 12, "bold"),
                  fg="white", bg="#22c55e", relief="flat").pack(pady=10)

        self.hash_box = tk.Text(self.root, height=18, width=100,
                                bg="#020617", fg="#22c55e", font=("Consolas", 11))
        self.hash_box.pack(pady=10)

        tk.Button(self.root, text="💾 Export Hash", command=self.export_hash,
                  font=("Segoe UI", 12, "bold"),
                  fg="white", bg="#2563eb", relief="flat").pack(pady=10)

    def select_file(self):
        p = filedialog.askopenfilename()
        if not p: return
        self.selected_file = Path(p)
        self.file_label.config(text=str(self.selected_file))
        self.hash_box.delete(1.0, tk.END)

    def compute_hash(self):
        if not self.selected_file:
            messagebox.showwarning("Error", "Select file first")
            return

        self.hash_box.delete(1.0, tk.END)
        algo = self.selected_algo.get()
        data = self.selected_file.read_bytes()

        self.hash_values.clear()
        if algo == "All":
            for a in ALGORITHMS:
                self.hash_values[a] = self.calc(a, data)
        else:
            self.hash_values[algo] = self.calc(algo, data)

        for k, v in self.hash_values.items():
            self.hash_box.insert(tk.END, f"{k}: {v}\n")

    def calc(self, algo, data):
        if algo == "MD5": return hashlib.md5(data).hexdigest()
        if algo == "SHA1": return hashlib.sha1(data).hexdigest()
        if algo == "SHA256": return hashlib.sha256(data).hexdigest()
        if algo == "SHA384": return hashlib.sha384(data).hexdigest()
        if algo == "SHA512": return hashlib.sha512(data).hexdigest()
        if algo == "SHA3-256": return hashlib.sha3_256(data).hexdigest()
        if algo == "SHA3-384": return hashlib.sha3_384(data).hexdigest()
        if algo == "SHA3-512": return hashlib.sha3_512(data).hexdigest()
        if algo == "RIPEMD160": return hashlib.new("ripemd160", data).hexdigest()

    def export_hash(self):
        if not self.hash_values:
            messagebox.showwarning("Export", "No hash to export")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if not path: return

        stat = self.selected_file.stat()
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"File: {self.selected_file.name}\n")
            f.write(f"Path: {self.selected_file}\n")
            f.write(f"Size: {stat.st_size} bytes\n")
            f.write(f"Exported: {datetime.now()}\n\n")
            for k, v in self.hash_values.items():
                f.write(f"{k}: {v}\n")
        messagebox.showinfo("Saved", "Report saved")



# ==================================================
# Compare Hash Module
# ==================================================
class CompareHashModule:
    def __init__(self, root):
        self.root = root
        self.root.title("Compare Hash")
        self.root.geometry("500x500")
        self.root.configure(bg="#020617")

        self.fileA = None
        self.algo = tk.StringVar(value="SHA256")
        self.hashB = tk.StringVar()

        self.build_ui()

    def build_ui(self):
        tk.Label(self.root, text="🔍 Compare Hash",
                 font=("Segoe UI", 18, "bold"),
                 fg="#38bdf8", bg="#020617").pack(pady=10)

        tk.Button(self.root, text="📄 Select File (Hash A)",
                  command=self.select_file, bg="#2563eb",
                  fg="white", relief="flat").pack(pady=5)

        self.file_label = tk.Label(self.root, text="No file selected",
                                   fg="#94a3b8", bg="#020617")
        self.file_label.pack()

        tk.Label(self.root, text="Paste Hash B",
                 fg="#e5e7eb", bg="#020617").pack(pady=5)
        tk.Entry(self.root, textvariable=self.hashB, width=70).pack()

        ttk.Combobox(self.root, values=ALGORITHMS,
                     textvariable=self.algo,
                     state="readonly").pack(pady=5)

        tk.Button(self.root, text="Compare",
                  command=self.compare, bg="#22c55e",
                  fg="white", relief="flat").pack(pady=10)

        self.result = tk.Label(self.root, text="", font=("Segoe UI", 14),
                               bg="#020617")
        self.result.pack()

    def select_file(self):
        p = filedialog.askopenfilename()
        if not p: return
        self.fileA = Path(p)
        self.file_label.config(text=self.fileA.name)

    def compare(self):
        if not self.fileA or not self.hashB.get():
            messagebox.showwarning("Error", "Select file and paste hash")
            return

        data = self.fileA.read_bytes()
        computed = FileHashingModule.calc(self, self.algo.get(), data)

        if computed.lower() == self.hashB.get().strip().lower():
            self.result.config(text="MATCH ✅", fg="#22c55e")
        else:
            self.result.config(text="MISMATCH ❌", fg="#ef4444")




# ==================================================
# Side-by-Side Compare Module
# ==================================================
class SideBySideCompareModule:
    def __init__(self, root):
        self.root = root
        self.root.title("Side-by-Side Compare")
        self.root.geometry("800x550")
        self.root.configure(bg="#020617")

        self.fileA = None
        self.fileB = None
        self.algo = tk.StringVar(value="SHA256")

        self.build_ui()

    def build_ui(self):
        tk.Label(self.root, text="🧬 Side-by-Side Compare",
                 font=("Segoe UI", 18, "bold"),
                 fg="#38bdf8", bg="#020617").pack(pady=10)

        top = tk.Frame(self.root, bg="#020617")
        top.pack(pady=10)

        tk.Button(top, text="📄 Select File A", command=self.select_a,
                  bg="#2563eb", fg="white", relief="flat", width=18).grid(row=0, column=0, padx=10)
        tk.Button(top, text="📄 Select File B", command=self.select_b,
                  bg="#2563eb", fg="white", relief="flat", width=18).grid(row=0, column=1, padx=10)

        self.labelA = tk.Label(self.root, text="File A: None", fg="#94a3b8", bg="#020617")
        self.labelA.pack()
        self.labelB = tk.Label(self.root, text="File B: None", fg="#94a3b8", bg="#020617")
        self.labelB.pack()

        algo_bar = tk.Frame(self.root, bg="#020617")
        algo_bar.pack(pady=10)

        tk.Label(algo_bar, text="Algorithm:", fg="#e5e7eb", bg="#020617").pack(side="left", padx=6)
        ttk.Combobox(algo_bar, values=ALGORITHMS, textvariable=self.algo,
                     state="readonly", width=14).pack(side="left")

        tk.Button(self.root, text="Compare Files",
                  command=self.compare, bg="#22c55e",
                  fg="white", relief="flat",
                  font=("Segoe UI", 12, "bold")).pack(pady=15)

        self.output = tk.Text(self.root, width=90, height=12,
                              bg="#020617", fg="#22c55e",
                              font=("Consolas", 11))
        self.output.pack(pady=10)

    def select_a(self):
        p = filedialog.askopenfilename()
        if p:
            self.fileA = Path(p)
            self.labelA.config(text=f"File A: {self.fileA.name}")

    def select_b(self):
        p = filedialog.askopenfilename()
        if p:
            self.fileB = Path(p)
            self.labelB.config(text=f"File B: {self.fileB.name}")

    
    def compare(self):
        if not self.fileA or not self.fileB:
            messagebox.showwarning("Error", "Select both files")
            return

        algo = self.algo.get()
        dataA = self.fileA.read_bytes()
        dataB = self.fileB.read_bytes()

        hashA = FileHashingModule.calc(self, algo, dataA)
        hashB = FileHashingModule.calc(self, algo, dataB)

        self.output.delete(1.0, tk.END)
        self.output.insert(tk.END, f"File A Hash ({algo}):\n{hashA}\n\n")
        self.output.insert(tk.END, f"File B Hash ({algo}):\n{hashB}\n\n")

        if hashA.lower() == hashB.lower():
            self.output.insert(tk.END, "RESULT: MATCH ✅\n")
            self.output.tag_add("match", "end-2l", "end")
            self.output.tag_config("match", foreground="#22c55e")
        else:
            self.output.insert(tk.END, "RESULT: MISMATCH ❌\n")
            self.output.tag_add("mismatch", "end-2l", "end")
            self.output.tag_config("mismatch", foreground="#ef4444")



# ==================================================
# Checksum Module
# ==================================================

class ChecksumModule:
    VERSION = "V1.0"
    def __init__(self, root):
        self.root = root
        self.root.title(f"Checksum Module ")
        self.root.geometry("720x560")
        self.root.configure(bg="#020617")
        self.file = None
        self.algo = tk.StringVar(value="SHA256")

        tk.Label(root, text="🧾 Checksum Module ",
                 font=("Segoe UI", 20, "bold"),
                 fg="#38bdf8", bg="#020617").pack(pady=18)

        tk.Button(root, text="Select File", command=self.select_file,
                  bg="#2563eb", fg="white", font=("Segoe UI", 12, "bold"),
                  relief="flat", width=22).pack(pady=8)

        self.file_lbl = tk.Label(root, text="No file selected",
                                 fg="#e5e7eb", bg="#020617", font=("Segoe UI", 11))
        self.file_lbl.pack(pady=4)

        algo_frame = tk.Frame(root, bg="#020617")
        algo_frame.pack(pady=10)
        tk.Label(algo_frame, text="Algorithm:", fg="#e5e7eb", bg="#020617",
                 font=("Segoe UI", 11)).pack(side="left", padx=6)
        ttk.Combobox(algo_frame, textvariable=self.algo,
                     values=["MD5","SHA1","SHA256"], width=12).pack(side="left")

        btns = tk.Frame(root, bg="#020617"); btns.pack(pady=14)
        tk.Button(btns, text="Write Checksum", command=self.write_checksum,
                  bg="#22c55e", fg="white", font=("Segoe UI", 11, "bold"),
                  relief="flat", width=18).grid(row=0,column=0,padx=10)
        tk.Button(btns, text="Load Checksum", command=self.load_checksum,
                  bg="#2563eb", fg="white", font=("Segoe UI", 11, "bold"),
                  relief="flat", width=18).grid(row=0,column=1,padx=10)

        self.out = tk.Text(root, height=14, width=80, bg="#020617",
                           fg="#22c55e", insertbackground="white",
                           font=("Consolas", 14))
        self.out.pack(pady=12)

    def select_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.file = Path(p)
            self.file_lbl.config(text=self.file.name)

    def _hash(self, data):
        a=self.algo.get()
        h = hashlib.md5() if a=="MD5" else hashlib.sha1() if a=="SHA1" else hashlib.sha256()
        h.update(data); return h.hexdigest()

    def write_checksum(self):
        if not self.file: return
        h = self._hash(self.file.read_bytes())
        out = self.file.with_suffix(self.file.suffix + "." + self.algo.get().lower())
        out.write_text(f"{h} *{self.file.name}")
        self.out.insert(tk.END, f"Saved: {out}\n")

    
    
    def load_checksum(self):
        c = filedialog.askopenfilename(filetypes=[("Checksum","*.md5 *.sha1 *.sha256")])
        if not c:
            return
        content = Path(c).read_text().strip().split()
        expected, fname = content[0], content[-1].lstrip("*")
        f = filedialog.askopenfilename(title=f"Select {fname}")
        if not f:
            return
        actual = self._hash(Path(f).read_bytes())

        self.out.delete(1.0, tk.END)
        self.out.insert(tk.END, f"Expected: {expected}\nActual: {actual}\n")

        start = self.out.index("end-1c")
        if expected.lower() == actual.lower():
            self.out.insert(tk.END, "MATCH\n")
            self.out.tag_add("match", start, "end-1c")
            self.out.tag_config("match", foreground="#22c55e")
        else:
            self.out.insert(tk.END, "MISMATCH\n")
            self.out.tag_add("mismatch", start, "end-1c")
            self.out.tag_config("mismatch", foreground="#ef4444")




# ==================================================
# Directory Monitor Module
# ==================================================
class DirectoryMonitor:
    VERSION = "V1.0"
    def __init__(self, root):
        self.root = root
        self.root.title(f"Directory Monitor ")
        self.root.geometry("820x640")
        self.root.configure(bg="#020617")
        self.folder = None

        tk.Label(root, text="📂 Directory Monitor ",
                 font=("Segoe UI", 18, "bold"),
                 fg="#38bdf8", bg="#020617").pack(pady=10)

        tk.Button(root, text="Select Folder", command=self.select_folder,
                  bg="#2563eb", fg="white", relief="flat").pack(pady=5)

        self.folder_lbl = tk.Label(root, text="No folder selected",
                                   fg="#e5e7eb", bg="#020617")
        self.folder_lbl.pack()

        btns = tk.Frame(root, bg="#020617"); btns.pack(pady=10)
        tk.Button(btns, text="Hash Directory", command=self.hash_directory,
                  bg="#22c55e", fg="white", relief="flat", width=18).grid(row=0,column=0,padx=10)
        tk.Button(btns, text="Verify Directory", command=self.verify_directory,
                  bg="#2563eb", fg="white", relief="flat", width=18).grid(row=0,column=1,padx=10)

        self.progress = ttk.Progressbar(root, length=500, mode="determinate")
        self.progress.pack(pady=6)

        self.out = tk.Text(root, width=100, height=22, bg="#020617",
                           fg="#22c55e", font=("Consolas", 11))
        self.out.pack(pady=10)

        # Status color tags
        self.out.tag_configure("green", foreground="#22c55e")
        self.out.tag_configure("red", foreground="#ef4444")
        self.out.tag_configure("yellow", foreground="#facc15")
        self.out.tag_configure("blue", foreground="#3b82f6")

    def select_folder(self):
        p = filedialog.askdirectory()
        if p:
            self.folder = Path(p)
            self.folder_lbl.config(text=str(self.folder))

    def hash_directory(self):
        if not self.folder:
            messagebox.showwarning("Error", "Select a folder first")
            return

        files = [fp for fp in self.folder.rglob("*") if fp.is_file()]
        if not files:
            messagebox.showinfo("Empty", "No files in this folder")
            return

        manifest = {
            "folder": str(self.folder),
            "algorithm": "SHA256",
            "generated_at": datetime.now().isoformat(),
            "files": {}
        }

        self.out.delete(1.0, tk.END)
        self.progress["maximum"] = len(files)
        self.progress["value"] = 0

        for i, fp in enumerate(files, 1):
            data = fp.read_bytes()
            h = hashlib.sha256(data).hexdigest()
            rel = str(fp.relative_to(self.folder))
            manifest["files"][rel] = {"size": fp.stat().st_size, "hash": h}
            self.out.insert(tk.END, f"Hashed: {rel}\n")
            self.progress["value"] = i
            self.root.update_idletasks()

        save = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
        if save:
            Path(save).write_text(json.dumps(manifest, indent=2))
            messagebox.showinfo("Saved", "JSON manifest created")


    def insert_status(self, status, rel):
        status = status.upper()
        if status == "MISSING":
            tag = "red"
        elif status in ("MODIFIED", "MODIFY"):
            tag = "yellow"
        elif status == "NEW":
            tag = "blue"
        else:
            tag = "green"
        self.out.insert(tk.END, f"{status}: {rel}\n", tag)

    def verify_directory(self):
        if not self.folder:
            messagebox.showwarning("Error", "Select folder")
            return

        mf = filedialog.askopenfilename(filetypes=[("Manifest","*.json")])
        if not mf:
            return

        data = json.loads(Path(mf).read_text())
        manifest_files = data.get("files", {})

        current_files = {
            str(fp.relative_to(self.folder)): fp
            for fp in self.folder.rglob("*") if fp.is_file()
        }

        self.out.delete(1.0, tk.END)
        self.progress["maximum"] = max(len(manifest_files), 1)
        self.progress["value"] = 0

        for i, (rel, info) in enumerate(manifest_files.items(), 1):
            f = current_files.get(rel)
            if not f:
                self.insert_status("MISSING", rel)
            else:
                h = hashlib.sha256(f.read_bytes()).hexdigest()
                if h == info["hash"]:
                    self.insert_status("OK", rel)
                else:
                    self.insert_status("MODIFIED", rel)
            self.progress["value"] = i
            self.root.update_idletasks()

        for rel in sorted(set(current_files.keys()) - set(manifest_files.keys())):
            self.insert_status("NEW", rel)
    




# ==================================================
# VirusTotal Scanner Module
# ==================================================
class VirusTotalScanner:
    API_FILE = Path("virustotal_api.txt")

    def __init__(self, root):
        self.root = root
        self.root.title("VirusTotal Scanner")
        self.root.geometry("720x520")
        self.root.configure(bg="#020617")

        self.file = None
        self.api_key = self.load_api_key()

        tk.Label(root, text="🦠 VirusTotal Scanner",
                 font=("Segoe UI", 20, "bold"),
                 fg="#38bdf8", bg="#020617").pack(pady=18)

        tk.Button(root, text="Select File",
                  command=self.select_file,
                  bg="#2563eb", fg="white",
                  font=("Segoe UI", 12, "bold"),
                  relief="flat", width=22).pack(pady=8)

        self.file_lbl = tk.Label(root, text="No file selected",
                                 fg="#e5e7eb", bg="#020617",
                                 font=("Segoe UI", 11))
        self.file_lbl.pack(pady=5)

        key_frame = tk.Frame(root, bg="#020617")
        key_frame.pack(pady=10)

        tk.Label(key_frame, text="API Key:",
                 fg="#e5e7eb", bg="#020617").grid(row=0, column=0, padx=5)

        self.key_entry = tk.Entry(key_frame, width=50)
        self.key_entry.grid(row=0, column=1, padx=5)
        if self.api_key:
            self.key_entry.insert(0, self.api_key)

        tk.Button(root, text="Save API Key",
                  command=self.save_api_key,
                  bg="#22c55e", fg="white",
                  font=("Segoe UI", 11, "bold"),
                  relief="flat", width=18).pack(pady=6)

        tk.Button(root, text="Check on VirusTotal",
                  command=self.check_file,
                  bg="#2563eb", fg="white",
                  font=("Segoe UI", 11, "bold"),
                  relief="flat", width=22).pack(pady=10)

        self.out = tk.Text(root, height=12, width=80,
                           bg="#020617", fg="#22c55e",
                           font=("Consolas", 14))
        self.out.pack(pady=10)

    def select_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.file = Path(p)
            self.file_lbl.config(text=self.file.name)

    def load_api_key(self):
        if self.API_FILE.exists():
            return self.API_FILE.read_text().strip()
        return ""

    def save_api_key(self):
        key = self.key_entry.get().strip()
        if not key:
            messagebox.showwarning("Error", "Enter API key")
            return
        self.API_FILE.write_text(key)
        messagebox.showinfo("Saved", "API key saved")

    def check_file(self):
        if not self.file:
            messagebox.showwarning("Error", "Select file first")
            return

        key = self.key_entry.get().strip()
        if not key:
            messagebox.showwarning("Error", "Enter API key first")
            return

        import requests

        self.out.delete(1.0, tk.END)
        self.out.insert(tk.END, "Calculating SHA256...\n")

        sha256 = hashlib.sha256(self.file.read_bytes()).hexdigest()
        self.out.insert(tk.END, f"SHA256: {sha256}\n\nQuerying VirusTotal...\n")

        headers = {"x-apikey": key}
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"

        try:
            r = requests.get(url, headers=headers)
            if r.status_code == 200:
                data = r.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]

                self.out.insert(tk.END, "\nScan Results:\n")
                for k, v in stats.items():
                    self.out.insert(tk.END, f"{k}: {v}\n")
            elif r.status_code == 404:
                self.out.insert(tk.END, "File not found on VirusTotal\n")
            else:
                self.out.insert(tk.END, f"Error: {r.status_code}\n")
        except Exception as e:
            self.out.insert(tk.END, f"Request failed: {e}\n")


# ==================================================
# main Function
# ==================================================

if __name__ == "__main__":
    import tkinter as tk
    try:
        root = tk.Tk()
        HomeScreen(root)
        root.mainloop()
    except NameError:
        root = tk.Tk()
        ChecksumModule(root)
        root.mainloop()
