# [Insigne, Antonio Jr A.]
import tkinter as tk
from tkinter import messagebox
import sqlite3
import hashlib
import os
import datetime
import re

DB_PATH = "users.db"

def center_window(win, w=380, h=300):
    win.update_idletasks()
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    x = (sw // 2) - (w // 2)
    y = (sh // 2) - (h // 2)
    win.geometry(f"{w}x{h}+{x}+{y}")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TEXT
        )
    """)
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        try:
            create_user("admin", "123", role="admin", conn=conn)
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

def create_user(username, password, role="user", conn=None):
    close_conn = False
    if conn is None:
        conn = sqlite3.connect(DB_PATH)
        close_conn = True
    salt = os.urandom(16).hex()
    password_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    created_at = datetime.datetime.now().isoformat()
    c = conn.cursor()
    c.execute(
        "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)",
        (username, password_hash, salt, role, created_at)
    )
    conn.commit()
    if close_conn:
        conn.close()

def verify_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash, salt FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False
    stored_hash, salt = row
    check_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    return check_hash == stored_hash

def start_app():
    init_db()
    root = tk.Tk()
    root.title("Login Module")
    root.resizable(False, False)
    center_window(root, 500, 320)
    root.configure(bg="#f4f4f4")  # simple light background

    frame = tk.Frame(root, bg="white", bd=1, relief="solid")
    frame.place(relx=0.5, rely=0.5, anchor="center", width=350, height=260)

    tk.Label(frame, text="User Login", font=("Arial", 18, "bold"), bg="white", fg="#4e54c8").pack(pady=10)

    tk.Label(frame, text="Username:", font=("Arial", 11), bg="white").pack(anchor="w", padx=30)
    entry_user = tk.Entry(frame, relief="flat", font=("Arial", 11), bg="#f0f0f0", highlightthickness=2,
                          highlightbackground="#8f94fb", insertbackground="#4e54c8")
    entry_user.pack(padx=30, pady=5, fill="x")

    tk.Label(frame, text="Password:", font=("Arial", 11), bg="white").pack(anchor="w", padx=30)
    entry_pw = tk.Entry(frame, relief="flat", font=("Arial", 11, "italic"), show="*", bg="#f0f0f0",
                        highlightthickness=2, highlightbackground="#8f94fb", insertbackground="#4e54c8")
    entry_pw.pack(padx=30, pady=5, fill="x")

    def toggle_pw():
        if entry_pw.cget("show") == "*":
            entry_pw.config(show="")
            btn_show_pw.config(text="Hide")
        else:
            entry_pw.config(show="*")
            btn_show_pw.config(text="Show")

    btn_show_pw = tk.Button(frame, text="Show", command=toggle_pw, bg="#8f94fb", fg="white", relief="flat")
    btn_show_pw.pack(pady=2)

    def do_login(event=None):
        user = entry_user.get().strip()
        pw = entry_pw.get()
        if not user or not pw:
            messagebox.showwarning("Input required", "Please enter username and password.")
            return
        if verify_user(user, pw):
            open_welcome(root, user)
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    btn_login = tk.Button(frame, text="Login", width=12, bg="#4e54c8", fg="white", command=do_login, relief="flat")
    btn_login.pack(side="left", padx=(30, 10), pady=15)

    def open_register():
        reg = tk.Toplevel(root)
        reg.title("Register")
        reg.resizable(False, False)
        center_window(reg, 480, 300)
        reg.configure(bg="white")

        tk.Label(reg, text="Create Account", font=("Arial", 16, "bold"), bg="white", fg="#4e54c8").pack(pady=10)

        tk.Label(reg, text="Username:", font=("Arial", 11), bg="white").pack(anchor="w", padx=40)
        entry_r_user = tk.Entry(reg, font=("Arial", 11), bg="#f0f0f0", highlightthickness=2,
                                highlightbackground="#8f94fb", insertbackground="#4e54c8")
        entry_r_user.pack(padx=40, pady=5, fill="x")

        tk.Label(reg, text="Password:", font=("Arial", 11), bg="white").pack(anchor="w", padx=40)
        entry_r_pw = tk.Entry(reg, font=("Arial", 11), bg="#f0f0f0", highlightthickness=2,
                              highlightbackground="#8f94fb", insertbackground="#4e54c8", show="*")
        entry_r_pw.pack(padx=40, pady=5, fill="x")

        tk.Label(reg, text="Confirm Password:", font=("Arial", 11), bg="white").pack(anchor="w", padx=40)
        entry_r_pw2 = tk.Entry(reg, font=("Arial", 11), bg="#f0f0f0", highlightthickness=2,
                               highlightbackground="#8f94fb", insertbackground="#4e54c8", show="*")
        entry_r_pw2.pack(padx=40, pady=5, fill="x")

        def toggle_reg_pw():
            if entry_r_pw.cget("show") == "*":
                entry_r_pw.config(show="")
                entry_r_pw2.config(show="")
                btn_reg_show.config(text="Hide")
            else:
                entry_r_pw.config(show="*")
                entry_r_pw2.config(show="*")
                btn_reg_show.config(text="Show")

        btn_reg_show = tk.Button(reg, text="Show", width=6, command=toggle_reg_pw, bg="#8f94fb", fg="white", relief="flat")
        btn_reg_show.pack(pady=3)

        def submit_register():
            uname = entry_r_user.get().strip()
            p1 = entry_r_pw.get()
            p2 = entry_r_pw2.get()
            if not uname or not p1 or not p2:
                messagebox.showwarning("Input required", "Please fill all fields.", parent=reg)
                return
            if p1 != p2:
                messagebox.showerror("Mismatch", "Passwords do not match.", parent=reg)
                return
            if len(uname) < 3 or len(p1) < 4:
                messagebox.showwarning("Weak", "Username must be 3+ chars and password 4+ chars.", parent=reg)
                return
            if re.search(r"\s", uname):
                messagebox.showwarning("Invalid", "Username cannot contain spaces.", parent=reg)
                return
            try:
                create_user(uname, p1, role="user")
                messagebox.showinfo("Success", "Account created successfully! You may now login.", parent=reg)
                reg.destroy()
            except sqlite3.IntegrityError:
                messagebox.showerror("Exists", "Username already exists. Choose another.", parent=reg)

        # Buttons aligned horizontally
        btn_frame = tk.Frame(reg, bg="white")
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Register", width=10, bg="#4e54c8", fg="white", command=submit_register, relief="flat").grid(row=0, column=0, padx=10)
        tk.Button(btn_frame, text="Cancel", width=10, command=reg.destroy, relief="flat").grid(row=0, column=1, padx=10)

    btn_register = tk.Button(frame, text="Register", width=10, command=open_register, bg="#8f94fb", fg="white", relief="flat")
    btn_register.pack(side="left", padx=10, pady=15)

    btn_exit = tk.Button(frame, text="Exit", width=8, bg="#f44336", fg="white", command=root.quit, relief="flat")
    btn_exit.pack(side="right", padx=30, pady=15)

    root.bind("<Return>", do_login)
    root.mainloop()

def open_welcome(root, user):
    root.withdraw()
    welcome = tk.Toplevel()
    welcome.title("Welcome")
    welcome.resizable(False, False)
    center_window(welcome, 360, 160)
    welcome.configure(bg="white")
    tk.Label(welcome, text=f"Welcome, {user}!", font=("Arial", 16, "bold"), fg="#4e54c8", bg="white").pack(pady=30)
    tk.Button(welcome, text="Logout", width=12, command=lambda: do_logout(welcome, root), bg="#8f94fb", fg="white", relief="flat").pack()
    welcome.protocol("WM_DELETE_WINDOW", lambda: do_logout(welcome, root))

def do_logout(welcome, root):
    welcome.destroy()
    root.deiconify()

if __name__ == "__main__":
    start_app()
