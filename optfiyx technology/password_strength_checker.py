import tkinter as tk
from tkinter import messagebox
import re

MIN_LENGTH = 8
STRENGTH_MESSAGES = {
    "weak": "Weak: {}",
    "strong": "Strong: Your password is strong."
}

COLORS = {
    "weak": "red",
    "strong": "green"
}

def check_password_strength(password):
    """Check the strength of the password and return the message and color."""
    if len(password) < MIN_LENGTH:
        return STRENGTH_MESSAGES["weak"].format(f"Too short (min {MIN_LENGTH} chars)."), COLORS["weak"]
    
    if not any(char.islower() for char in password):
        return STRENGTH_MESSAGES["weak"].format("At least one lowercase letter required."), COLORS["weak"]
    
    if not any(char.isupper() for char in password):
        return STRENGTH_MESSAGES["weak"].format("At least one uppercase letter required."), COLORS["weak"]
    
    if not any(char.isdigit() for char in password):
        return STRENGTH_MESSAGES["weak"].format("At least one digit required."), COLORS["weak"]
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return STRENGTH_MESSAGES["weak"].format("At least one special character required."), COLORS["weak"]
    
    return STRENGTH_MESSAGES["strong"], COLORS["strong"]

def evaluate_password():
    """Evaluate the entered password and update the UI."""
    password = entry.get()
    strength, color = check_password_strength(password)
    result_label.config(text=strength, fg=color)

def toggle_password_visibility():
    """Toggle the visibility of the password."""
    if entry.cget('show') == '*':
        entry.config(show='')
        show_password_button.config(text='Hide Password')
    else:
        entry.config(show='*')
        show_password_button.config(text='Show Password')

def copy_to_clipboard():
    """Copy password to clipboard."""
    root.clipboard_clear()
    root.clipboard_append(entry.get())
    root.update()
    messagebox.showinfo("Copied", "Password copied to clipboard!")

root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x250")
root.config(bg="#f0f0f0")

label = tk.Label(root, text="Enter your password:", bg="#f0f0f0", font=("Arial", 12))
label.pack(pady=10)

entry = tk.Entry(root, show='*', width=30, font=("Arial", 12))
entry.pack(pady=5)

check_button = tk.Button(root, text="Check Strength", command=evaluate_password, font=("Arial", 12), bg="#4CAF50", fg="white")
check_button.pack(pady=10)

show_password_button = tk.Button(root, text="Show Password", command=toggle_password_visibility, font=("Arial", 12), bg="#008CBA", fg="white")
show_password_button.pack(pady=5)

copy_button = tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard, font=("Arial", 12), bg="#f39c12", fg="white")
copy_button.pack(pady=5)

result_label = tk.Label(root, text="", bg="#f0f0f0", font=("Arial", 12, "bold"))
result_label.pack(pady=10)

root.mainloop()
