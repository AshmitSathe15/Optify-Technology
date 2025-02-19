import tkinter as tk
from tkinter import ttk, messagebox

def caesar_cipher(message, shift, mode='encrypt'):
    result = ''
    if mode == 'decrypt':
        shift = -shift

    for char in message:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    
    return result

def vigenere_cipher(message, key, mode='encrypt'):
    result = ''
    key_length = len(key)
    key_as_int = [ord(i) - ord('A') for i in key.upper()]
    message_int = [ord(i) - ord('A') for i in message.upper() if i.isalpha()]
    
    index = 0
    for char in message:
        if char.isalpha():
            shift = key_as_int[index % key_length]
            shift = -shift if mode == 'decrypt' else shift
            value = (ord(char.upper()) - ord('A') + shift) % 26
            result += chr(value + ord('A')) if char.isupper() else chr(value + ord('a'))
            index += 1
        else:
            result += char
    
    return result

def process():
    message = entry_message.get()
    cipher_type = cipher_var.get()
    mode = mode_var.get()
    
    if cipher_type == "Caesar":
        try:
            shift = int(entry_key.get())
            result = caesar_cipher(message, shift, mode.lower())
        except ValueError:
            messagebox.showerror("Input Error", "Please enter a valid integer for the shift.")
            return
        
    elif cipher_type == "Vigenère":
        key = entry_key.get()
        if not key.isalpha():
            messagebox.showerror("Input Error", "Vigenère key must contain only letters.")
            return
        result = vigenere_cipher(message, key, mode.lower())
    
    output_var.set(result)

root = tk.Tk()
root.title("Encryption & Decryption Tool")
root.geometry("500x350")
root.resizable(False, False)
root.configure(bg="#2C3E50")

frame = ttk.Frame(root, padding=10)
frame.grid(row=0, column=0, sticky="NSEW")
frame.configure(style="TFrame")

style = ttk.Style()
style.configure("TFrame", background="#2C3E50")
style.configure("TLabel", background="#2C3E50", foreground="white", font=("Arial", 11))
style.configure("TButton", background="#0000FF", foreground="black", font=("Arial", 10, "bold"))
style.map("TButton", background=[("active", "#0000FF")])
style.configure("TRadiobutton", background="#2C3E50", foreground="white", font=("Arial", 10))

ttk.Label(frame, text="Enter Message:").grid(row=0, column=0, sticky="W", pady=5)
entry_message = ttk.Entry(frame, width=50)
entry_message.grid(row=0, column=1, columnspan=2, pady=5)

cipher_var = tk.StringVar(value="Caesar")
ttk.Label(frame, text="Select Cipher:").grid(row=1, column=0, sticky="W", pady=5)
ttk.Radiobutton(frame, text="Caesar", variable=cipher_var, value="Caesar").grid(row=1, column=1, sticky="W")
ttk.Radiobutton(frame, text="Vigenère", variable=cipher_var, value="Vigenère").grid(row=1, column=2, sticky="W")

ttk.Label(frame, text="Enter Key/Shift:").grid(row=2, column=0, sticky="W", pady=5)
entry_key = ttk.Entry(frame)
entry_key.grid(row=2, column=1, columnspan=2, pady=5)


mode_var = tk.StringVar(value="Encrypt")
ttk.Label(frame, text="Select Mode:").grid(row=3, column=0, sticky="W", pady=5)
ttk.Radiobutton(frame, text="Encrypt", variable=mode_var, value="Encrypt").grid(row=3, column=1, sticky="W")
ttk.Radiobutton(frame, text="Decrypt", variable=mode_var, value="Decrypt").grid(row=3, column=2, sticky="W")

# Process button
ttk.Button(frame, text="Process", command=process).grid(row=4, column=0, columnspan=3, pady=10)

# Output label
output_var = tk.StringVar()
ttk.Label(frame, text="Result:").grid(row=5, column=0, sticky="W", pady=5)
ttk.Entry(frame, textvariable=output_var, width=50, state='readonly').grid(row=5, column=1, columnspan=2, pady=5)

root.mainloop()
