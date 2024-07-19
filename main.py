from tkinter import *
from tkinter import messagebox
from PIL import Image, ImageTk
from Crypto.Cipher import AES
import base64


def pad(text):
    """Add padding to the text to make it a multiple of 16 bytes"""
    while len(text) % 16 != 0:
        text += ' '
    return text


def encrypt_text(text, key):
    key = pad(key)[:16].encode()  # Ensure the key is exactly 16 bytes long
    text = pad(text)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_bytes = cipher.encrypt(text.encode())
    return base64.b64encode(encrypted_bytes).decode()


def decrypt_text(encrypted_text, key):
    key = pad(key)[:16].encode()  # Ensure the key is exactly 16 bytes long
    encrypted_bytes = base64.b64decode(encrypted_text)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    return decrypted_bytes.decode().strip()


def save_encrypted_file(title, encrypted_text):
    with open("encrypted_notes.txt", "a") as file:
        file.write(f"Title: {title}\n")
        file.write(f"Encrypted Note: {encrypted_text}\n")
        file.write("=" * 50 + "\n")  # Notları ayırmak için bir ayraç ekleyin


def load_titles():
    try:
        with open("encrypted_notes.txt", "r") as file:
            lines = file.readlines()
    except FileNotFoundError:
        print("No encrypted notes found.")
        return []

    titles = []
    for line in lines:
        if line.startswith("Title:"):
            titles.append(line.split(": ")[1].strip())
    return titles


# Tkinter penceresini oluşturma
win = Tk()
win.title("SecretNotes")
win.geometry("700x700")
win.resizable(False, False)

# Görseli yükle
bg = Image.open("vadaa.jpg")
bgImg = ImageTk.PhotoImage(bg)

# Canvas oluştur ve görseli ekle
canvas = Canvas(win, width=bg.width, height=bg.height)
canvas.pack(fill="both", expand=True)
canvas.create_image(0, 0, image=bgImg, anchor="nw")


def encrypt():
    title = noteTitle.get()
    masterKey = masterK.get()
    n = note.get("1.0", END).strip()

    if title and masterKey and n:
        encrypted_note = encrypt_text(n, masterKey)
        save_encrypted_file(title, encrypted_note)
        print(f"Note titled '{title}' has been encrypted and saved.")
        listbox.insert(END, title)
        # Alanları temizle
        noteTitle.delete(0, END)
        masterK.delete(0, END)
        note.delete("1.0", END)
    else:
        messagebox.showwarning("Missing Information", "All fields must be filled.")


def decrypt():
    selected_title = listbox.get(ACTIVE)
    masterKey = masterK.get()

    if not selected_title or not masterKey:
        messagebox.showwarning("Missing Information", "A title must be selected and Master Key must be provided.")
        return

    try:
        with open("encrypted_notes.txt", "r") as file:
            lines = file.readlines()
    except FileNotFoundError:
        messagebox.showerror("Error", "No encrypted notes found.")
        return

    encrypted_text = None
    for i, line in enumerate(lines):
        if line.strip() == f"Title: {selected_title}":
            encrypted_text = lines[i + 1].split(": ")[1].strip()
            break

    if encrypted_text:
        decrypted_note = decrypt_text(encrypted_text, masterKey)
        note.delete("1.0", END)
        note.insert("1.0", decrypted_note)
        print(f"Note titled '{selected_title}' has been decrypted.")
    else:
        messagebox.showerror("Error", "No matching title found.")


noteTitleLab = Label(win, text="Note Title", font=("Helvetica"), bg="gray", pady=10)
noteTitle = Entry(win, font=("Helvetica"))
noteLab = Label(win, text="Note", font=("Helvetica"), bg="gray", pady=10)
note = Text(win, font=("Helvetica"), width=50, height=5)
masterKLab = Label(win, text="Master Key", bg="gray", pady=10)
masterK = Entry(win, font=("Helvetica"))
encrypt_button = Button(win, text="Save & Encrypt", font=("Helvetica", 12), command=encrypt)
decrypt_button = Button(win, text="Decrypt", font="Helvetica", command=decrypt)

listbox = Listbox(win, width=50, height=4)
titles = load_titles()
for title in titles:
    listbox.insert(END, title)

# Bileşenleri Canvas üzerine yerleştirme
canvas.create_window(350, 30, window=noteTitleLab)  # X, Y koordinatları ile ayarlandı
canvas.create_window(350, 70, window=noteTitle)
canvas.create_window(350, 110, window=noteLab)
canvas.create_window(350, 180, window=note)
canvas.create_window(350, 280, window=masterKLab)
canvas.create_window(350, 320, window=masterK)
canvas.create_window(350, 360, window=encrypt_button)
canvas.create_window(350, 500, window=decrypt_button)
canvas.create_window(350, 440, window=listbox)

# PhotoImage nesnesini referans olarak saklama
canvas.image = bgImg

win.mainloop()