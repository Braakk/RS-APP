import argparse
from datetime import datetime
import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import ttkbootstrap as ttkb # type: ignore
import asyncio
import Backend
import qrcode
import queue
from PIL import Image, ImageTk

class EnhancedChatroom(tk.Tk):
    def __init__(self, backend):
        self.backend: Backend.Backend = backend

        super().__init__()

        self.title("InfinityLock Client")
        self.geometry("1200x700")

        style = ttkb.Style(theme="darkly")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.main_frame = ttk.Frame(self)
        self.main_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_columnconfigure(1, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        self.blocked_users = set()
        self.notifications_enabled = True
        self.privateMessages = {}
        self.conversations = {"General": {"type": "group", "users": [], "messages": []}}

        self.setup_ui()

    def setup_ui(self):
        self.setup_header()
        self.setup_user_list()
        self.setup_chat_area()
        self.setup_input_area()
        self.setup_menu()
        self.setup_members_list()

        self.login()

    ## Main Window ##

    def setup_header(self):
        header = ttk.Label(self.main_frame, text="InfinityLock", font=("Helvetica", 24, "bold"))
        header.grid(row=0, column=0, columnspan=3, pady=(0, 20))

    def setup_user_list(self):
        user_frame = ttk.Frame(self.main_frame)
        user_frame.grid(row=1, column=0, sticky="ns", padx=(0, 20))
        
        ttk.Label(user_frame, text="Utilisateurs", font=("Helvetica", 16, "bold")).pack(pady=(0, 10))
        
        self.user_listbox = tk.Listbox(user_frame, width=20, font=("Helvetica", 12))
        self.user_listbox.pack(expand=True, fill="both")
        self.user_listbox.bind("<Double-1>", self.on_user_double_click)
        self.user_listbox.bind("<Button-3>", self.on_user_select)
    
    def on_user_double_click(self, event):
        if self.user_listbox.curselection():
            selected_user = self.user_listbox.get(self.user_listbox.curselection())
            self.start_private_conversation(selected_user)
        else:
            print("Aucun utilisateur sélectionné")

    def setup_chat_area(self):
        chat_frame = ttk.Frame(self.main_frame)
        chat_frame.grid(row=1, column=1, sticky="nsew")
        chat_frame.grid_rowconfigure(0, weight=1)
        chat_frame.grid_columnconfigure(0, weight=1)

        self.conversation_tabs = ttk.Notebook(chat_frame)
        self.conversation_tabs.grid(row=0, column=0, sticky="nsew")

        self.chat_areas = {}
        for conv, data in self.conversations.items():
            self.create_conversation_tab(conv, data["users"])

        self.conversation_tabs.bind("<<NotebookTabChanged>>", self.on_tab_change)

        search_frame = ttk.Frame(chat_frame)
        search_frame.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.pack(side="left", expand=True, fill="x")
        ttk.Button(search_frame, text="Search", command=self.search_messages).pack(side="right")

    def create_conversation_tab(self, conv_name, users):
        tab = ttk.Frame(self.conversation_tabs)
        self.conversation_tabs.add(tab, text=conv_name)
        
        chat_frame = ttk.Frame(tab)
        chat_frame.pack(expand=True, fill="both")
        
        chat_frame.grid_rowconfigure(0, weight=1)
        chat_frame.grid_columnconfigure(0, weight=1)
        
        chat_area = tk.Text(chat_frame, wrap=tk.WORD, state="disabled", font=("Helvetica", 12))
        chat_area.grid(row=0, column=0, sticky="nsew")
        chat_area.tag_configure("user", foreground="#4CAF50")
        chat_area.tag_configure("other", foreground="#2196F3")
        chat_area.tag_configure("system", foreground="#FFA500")
        
        scrollbar = ttk.Scrollbar(chat_frame, orient="vertical", command=chat_area.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        
        chat_area["yscrollcommand"] = scrollbar.set
        
        self.chat_areas[conv_name] = chat_area

    def setup_input_area(self):
        input_frame = ttk.Frame(self.main_frame)
        input_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(20, 0))
        input_frame.grid_columnconfigure(0, weight=1)

        self.message_entry = ttk.Entry(input_frame, font=("Helvetica", 12))
        self.message_entry.grid(row=0, column=0, sticky="ew")

        send_button = ttk.Button(input_frame, text="Send", command=lambda: asyncio.create_task(self.send_message()))
        send_button.grid(row=0, column=1, padx=(10, 0))

        file_button = ttk.Button(input_frame, text="Send File", command=self.send_file)
        file_button.grid(row=0, column=2, padx=(10, 0))

        self.message_entry.bind("<Return>", lambda event: asyncio.create_task(self.send_message()))

    def setup_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Toggle Notifications", command=self.toggle_notifications)
        settings_menu.add_command(label="Create New Conversation", command=self.create_new_conversation)
        settings_menu.add_command(label="View Profile", command=self.view_profile)
        settings_menu.add_command(label="Logout", command=self.logout)

    def setup_members_list(self):
        members_frame = ttk.Frame(self.main_frame)
        members_frame.grid(row=1, column=2, sticky="ns", padx=(20, 0))
        
        ttk.Label(members_frame, text="Members", font=("Helvetica", 16, "bold")).pack(pady=(0, 10))
        
        self.members_listbox = tk.Listbox(members_frame, width=20, font=("Helvetica", 12))
        self.members_listbox.pack(expand=True, fill="both")

    async def send_message(self):
        message = self.message_entry.get().strip()
        if message:
            if self.conversations[self.backend.current_conversation]["type"] == "user":
                toUser = self.backend.current_conversation

                await self.backend.sendUserMessage(toUser, message)
                
                timestamp = datetime.now().strftime("%H:%M:%S")
                full_message = f"[{timestamp}] You: {message}\n"

                chat_area = self.chat_areas[self.backend.current_conversation]
                chat_area.config(state="normal")
                chat_area.insert(tk.END, full_message, "user")
                chat_area.config(state="disabled")
                chat_area.see(tk.END)

                self.message_entry.delete(0, tk.END)

    # To implement
    def send_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            file_name = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%H:%M:%S")
            full_message = f"[{timestamp}] {self.backend.username} sent a file: {file_name}\n"
            
            chat_area = self.chat_areas[self.backend.current_conversation]
            chat_area.config(state="normal")
            chat_area.insert(tk.END, full_message, "system")
            chat_area.config(state="disabled")
            chat_area.see(tk.END)
            
            self.conversations[self.backend.current_conversation]["messages"].append(full_message)

            if self.notifications_enabled:
                self.show_notification(f"New file shared in {self.backend.current_conversation}")

    # To verify
    def load_conversation(self):
        chat_area = self.chat_areas[self.backend.current_conversation]
        chat_area.config(state="normal")
        chat_area.delete("1.0", tk.END)
        if self.conversations[self.backend.current_conversation]["type"] == "user":
            self.conversations[self.backend.current_conversation]["messages"] = self.backend.loadUserConversation(self.backend.current_conversation)

        for message in self.conversations[self.backend.current_conversation]["messages"]:
            chat_area.insert(tk.END, message, "user")
            # if self.backend.username in message:
            #     chat_area.insert(tk.END, message, "user")
            # elif "sent a file:" in message:
            #     chat_area.insert(tk.END, message, "system")
            # else:
            #     chat_area.insert(tk.END, message, "other")
        chat_area.config(state="disabled")
        chat_area.see(tk.END)

        # Update members list
        self.members_listbox.delete(0, tk.END)
        for user in self.conversations[self.backend.current_conversation]["users"]:
            self.members_listbox.insert(tk.END, user)

    # To verify
    def update_user_list(self):
        self.user_listbox.delete(0, tk.END)
        for user in self.backend.users:
            if user not in self.blocked_users and user != self.backend.username:
                self.user_listbox.insert(tk.END, user)

    # To verify
    def toggle_notifications(self):
        self.notifications_enabled = not self.notifications_enabled
        status = "enabled" if self.notifications_enabled else "disabled"
        messagebox.showinfo("Notifications", f"Notifications are now {status}")

    # To verify
    def show_notification(self, message):
        messagebox.showinfo("New Message", message)

    # To verify
    def search_messages(self):
        query = self.search_entry.get().lower()
        results = []
        for conversation, data in self.conversations.items():
            for message in data["messages"]:
                if query in message.lower():
                    results.append(f"[{conversation}] {message}")
        
        if results:
            result_window = tk.Toplevel(self)
            result_window.title("Search Results")
            result_text = tk.Text(result_window, wrap=tk.WORD, font=("Helvetica", 12))
            result_text.pack(expand=True, fill="both")
            for result in results:
                result_text.insert(tk.END, result)
        else:
            messagebox.showinfo("Search Results", "No matches found")

    ## TOTP Window ##

    def get_totp(self, q):
        # Création de la fenêtre
        totp_window = tk.Tk()
        totp_window.title("Enter TOTP")

        # Ajout d'un champ de saisie pour le token TOTP
        ttk.Label(totp_window, text="TOTP Token:").grid(row=0, column=0, padx=5, pady=5)
        totp_entry = ttk.Entry(totp_window)
        totp_entry.grid(row=0, column=1, padx=5, pady=5)

        # Fonction pour soumettre le token TOTP
        def submit():
            totpToken = totp_entry.get()
            q.put(totpToken)  # Mettre le token dans la queue
            totp_window.destroy()

        # Ajout d'un bouton pour soumettre le token TOTP
        ttk.Button(totp_window, text="Submit", command=submit).grid(row=1, column=0, columnspan=2, pady=10)

        totp_window.mainloop()

    def display_qr_and_get_totp(self, secret, queue):
        window = tk.Tk()
        window.title("2FA Setup")

        totpToken = None

        # Generate the QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data("otpauth://totp/InfinityLock:" + self.backend.username + "?secret=" + secret)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        img = img.resize((150, 150), Image.Resampling.LANCZOS)
        photo = ImageTk.PhotoImage(img, master=window)  # Assign window as the master

        # Display the QR code
        qr_label = tk.Label(window, image=photo)
        qr_label.photo = photo  # Keep a reference to avoid garbage collection
        qr_label.pack()

        # Entry field for TOTP token
        totp_entry = tk.Entry(window)
        totp_entry.pack()

        # Function to submit the TOTP token
        def submit():
            nonlocal totpToken
            totpToken = totp_entry.get()
            window.destroy()

        submit_button = tk.Button(window, text="Submit", command=submit)
        submit_button.pack()

        window.mainloop()
        queue.put(totpToken)

    ## Login Window ##

    def login(self):
        login_window = tk.Toplevel(self)
        login_window.title("Login")

        ttk.Label(login_window, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        username_entry = ttk.Entry(login_window)
        username_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(login_window, text="Bio:").grid(row=1, column=0, padx=5, pady=5)
        bio_entry = ttk.Entry(login_window)
        bio_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Button(login_window, text="Login", command=lambda: asyncio.create_task(self.authenticate(username_entry.get(), login_window))).grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(login_window, text="Register", command=lambda: asyncio.create_task(self.register(username_entry.get(), bio_entry.get(), login_window))).grid(row=3, column=0, columnspan=2)

    ## Login and Registration ##

    async def authenticate(self, username: str, login_window):
        self.backend.username = username
        login = False
        await self.backend.sendMessage({"type": "login", "authMethod": "RSASignature", "email": username})
        while not login:
            message = await self.receivedMessage()
    
            if message.get("type") == "login" and message.get("authMethod") == "RSASignature" and message.get("Value") is not None:
                signature = self.backend.rsaKey.sign(bytes.fromhex(message["Value"]))
                await self.backend.sendMessage({"type": "login", "authMethod": "RSASignature", "signature": signature.hex()})
    
            elif message.get("type") == "login" and message.get("authMethod") == "TOTP" and message.get("message") == "SendTOTPToken":
                q = queue.Queue()
                # Créez et démarrez un thread pour Tkinter
                threading.Thread(target=self.get_totp, args=(q,), daemon=True).start()
                # Attendez que le token soit mis dans la queue
                while q.empty():
                    await asyncio.sleep(0.1)
                totpToken = q.get()
                await self.backend.sendMessage({"type": "login", "authMethod": "TOTP", "Value": totpToken})
    
            elif message.get("type") == "login" and message.get("status") == "success":
                login = True
    
            else:
                print("Unexpected message received. Exiting.")
                self.backend.writer.close()
                exit(1)
    
        messagebox.showinfo("Registration Successful", "You are login")
        login_window.destroy()
        await self.backend.sync()
        self.update_user_list()
        #self.load_conversation()

    async def register(self, username: str, bio: str, login_window):
        if username:
            self.backend.username = username
            await self.backend.sendMessage({"type": "register", "email": username, "bio": bio})

            login = False
            while not login:
                message = await self.receivedMessage()

                if message["type"] == "register" and message["message"] == "generateRSAKeys":
                    self.backend.rsaKey.generate_keys()
                    publicKey = self.backend.rsaKey.get_public_key()
                    await self.backend.sendMessage({"type": "register", "publicKey": publicKey})
                
                elif message["type"] == "register" and message["message"] == "add2FAMethod":
                    add2FA = messagebox.askyesno("2FA Method", "Do you want to add a 2FA method?")
                    add2FA = "yes" if add2FA else "no"
                    await self.backend.sendMessage({"type": "register", "Value": add2FA, "authMethod": "TOTP"})

                elif message["type"] == "register" and message["message"] == "TOTPSecretAndGetTOTPToken":
                    q = queue.Queue()
                    # Créez et démarrez un thread pour Tkinter
                    threading.Thread(target=self.display_qr_and_get_totp, args=(message["secret"], q), daemon=True).start()
                    # Attendez que le token soit mis dans la queue
                    while q.empty():
                        await asyncio.sleep(0.1)
                    totpToken = q.get()
                    await self.backend.sendMessage({"type": "register", "authMethod": "TOTP", "Value": totpToken})

                elif message["type"] == "register" and message["status"] == "success":
                    login = True
                    print("Successfully registered.")

                else:
                    print("Unexpected message received. Exiting.")
                    self.backend.writer.close()
                    exit(1)
            
            messagebox.showinfo("Registration Successful", "You are login")
            login_window.destroy()
            await self.backend.sync()
            self.update_user_list()
        else:
            messagebox.showerror("Registration Failed", "Username and RSA key are required")

    def logout(self):
        self.backend.username = None
        self.login()

    async def receivedMessage(self):
        await self.backend.messageReceived.wait()  # Attendre que l'événement soit déclenché
        if self.backend.messageTopic:  # Vérifier si la liste des messages n'est pas vide
            message = self.backend.messageTopic.pop(0)  # Récupérer le premier message
            if not self.backend.messageTopic:  # Si la liste est vide après le retrait, réinitialiser l'événement
                self.backend.messageReceived.clear()
            return message
        return None
    
    ## Main Window Functions ##

    def view_profile(self):
        if self.backend.username:
            profile_window = tk.Toplevel(self)
            profile_window.title(f"Profile - {self.backend.username}")
            profile_window.geometry("400x200")
            profile_window.grid_columnconfigure(0, weight=1)
            profile_window.grid_rowconfigure(0, weight=1)

            profile_frame = ttk.Frame(profile_window)
            profile_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)

            ttk.Label(profile_frame, text="Username:", font=("Helvetica", 12, "bold")).grid(row=0, column=0, sticky="w", pady=5)
            ttk.Label(profile_frame, text=self.backend.username).grid(row=0, column=1, sticky="w", pady=5)

            ttk.Label(profile_frame, text="Bio:", font=("Helvetica", 12, "bold")).grid(row=1, column=0, sticky="w", pady=5)
            bio_entry = ttk.Entry(profile_frame, width=30)
            bio_entry.insert(0, self.backend.users[self.backend.username]["profile"]["bio"])
            bio_entry.grid(row=1, column=1, sticky="w", pady=5)

            ttk.Label(profile_frame, text="Email:", font=("Helvetica", 12, "bold")).grid(row=2, column=0, sticky="w", pady=5)
            email_entry = ttk.Entry(profile_frame, width=30)
            email_entry.insert(0, self.backend.users[self.backend.username]["profile"]["email"])
            email_entry.grid(row=2, column=1, sticky="w", pady=5)

            ttk.Button(profile_frame, text="Update Profile", command=lambda: self.update_profile(bio_entry.get(), email_entry.get())).grid(row=3, column=0, columnspan=2, pady=20)

    # To Implement
    async def update_profile(self, bio, email):
        await self.backend.sendMessage({"type": "updateProfile", "bio": bio, "email": email})
        self.backend.users[self.backend.username]["profile"]["bio"] = bio
        self.backend.users[self.backend.username]["profile"]["email"] = email

        message = await self.receivedMessage()
        if message["type"] == "updateProfile" and message["status"] == "success":
            messagebox.showinfo("Profile Updated", "Your profile has been updated successfully.")
        else:
            messagebox.showerror("Profile Update Failed", "An error occurred while updating your profile.")

    def on_user_select(self, event):
        selected_user = self.user_listbox.get(self.user_listbox.curselection())
        action = simpledialog.askstring("User Action", f"What would you like to do with {selected_user}?", 
                                        initialvalue="View Profile/Block/Message")
        
        if action:
            action = action.lower()
            if "view" in action or "profile" in action:
                self.view_other_profile(selected_user)
            elif "block" in action:
                self.blocked_users.add(selected_user)
                self.update_user_list()
            elif "message" in action:
                self.start_private_conversation(selected_user)

    def view_other_profile(self, username):
        profile_window = tk.Toplevel(self)
        profile_window.title(f"Profile - {username}")
        profile_window.geometry("400x200")
        profile_window.grid_columnconfigure(0, weight=1)
        profile_window.grid_rowconfigure(0, weight=1)

        profile_frame = ttk.Frame(profile_window)
        profile_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)

        ttk.Label(profile_frame, text="Username:", font=("Helvetica", 12, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        ttk.Label(profile_frame, text=username).grid(row=0, column=1, sticky="w", pady=5)

        ttk.Label(profile_frame, text="Bio:", font=("Helvetica", 12, "bold")).grid(row=1, column=0, sticky="w", pady=5)
        ttk.Label(profile_frame, text=self.backend.users[username]["profile"]["bio"]).grid(row=1, column=1, sticky="w", pady=5)

        ttk.Label(profile_frame, text="Email:", font=("Helvetica", 12, "bold")).grid(row=2, column=0, sticky="w", pady=5)
        ttk.Label(profile_frame, text=self.backend.users[username]["profile"]["email"]).grid(row=2, column=1, sticky="w", pady=5)

    def start_private_conversation(self, other_user):
        conv_name = f"{other_user}"
        if conv_name not in self.conversations:
            self.conversations[conv_name] = {"type": "user", "users": [self.backend.username, other_user], "messages": []}
            self.create_conversation_tab(conv_name, [self.backend.username, other_user])
        self.backend.current_conversation = conv_name
        tab_ids = []

        for i in range(self.conversation_tabs.index("end")):
            tab_id = self.conversation_tabs.tab(i, "text")
            tab_ids.append(tab_id)
        
        self.conversation_tabs.select(self.conversation_tabs.index(tab_ids.index(conv_name)))
        self.update_members_list(conv_name)

    def create_new_conversation(self):
        conversation_name = simpledialog.askstring("New Conversation", "Enter conversation name:")
        if conversation_name and conversation_name not in self.conversations:
            user_selection = UserSelectionDialog(self, [user for user in self.backend.users.keys() if user != self.backend.username])
            self.wait_window(user_selection)
            selected_users = user_selection.result
            if selected_users:
                selected_users.append(self.backend.username)  # Add the current user to the conversation
                self.conversations[conversation_name] = {"users": selected_users, "messages": []}
                self.create_conversation_tab(conversation_name, selected_users)
                self.backend.current_conversation = conversation_name
                self.conversation_tabs.select(self.conversation_tabs.index("end") - 1)
                self.update_members_list(conversation_name)
            elif user_selection.dialog_result != "cancel":
                messagebox.showwarning("Warning", "No users selected. Conversation not created.")
        elif conversation_name in self.conversations:
            messagebox.showwarning("Warning", "Conversation name already exists.")

    def update_members_list(self, conversation):
        self.members_listbox.delete(0, tk.END)
        for user in self.conversations[conversation]["users"]:
            self.members_listbox.insert(tk.END, user)

    def on_tab_change(self, event):
        selected_tab = self.conversation_tabs.select()
        self.backend.current_conversation = self.conversation_tabs.tab(selected_tab, "text")
        self.load_conversation()
        self.update_members_list(self.backend.current_conversation)

    # To verify
    def show_discrete_notification(self, message):
        notification_window = tk.Toplevel(self)
        notification_window.overrideredirect(True)  # Remove window decorations
        notification_window.attributes("-topmost", True)  # Keep on top of other windows
    
        # Position the notification in the bottom-right corner
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        notification_window.geometry(f"200x50+{screen_width-220}+{screen_height-80}")
    
        ttk.Label(notification_window, text=message, wraplength=180).pack(expand=True, fill="both")
    
        # Auto-close the notification after 3 seconds
        notification_window.after(3000, notification_window.destroy)

# To verify
class UserSelectionDialog(tk.Toplevel):
    def __init__(self, parent, users):
        super().__init__(parent)
        self.title("Select Users")
        self.backend.users = users
        self.result = []
        self.dialog_result = None

        self.user_listbox = tk.Listbox(self, selectmode=tk.MULTIPLE, width=30, height=10)
        self.user_listbox.pack(padx=10, pady=10)

        for user in self.backend.users:
            self.user_listbox.insert(tk.END, user)

        ttk.Button(self, text="Select", command=self.on_select).pack(side=tk.LEFT, padx=10, pady=10)
        ttk.Button(self, text="Cancel", command=self.on_cancel).pack(side=tk.RIGHT, padx=10, pady=10)

    def on_select(self):
        selected_indices = self.user_listbox.curselection()
        self.result = [self.backend.users[i] for i in selected_indices]
        self.dialog_result = "select"
        self.destroy()

    def on_cancel(self):
        self.dialog_result = "cancel"
        self.destroy()

async def tk_update(app):
    try:
        while True:
            # Mettre à jour la liste des utilisateurs toutes les 10s
            if app.backend.newMessage:
                app.load_conversation()
                app.backend.newMessage = False
            if app.backend.newUser:
                app.update_user_list()
                app.backend.newUser = False
            app.update()
            await asyncio.sleep(0.01)  # Attendre un peu avant la prochaine mise à jour
    except tk.TclError as e:
        if "application has been destroyed" not in str(e):
            raise

async def main():
    parser = argparse.ArgumentParser(description="Start the InfinityLock client.")
    parser.add_argument("-s", "--server", type=str, help="The address of the server", required=False, default="localhost")
    parser.add_argument("-p", "--port", type=int, help="The listening port of the server", required=False, default=5020)
    parser.add_argument("--disable-ssl", action="store_true", help="Disable SSL encryption", required=False, default=False)
    parser.add_argument("--allow-invalid-cert", action="store_true", help="Allow connections with invalid certificates", required=False, default=False)
    parser.add_argument("--debug", action="store_true", help="Enable debug mode", required=False, default=False)
    args = parser.parse_args()
    
    backend = Backend.Backend(args.debug, args.server, args.port, args.disable_ssl, args.allow_invalid_cert)
    app = EnhancedChatroom(backend)
    await backend.connectToServer()

    listener_task = asyncio.create_task(backend.listenner())
    tk_task = asyncio.create_task(tk_update(app))

    await asyncio.gather(listener_task, tk_task)

if __name__ == "__main__":
    asyncio.run(main())