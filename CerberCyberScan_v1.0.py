import ctypes
import sys
import os
import re
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox, PhotoImage, Label, filedialog
from PIL import Image, ImageTk
import paramiko
import queue
import subprocess
import webbrowser

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Ajoutez une vérification pour voir si '--elevated' est dans les arguments de ligne de commande
is_elevated = '--elevated' in sys.argv

if is_admin():
    pass  # Votre code ici
else:
    if not is_elevated:
        # Relancez le programme avec les droits d'administrateur et l'argument --elevated
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv) + " --elevated", None, 1)
    else:
        # L'application a déjà été relancée avec élévation, évitez de boucler
        pass

proc = None  
global_ssh_client = None  
channel = None  

powershell_output_queue = queue.Queue()
current_command = ''
message_queue = queue.Queue()

def launch_reparation_in_background():
    """Lance le script reparation.bat en arrière-plan."""
    subprocess.call(["cmd.exe", "/c", "reparation.bat"], shell=True)

def launch_reparation():
    """Crée un thread pour exécuter le script reparation.bat sans bloquer l'interface utilisateur."""
    thread = threading.Thread(target=launch_reparation_in_background)
    thread.start()

def run_powershell_cmd(cmd):
    completed_process = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
    if completed_process.returncode != 0:
        print(f"Erreur lors de l'exécution de la commande: {cmd}")
        print(completed_process.stderr)
    else:
        print(completed_process.stdout)

def optimiser_windows_thread():
    if not is_admin():
        # Relance le programme avec les droits d'administrateur si nécessaire
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        return

    services_to_disable = [
        "XblAuthManager",
        "XblGameSave",
        "XboxNetApiSvc",
        "DiagTrack"
    ]

    tasks_to_disable = [
        "\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
        "\\Microsoft\\Windows\\Application Experience\\ProgramDataUpdater",
        "\\Microsoft\\Windows\\Autochk\\Proxy",
        "\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
        "\\Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask",
        "\\Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
    ]

    for service in services_to_disable:
        print(f"Désactivation du service {service}...")
        run_powershell_cmd(f"Set-Service -Name {service} -StartupType Disabled")

    for task in tasks_to_disable:
        print(f"Désactivation de la tâche planifiée {task}...")
        run_powershell_cmd(f"Schtasks /Change /TN \"{task}\" /DISABLE")

    messagebox.showinfo("Optimisation Windows", "Optimisation terminée.")

def optimiser_windows():
    # Création et démarrage d'un thread pour l'optimisation de Windows
    threading.Thread(target=optimiser_windows_thread).start()

def open_paypal_link():
    webbrowser.open_new("https://www.paypal.com/donate/?hosted_button_id=FSX7RHUT4BDRY")

about_window_open = False

def show_about():
    global about_window_open
    if about_window_open:  
        return 

    about_window_open = True 

    about_window = tk.Toplevel(root)
    about_window.title("À propos")
    about_window.geometry("300x250")

    # Charger l'image "logo_avhiral.jpg" et l'utiliser dans un widget Label
    pil_image = Image.open("logo_avhiral.png") 
    logo_image = ImageTk.PhotoImage(pil_image)
    # Conserver une référence à l'image pour éviter la collecte de déchets
    about_window.logo_image = logo_image
    # Utiliser l'image dans un widget Label
    logo_label = tk.Label(about_window, image=about_window.logo_image)
    logo_label.pack(pady=(10, 0))  # Ajouter un peu d'espace vertical pour une meilleure mise en page

    # Affichage des informations À propos
    about_info = tk.Label(about_window, text="CerberCyberScan V1.0\n\nCopyright 2024 ® - AVHIRAL\nSIRET : 954-046-108-00013", font=("Arial", 10, "bold"))
    about_info.pack(pady=(5, 10))

    # Lien du site web
    website_link = tk.Label(about_window, text="WWW.AVHIRAL.COM", fg="blue", cursor="hand2")
    website_link.pack()
    website_link.bind("<Button-1>", lambda e: webbrowser.open_new("https://www.avhiral.com"))

    # Bouton OK pour fermer la fenêtre À propos
    ok_button = tk.Button(about_window, text="OK", command=lambda: on_close(about_window))
    ok_button.pack(pady=(5, 10))

    def on_close(window):
        global about_window_open
        about_window_open = False  
        window.destroy()

    about_window.protocol("WM_DELETE_WINDOW", lambda: on_close(about_window))

# Fonction pour effacer la fenêtre de log
def clear_log():
    """Efface le contenu de la fenêtre de log."""
    log_text.delete('1.0', tk.END)

def start_powershell_process():
    global proc
    proc = subprocess.Popen(['powershell'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# Appeler cette fonction pour démarrer le processus PowerShell avant de l'utiliser dans write_from_log_to_powershell
start_powershell_process()

# Fonctions pour mettre à jour le log
def update_log(message):
    """Ajoute un message à la fenêtre de log."""
    log_text.insert(tk.END, message + "\n")
    log_text.see(tk.END)

def execute_command_and_update_log(command, log_widget):
    def run_command():
        # Démarrer le processus PowerShell
        process = subprocess.Popen(["powershell", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Lire la sortie en temps réel
        for line in iter(process.stdout.readline, ''):
            log_widget.after(1, update_log, line)  # Planifier l'update_log pour s'exécuter dans le thread principal
        process.stdout.close()
        process.wait()

    def update_log(line):
        log_widget.insert(tk.END, line)
        log_widget.see(tk.END)  # Faire défiler automatiquement vers le bas

    # Exécuter la commande dans un thread pour éviter de bloquer l'interface graphique
    threading.Thread(target=run_command, daemon=True).start()

def load_and_execute_boot_script():
    try:
        # Chemin où le script sera copié (par exemple, dans le répertoire System32)
        destination_path = os.path.join(os.environ['WINDIR'], 'System32', 'boot.ps1')
        
        # Copie du script "boot.ps1" dans le répertoire cible
        script_source = 'boot.ps1'  # Chemin d'accès au script "boot.ps1"
        with open(script_source, 'r') as source, open(destination_path, 'w') as dest:
            dest.write(source.read())
        
        # Création d'une tâche planifiée pour exécuter le script au démarrage de Windows
        subprocess.run(["schtasks", "/Create", "/SC", "ONSTART", "/TN", "SecureBootScript", "/TR", f"powershell -ExecutionPolicy Bypass -File {destination_path}"], check=True)
        
        messagebox.showinfo("Succès", "Le script boot.ps1 a été chargé et sera exécuté au démarrage de Windows.")
    except Exception as e:
        messagebox.showerror("Erreur", f"Une erreur est survenue : {e}")

def load_and_execute_ps_script():
    try:
        # Chemin où le script sera copié (dans la racine de Windows, par exemple C:\Windows)
        destination_path = os.path.join(os.environ['WINDIR'], 'DDoS_Monitor.ps1')
        
        # Copie du script dans le répertoire cible
        script_source = 'DDoS_Monitor.ps1'  
        with open(script_source, 'r') as source, open(destination_path, 'w') as dest:
            dest.write(source.read())
        
        # Création d'une tâche planifiée pour exécuter le script au démarrage de Windows
        subprocess.run(["schtasks", "/Create", "/SC", "ONSTART", "/TN", "DDoSMonitorStartup", "/TR", f"powershell -ExecutionPolicy Bypass -File {destination_path}"], check=True)
        
        messagebox.showinfo("Succès", "Le script DDoS_Monitor.ps1 a été chargé et sera exécuté au démarrage de Windows.")
    except Exception as e:
        messagebox.showerror("Erreur", f"Une erreur est survenue : {e}")

# Fonction pour se connecter au serveur SSH
def ssh_connect(username, password, hostname, port):
    global global_ssh_client
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, port=port, username=username, password=password)
        global_ssh_client = client  # Mise à jour de la variable globale
        return client
    except Exception as e:
        messagebox.showerror("Erreur de connexion SSH", str(e))
        return None

def write_to_shell(event):
    global channel
    command = entry_command.get().rstrip()
    if command:
        # Lancer un thread pour envoyer la commande
        threading.Thread(target=send_command, args=(command,), daemon=True).start()
        entry_command.delete(0, tk.END)

def write_from_log_to_powershell(event):
    global proc, global_ssh_client  # Référence aux variables globales
    current_line_index = log_text.index("insert linestart")
    line_text = log_text.get(current_line_index, current_line_index + " lineend").strip()

    if line_text:
        if global_ssh_client:  # Vérifie si une connexion SSH est active
            send_command(line_text)  # Utilise la fonction send_command pour envoyer via SSH
        else:
            # Envoie la commande à PowerShell
            proc.stdin.write(line_text + "\n")
            proc.stdin.flush()
        # Supprime la ligne après l'envoi de la commande
        log_text.delete(current_line_index, current_line_index + " lineend")

def send_command(command, update_log_live=False, callback=None):
    def command_execution():
        global global_ssh_client
        if global_ssh_client:
            stdin, stdout, stderr = global_ssh_client.exec_command(command, get_pty=True)
            if update_log_live:
                while True:
                    line = stdout.readline()
                    if not line:
                        break
                    update_log(line.strip())
                stderr_output = stderr.read().decode().strip()
                if stderr_output:
                    update_log(stderr_output)
            else:
                stdout_output = stdout.read().decode().strip()
                stderr_output = stderr.read().decode().strip()
                return stdout_output, stderr_output
        else:
            update_log("Connection not established")
        if callback:
            callback()

    if update_log_live:
        threading.Thread(target=command_execution).start()
        return "", ""  # Renvoie un tuple vide pour les appels asynchrones
    else:
        return command_execution()

def on_key_press(event):
    global channel, current_command
    if event.char and event.char.isprintable():
        current_command += event.char
    elif event.keysym == 'Return':
        channel.send(current_command + '\n')
        current_command = ''
    elif event.keysym == 'BackSpace':
        current_command = current_command[:-1]

def ssh_shell_interaction(ssh_client):
    global current_mode, channel
    current_mode = 'SSH'
    channel = ssh_client.invoke_shell()
    # Le reste de votre code pour l'interaction SSH
    print("Mode SSH activé")  # Débogage

    def read_from_shell():
        while True:
            if channel.recv_ready():
                data = channel.recv(1024).decode('utf-8', 'replace')
                message_queue.put(data)
            else:
                # Ajout d'une petite pause pour éviter de surcharger le thread
                time.sleep(0.1)

    read_thread = threading.Thread(target=read_from_shell, daemon=True)
    read_thread.start()

    log_text.bind('<KeyPress>', on_key_press)

    # Lier la touche Entrée à l'envoi de commandes
    entry_command.bind('<Return>', write_to_shell)

# Création de la file d'attente pour les messages
message_queue = queue.Queue()

def process_queue():
    while not message_queue.empty():
        message = message_queue.get()
        clean_message = re.sub(r'\x1B\[([0-?]*[ -/]*[@-~])', '', message)
        log_text.insert(tk.END, clean_message)
        log_text.see(tk.END)
    root.after(50, process_queue)

def block_malicious_bots():
    global global_ssh_client
    if global_ssh_client is None:
        messagebox.showerror("Erreur", "Veuillez d'abord établir une connexion SSH.")
        return

    commands = [
        # Règles existantes
        "sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set",
        "sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP",
        
        # Bloquer les scans de ports
        "sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP",
        "sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP",
        
        # Bloquer les requêtes ICMP excessives
        "sudo iptables -A INPUT -p icmp -m icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT",
        "sudo iptables -A INPUT -p icmp -j DROP",
        
        # Limiter le taux de nouvelles connexions par seconde
        "sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT",
        "sudo iptables -A INPUT -p tcp --syn -j DROP",
        
        # Ajoutez d'autres règles selon vos besoins
    ]

    for cmd in commands:
        stdin, stdout, stderr = global_ssh_client.exec_command(cmd)
        update_log(stdout.read().decode())
        update_log(stderr.read().decode())

    update_log("Règles iptables avancées appliquées pour renforcer la sécurité.")

def audit_windows():
    if not proc:
        messagebox.showerror("Erreur", "Veuillez d'abord ouvrir une session PowerShell.")
        return

    update_log("Début de l'audit Windows, veuillez patienter...")

    commands = [
        'Get-ComputerInfo | Format-List',  # Utilisez Format-List pour obtenir une sortie formatée
        'Get-LocalUser | Format-List',
        'Get-LocalGroup | Format-List',
        'Get-NetFirewallProfile | Format-List',
        'Get-Process -IncludeUserName | Format-List',
        'Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | Format-List',
        'Get-AppxPackage',
    ]

    command_outputs = []  # Liste pour stocker les résultats des commandes

    def execute_command(command):
        """Exécute une commande PowerShell et capture la sortie."""
        proc.stdin.write(command + "\n")
        proc.stdin.flush()

    def read_powershell_output():
        """Lit la sortie de PowerShell et la stocke."""
        for command in commands:
            execute_command(command)
            output = []
            while True:
                if not powershell_output_queue.empty():
                    line = powershell_output_queue.get()
                    if line.strip() == "COMMAND_DONE":
                        break
                    output.append(line)
                else:
                    time.sleep(0.1)
            command_outputs.append(''.join(output))
            update_log(''.join(output))  # Afficher chaque sortie de commande dans le log

        # Concaténer toutes les sorties de commande et sauvegarder le rapport
        final_output = "\n".join(command_outputs)
        save_audit_report(final_output, "Windows_Audit_Report")

    # Ajouter "COMMAND_DONE" à la fin de chaque commande pour identifier sa fin
    commands = [command + '; echo "COMMAND_DONE"' for command in commands]

    # Lancer un thread pour lire et traiter les sorties des commandes
    threading.Thread(target=read_powershell_output, daemon=True).start()

    def execute_command(command):
        """Exécute une commande PowerShell et capture la sortie."""
        proc.stdin.write(command + "\n")
        proc.stdin.flush()

def check_and_install_lynis():
    """
    Vérifie si Lynis est installé sur le système. S'il ne l'est pas, installe Lynis.
    """
    lynis_installed = False
    try:
        # Vérifie si Lynis est installé en exécutant 'lynis --version'
        stdin, stdout, stderr = global_ssh_client.exec_command('lynis --version')
        if stdout.read():
            lynis_installed = True
    except Exception as e:
        print(f"Erreur lors de la vérification de Lynis : {e}")

    if not lynis_installed:
        try:
            # Installer Lynis. La commande peut varier selon la distribution Linux.
            stdin, stdout, stderr = global_ssh_client.exec_command('sudo apt-get install lynis -y')
            if stdout.read():
                return True  # Lynis installé avec succès
        except Exception as e:
            print(f"Erreur lors de l'installation de Lynis : {e}")
            return False

    return lynis_installed

    def read_powershell_output():
        """Lit la sortie de PowerShell et la stocke."""
        for command in commands:
            execute_command(command)
            output = []
            while True:
                if not powershell_output_queue.empty():
                    line = powershell_output_queue.get()
                    if line.strip() == "COMMAND_DONE":
                        break
                    output.append(line)
                else:
                    time.sleep(0.1)
            command_outputs.append(''.join(output))
            update_log(''.join(output))  # Afficher chaque sortie de commande dans le log

        # Concaténer toutes les sorties de commande et sauvegarder le rapport
        final_output = "\n".join(command_outputs)
        save_audit_report(final_output, "Windows_Audit_Report")

    # Ajouter "COMMAND_DONE" à la fin de chaque commande pour identifier sa fin
    commands = [command + '; echo "COMMAND_DONE"' for command in commands]

    # Lancer un thread pour lire et traiter les sorties des commandes
    threading.Thread(target=read_powershell_output, daemon=True).start()

def audit_server():
    if not global_ssh_client:
        messagebox.showerror("Erreur", "Veuillez d'abord établir une connexion SSH.")
        return
    update_log("Audit en cours, veuillez patienter...")

    def perform_audit():
        if not check_and_install_lynis():
            return

        commands = [
            'uname -a',
            'df -h',
            'netstat -tuln',
            'ps aux',
            'sudo ufw status',
            'sudo getent passwd',  
            'sudo getent group',  
            'sudo crontab -l',  
            'sudo lynis audit system --quick',
        ]

        for cmd in commands:
            send_command(cmd, update_log_live=True)
            # Wait a bit between commands to ensure they don't overlap in the log
            time.sleep(2)

        # Utiliser un compteur pour suivre le nombre de commandes terminées
        completed_commands = 0

        def process_queue():
            while not message_queue.empty():
                message = message_queue.get()
                update_log(message)
            root.after(100, process_queue)

        def command_callback():
            nonlocal completed_commands
            completed_commands += 1
            # Si toutes les commandes ont été exécutées, enregistrer les résultats
            if completed_commands == len(commands):
                save_audit_report(log_text.get("1.0", tk.END))

        for cmd in commands:
            if cmd.startswith('sudo lynis'):
                # Exécution de l'audit Lynis et des commandes asynchrones
                send_command(cmd, update_log_live=True, callback=command_callback)
            else:
                # Exécution synchrone pour les autres commandes
                send_command(cmd)
                command_callback()  # Incrémenter manuellement pour les commandes synchrones

    threading.Thread(target=perform_audit).start()

def save_audit_report_callback():
    # Récupérer le contenu du log pour le sauvegarder en PDF
    content = log_text.get("1.0", tk.END)
    save_audit_report(content)

def clean_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B\[([0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def save_audit_report(content, default_filename="Audit_Report"):
    file_path = filedialog.asksaveasfilename(initialfile=default_filename, defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if not file_path:
        return

    with open(file_path, 'w') as file:
        file.write(content)

    messagebox.showinfo("Succès", "Le rapport d'audit a été enregistré dans log.txt.")

# Fonctions pour les commandes de sécurisation (à développer)
def execute_linux_security():
    # Récupération des informations de connexion à partir des champs de saisie
    hostname = entry_hostname.get()
    port = entry_port.get()
    username = entry_username.get()
    password = entry_password.get()

    # Vérification que tous les champs de connexion sont remplis
    if not hostname or not port or not username or not password:
        messagebox.showerror("Erreur", "Veuillez remplir tous les champs de connexion SSH.")
        return

    # Conversion du port en entier
    try:
        port = int(port)
    except ValueError:
        messagebox.showerror("Erreur", "Le port SSH doit être un nombre.")
        return

    # Mise à jour du log pour indiquer la tentative de connexion
    update_log("Tentative de connexion au serveur SSH...")
    
    # Tentative de connexion SSH avec les informations fournies
    ssh_client = ssh_connect(username, password, hostname, port)
    
    # Si la connexion est réussie, mise à jour du log et appel de la fonction d'interaction SSH
    if ssh_client:
        update_log("Connecté au serveur SSH.")
        ssh_shell_interaction(ssh_client)
    else:
        # En cas d'échec de la connexion, une erreur sera affichée par la fonction `ssh_connect`
        update_log("Échec de la connexion au serveur SSH.")

def execute_windows_security():
    global proc  # Utilisation de la variable globale proc
    update_log("Ouverture de PowerShell...")

    # Configuration de PowerShell pour utiliser UTF-8
    ps_command = [
        "powershell",
        "-NoProfile",
        "-Command",
        "$OutputEncoding = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8;"
    ]

    def read_from_powershell(proc):
        while True:
            line = proc.stdout.readline()
            if not line:
                break            
            powershell_output_queue.put(line)
        proc.stdout.close()

    def update_powershell_log():
        while not powershell_output_queue.empty():
            line = powershell_output_queue.get()
            update_log(line.rstrip())
        root.after(100, update_powershell_log)

    try:
        proc = subprocess.Popen(["powershell"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        threading.Thread(target=read_from_powershell, args=(proc,), daemon=True).start()
        root.after(100, update_powershell_log)
        entry_command.bind('<Return>', lambda event: write_to_powershell(proc, event))
    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible de démarrer PowerShell : {e}")

def write_to_powershell(proc, event):
    """Envoyer la commande à PowerShell et effacer l'entrée."""
    command = entry_command.get().rstrip() + "\n"  # Ajout d'une nouvelle ligne pour exécuter la commande
    if command:
        proc.stdin.write(command)
        proc.stdin.flush()
        entry_command.delete(0, tk.END)

warning_window_open = False  # Variable globale pour suivre l'état de la fenêtre d'avertissement

def secure_shellshock_advanced_warning():
    global warning_window_open

    if warning_window_open:  # Vérifier si la fenêtre est déjà ouverte
        return

    warning_window_open = True

    def on_close():
        global warning_window_open
        warning_window_open = False
        warning_window.destroy()

    warning_window = tk.Toplevel(root)
    warning_window.title("Secure Shellshock Advanced - Avertissement")
    warning_window.geometry("600x300")  # Taille de la fenêtre
    warning_window.resizable(False, False)
    warning_window.protocol("WM_DELETE_WINDOW", on_close)

    # Container pour le texte d'avertissement
    text_frame = tk.Frame(warning_window)
    text_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

    # Configuration du widget Text pour qu'il se fonde dans le fond de la fenêtre Toplevel
    warning_text_widget = tk.Text(text_frame, wrap=tk.WORD, fg="red", font=("Helvetica", 10, "bold"), borderwidth=0, highlightthickness=0, height=10)
    warning_text_widget.insert(tk.END, (
        "Vous êtes sur le point d'appliquer une sécurisation avancée contre les attaques Shellshock. "
        "Cela inclura la mise à jour de Bash, la vérification et potentiellement l'activation de SELinux, "
        "et l'application d'une politique de sécurité stricte.\n\n"
        "Assurez-vous de comprendre les implications de ces actions et d'avoir effectué des sauvegardes "
        "adéquates avant de continuer."
    ))
    warning_text_widget.configure(state='disabled', bg=text_frame.cget("background"))  # Fait correspondre le fond du widget Text avec celui du Frame
    warning_text_widget.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    # Container pour les boutons
    buttons_frame = tk.Frame(warning_window)
    buttons_frame.pack(padx=10, pady=10, fill=tk.X)

    apply_button = tk.Button(warning_window, text="J'applique la sécurisation", command=lambda: [on_close(), secure_shellshock_advanced()], fg="red", font=("Helvetica", 10, "bold"))
    apply_button.pack(side=tk.LEFT, padx=10, pady=20)

    stop_button = tk.Button(warning_window, text="Je stop la sécurisation", command=on_close, fg="blue", font=("Helvetica", 10, "bold"))
    stop_button.pack(side=tk.RIGHT, padx=10, pady=20)

def on_warning_window_close(window):
    global warning_window_open
    warning_window_open = False  # Marquer la fenêtre comme fermée
    window.destroy()

def secure_shellshock_advanced():
    """Utilise threading pour appliquer une sécurisation avancée contre les attaques Shellshock sans bloquer l'interface utilisateur."""
    if not global_ssh_client:
        messagebox.showerror("Erreur", "Veuillez d'abord établir une connexion SSH.")
        return

    def task():
        try:
            # Mise à jour de Bash et du système, vérification et activation de SELinux
            commands = [
                'sudo apt-get update',
                'sudo apt-get upgrade bash -y',
                'sestatus',
                'sudo apt-get install selinux-basics selinux-policy-default auditd -y',
                'sudo selinux-activate',
                'sudo selinux-config-enforcing',
            ]

            for command in commands:
                stdin, stdout, stderr = global_ssh_client.exec_command(command)
                stdout.channel.recv_exit_status()  # Attend la fin de l'exécution
                response = stdout.read().decode() + stderr.read().decode()
                update_log(f"Exécution : {command}\n{response}")

            messagebox.showinfo("Sécurisation réussie", "Le serveur a été sécurisé contre les attaques Shellshock, et SELinux a été configuré.")
        except Exception as e:
            messagebox.showerror("Erreur lors de la sécurisation", f"Une erreur est survenue lors de la sécurisation contre Shellshock et de la configuration de SELinux : {e}")

    threading.Thread(target=task).start()

def secure_shellshock():
    """Utilise threading pour sécuriser le serveur contre les attaques Shellshock sans bloquer l'interface utilisateur."""
    if not global_ssh_client:
        messagebox.showerror("Erreur", "Veuillez d'abord établir une connexion SSH.")
        return

    def task():
        try:
            commands = [
                'sudo apt-get update',
                'sudo apt-get upgrade bash -y',
            ]

            for command in commands:
                stdin, stdout, stderr = global_ssh_client.exec_command(command)
                stdout.channel.recv_exit_status()  # Attend la fin de l'exécution
                response = stdout.read().decode()
                update_log(f"Exécution : {command}\n{response}")

            messagebox.showinfo("Sécurisation réussie", "Le serveur a été sécurisé contre les attaques Shellshock.")
        except Exception as e:
            messagebox.showerror("Erreur lors de la sécurisation", f"Une erreur est survenue lors de la sécurisation contre Shellshock : {e}")

    threading.Thread(target=task).start()

# Création de la fenêtre principale
root = tk.Tk()
root.title("CerbèreCyberScan V1.0 - AVHIRAL Copyright 2024 ® FREEWARE")
root.iconbitmap('logo.ico')

root.geometry("1100x400")
root.resizable(False, False)

# Configuration du layout de la fenêtre principale
root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=1)
root.columnconfigure(2, weight=2)
root.rowconfigure(1, weight=1)

# Création de la barre de menu
menu_bar = tk.Menu(root)  
root.config(menu=menu_bar)  

# Ajout du menu Linux
linux_menu = tk.Menu(menu_bar, tearoff=0)
linux_menu.add_command(label="Sécuriser contre Shellshock", command=secure_shellshock)
linux_menu.add_command(label="Secure Shellshock Advanced", command=secure_shellshock_advanced_warning)
menu_bar.add_cascade(label="Linux", menu=linux_menu)

# Ajout du menu Windows et de l'option de réparation
windows_menu = tk.Menu(menu_bar, tearoff=0)
windows_menu.add_command(label="Réparation Windows", command=launch_reparation)
windows_menu.add_command(label="Optimisation Windows", command=optimiser_windows)
menu_bar.add_cascade(label="Windows", menu=windows_menu)
root.config(menu=menu_bar)

# Ajout du menu À propos
menu_bar.add_command(label="À propos", command=show_about)

# Ajout du menu Don PAYPAL
menu_bar.add_command(label="DON PAYPAL", command=open_paypal_link)

# Ajout du menu Quitter
menu_bar.add_command(label="Quitter", command=root.destroy) 

# Panneau de sécurisation Linux
linux_frame = ttk.Frame(root, padding="3 3 12 12")
linux_frame.grid(column=0, row=1, sticky=(tk.N, tk.W, tk.E, tk.S))
linux_frame.columnconfigure(0, weight=1)
linux_frame.rowconfigure(1, weight=1)

# Exemple de widget pour Linux
linux_button = ttk.Button(linux_frame, text="CONNEXION SSH LINUX", command=execute_linux_security)
linux_button.grid(column=0, row=1, sticky=(tk.W, tk.E))

# Ajout du bouton "Block BOT Malveillant"
block_bot_button = ttk.Button(linux_frame, text="Block BOT Malveillant", command=block_malicious_bots)
block_bot_button.grid(column=0, row=10, sticky=(tk.W, tk.E))

# Ajout du bouton "Audit Serveur" sous le bouton "Block BOT Malveillant"
audit_server_button = ttk.Button(linux_frame, text="Audit Serveur", command=audit_server)
audit_server_button.grid(column=0, row=11, sticky=(tk.W, tk.E))  # Notez le changement de 'row=11'

# Ajout des champs de saisie pour la connexion SSH dans le panneau de sécurisation Linux
label_hostname = ttk.Label(linux_frame, text="Hostname:")
label_hostname.grid(column=0, row=2, sticky=tk.W)

entry_hostname = ttk.Entry(linux_frame)
entry_hostname.grid(column=0, row=3, sticky=(tk.W, tk.E))

label_port = ttk.Label(linux_frame, text="Port SSH:")
label_port.grid(column=0, row=4, sticky=tk.W)

entry_port = ttk.Entry(linux_frame)
entry_port.grid(column=0, row=5, sticky=(tk.W, tk.E))

label_username = ttk.Label(linux_frame, text="Nom d'utilisateur SSH:")
label_username.grid(column=0, row=6, sticky=tk.W)

entry_username = ttk.Entry(linux_frame)
entry_username.grid(column=0, row=7, sticky=(tk.W, tk.E))

label_password = ttk.Label(linux_frame, text="Mot de passe SSH:")
label_password.grid(column=0, row=8, sticky=tk.W)

entry_password = ttk.Entry(linux_frame, show="*")
entry_password.grid(column=0, row=9, sticky=(tk.W, tk.E))

# Panneau de sécurisation Windows
windows_frame = ttk.Frame(root, padding="3 3 12 12")
windows_frame.grid(column=1, row=1, sticky=(tk.N, tk.W, tk.E, tk.S))
windows_frame.columnconfigure(0, weight=1)
windows_frame.rowconfigure(1, weight=1)

# Ajout du bouton "Anti-DDOS-Win" juste au-dessus du bouton "Audit Windows"
def add_anti_ddos_button():
    anti_ddos_btn = ttk.Button(windows_frame, text="Anti-DDOS-Win", command=load_and_execute_ps_script)
    # Position ajustée pour être au-dessus du bouton "Audit Windows"
    anti_ddos_btn.grid(column=0, row=1, sticky=(tk.W, tk.E), padx=5, pady=5)

def add_secure_boot_button():
    secure_boot_btn = ttk.Button(windows_frame, text="Secure-Boot-Win", command=load_and_execute_boot_script)
    # Position ajustée pour être sous le bouton "Anti-DDOS-Win"
    secure_boot_btn.grid(column=0, row=0, sticky=(tk.W, tk.E), padx=5, pady=5)

# Exemple de widget pour Windows
windows_button = ttk.Button(windows_frame, text="CONNEXION POWERSHELL WINDOWS", command=execute_windows_security)
windows_button.grid(column=0, row=2, sticky=(tk.W, tk.E))

# Bouton pour démarrer l'audit Windows
windows_audit_button = ttk.Button(windows_frame, text="Audit Windows", command=audit_windows)
# Position ajustée pour permettre l'insertion du bouton "Anti-DDOS-Win" au-dessus
windows_audit_button.grid(column=0, row=3, sticky=(tk.W, tk.E))

# Appel de la fonction pour ajouter le bouton "Anti-DDOS-Win" & "Secure-boot-win"
add_secure_boot_button()
add_anti_ddos_button()

# Panneau de logs et Scrollbar - Initialisation de log_text avant de créer la Scrollbar
log_frame = ttk.Frame(root, padding="3 3 12 12", relief=tk.SUNKEN)
log_frame.grid(column=2, row=0, rowspan=2, sticky=(tk.N, tk.W, tk.E, tk.S))
log_frame.columnconfigure(0, weight=1)
log_frame.rowconfigure(0, weight=1)

log_text = tk.Text(log_frame, bg="black", fg="white", insertbackground='red',
                   insertofftime=300, insertontime=300)
log_text.grid(column=0, row=0, sticky=(tk.N, tk.W, tk.E, tk.S))

log_scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=log_text.yview)
log_text.config(yscrollcommand=log_scrollbar.set)
log_scrollbar.grid(column=1, row=0, sticky=(tk.N, tk.S))

# Ajouter une zone d'entrée de commande pour l'utilisateur
entry_command = tk.Entry(root, insertbackground='red', insertofftime=300, insertontime=300)
entry_command.focus()

# Charger l'image avec PhotoImage après la création de la fenêtre principale
logo_path = "logo.png" 
logo_image = PhotoImage(file=logo_path)

# Créez un Label pour afficher le logo et le placer dans la grille au-dessus des boutons
logo_label = Label(root, image=logo_image)
logo_label.grid(column=0, row=0, columnspan=2, sticky=(tk.W, tk.E))

# Ajouter un bouton "Clear" dans le panneau de logs
clear_log_button = ttk.Button(log_frame, text="Clear", command=clear_log)
clear_log_button.grid(column=0, row=1, sticky=(tk.W, tk.E))

# Ajustement de la configuration du panneau de log pour permettre l'ajout du bouton
log_frame.rowconfigure(1, weight=0)  # S'assurer que le bouton ne prend pas trop d'espace vertical

# Réajuster la configuration de log_text pour s'assurer qu'il remplit toujours l'espace disponible
log_text.grid(column=0, row=0, sticky=(tk.N, tk.W, tk.E, tk.S), padx=5, pady=5)

# Gardez une référence de l'image pour éviter la collecte de déchets
root.logo_image = logo_image

# Démarrer le traitement de la file d'attente
process_queue()

# Variable pour suivre le mode actuel (SSH ou PowerShell)
current_mode = 'PowerShell'  # Valeur initiale; ajustez selon votre configuration par défaut

def send_command_based_on_context(event):
    global global_ssh_client, current_mode  # Référence aux variables globales
    current_line_index = log_text.index("insert linestart")
    line_text = log_text.get(current_line_index, current_line_index + " lineend").strip()

    if line_text:
        if current_mode == 'SSH' and global_ssh_client:  # Si en mode SSH et une connexion SSH est établie
            send_command(line_text)
        elif current_mode == 'PowerShell':  # Si en mode PowerShell
            global proc
            proc.stdin.write(line_text + "\n")
            proc.stdin.flush()

        # Supprimer la ligne de commande après l'envoi
        log_text.delete(current_line_index, current_line_index + " lineend")

def send_ssh_command_directly(event):
    global channel
    current_line_index = log_text.index("insert linestart")
    line_text = log_text.get(current_line_index, current_line_index + " lineend").strip()

    # Supprimez tout préfixe de la commande, par exemple "root@hostname:~# "
    command = line_text.split('#')[-1].strip()  # Ceci est juste un exemple, ajustez en fonction de votre cas

    if command and channel:
        print("Envoi SSH direct : ", command)  # Débogage
        channel.send(command + '\n')
        log_text.delete(current_line_index, current_line_index + " lineend")
    else:
        print("Échec de l'envoi SSH : canal non disponible ou commande vide")

def on_return_key_pressed(event):
    global current_mode
    print("Mode actuel : ", current_mode)  # Débogage : vérifiez le mode actuel
    if current_mode == 'SSH':
        send_ssh_command_directly(event)
    else:
        send_command_based_on_context(event)

log_text.bind('<Return>', on_return_key_pressed)

# Lancement de l'interface graphique
root.mainloop()