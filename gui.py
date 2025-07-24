import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import threading
import os
import sys
import importlib.util
import shutil

MAIN_SCRIPT_NAME = "Pasted_Text_1753306735605.txt"
if not os.path.isfile(MAIN_SCRIPT_NAME):
    MAIN_SCRIPT_NAME = "main.py"
    if not os.path.isfile(MAIN_SCRIPT_NAME):
        print(f"Error: No se encuentra el script principal '{MAIN_SCRIPT_NAME}'.")
        print("Por favor, asegúrate de que este archivo GUI esté en el mismo directorio")
        print("y que el nombre del archivo del toolkit sea correcto.")
        input("Presiona Enter para salir...")
        sys.exit(1)

spec = importlib.util.spec_from_file_location("main_toolkit", MAIN_SCRIPT_NAME)
main_toolkit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(main_toolkit)

class AndroidToolkitGUI_Modern:
    def __init__(self, root):
        self.root = root
        self.root.title("📱 Android Toolkit (ADB + Fastboot) - MODERN")
        self.root.attributes('-fullscreen', True)
        self.root.attributes('-alpha', 0.93)
        self.root.configure(bg='#1e1e1e')
        self.root.bind("<Button-1>", self.start_move)
        self.root.bind("<ButtonRelease-1>", self.stop_move)
        self.root.bind("<B1-Motion>", self.on_motion)
        self.x = 0
        self.y = 0
        self.selected_device = tk.StringVar(value="Ninguno")
        self.create_widgets()
        self.check_tools()

    def start_move(self, event):
        self.x = event.x
        self.y = event.y

    def stop_move(self, event):
        self.x = None
        self.y = None

    def on_motion(self, event):
        if self.x is not None and self.y is not None:
            deltax = event.x - self.x
            deltay = event.y - self.y
            x = self.root.winfo_x() + deltax
            y = self.root.winfo_y() + deltay
            self.root.geometry(f"+{x}+{y}")

    def create_widgets(self):
        self.main_frame = tk.Frame(self.root, bg='#1e1e1e', padx=10, pady=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        title_bar = tk.Frame(self.main_frame, bg='#d32f2f', height=35)
        title_bar.pack(fill=tk.X)
        title_bar.pack_propagate(False)
        title_label = tk.Label(title_bar, text="📱 ANDROID TOOLKIT (ADB + FASTBOOT) - MODERN", bg='#d32f2f', fg='white', font=("Segoe UI", 12, "bold"))
        title_label.pack(side=tk.LEFT, padx=15)
        minimize_button = tk.Button(title_bar, text="−", bg='#d32f2f', fg='white', command=self.root.iconify, bd=0, font=("Arial", 14, "bold"), activebackground='#b71c1c')
        minimize_button.pack(side=tk.RIGHT, padx=2)
        close_button = tk.Button(title_bar, text="X", bg='#d32f2f', fg='white', command=self.root.destroy, bd=0, font=("Arial", 12, "bold"), activebackground='#b71c1c')
        close_button.pack(side=tk.RIGHT, padx=2)
        fullscreen_button = tk.Button(title_bar, text="□", bg='#d32f2f', fg='white', command=self.toggle_fullscreen, bd=0, font=("Arial", 10, "bold"), activebackground='#b71c1c')
        fullscreen_button.pack(side=tk.RIGHT, padx=2)
        header_frame = tk.Frame(self.main_frame, bg='#1e1e1e')
        header_frame.pack(fill=tk.X, pady=(10, 5))
        tk.Label(header_frame, text="DISPOSITIVO SELECCIONADO:", bg='#1e1e1e', fg='#bbbbbb', font=("Segoe UI", 10)).pack(side=tk.LEFT)
        tk.Label(header_frame, textvariable=self.selected_device, bg='#1e1e1e', fg='#64b5f6', font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=(5, 0))
        self.content_frame = tk.Frame(self.main_frame, bg='#1e1e1e')
        self.content_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.create_button_frames()
        self.create_console_frame()
        self.content_frame.columnconfigure(0, weight=1)
        self.content_frame.columnconfigure(1, weight=3)
        self.content_frame.columnconfigure(2, weight=1)
        self.content_frame.rowconfigure(0, weight=1)
        self.create_and_arrange_buttons()
        self.root.bind('<Configure>', self.on_window_resize)

    def toggle_fullscreen(self):
        is_fullscreen = self.root.attributes('-fullscreen')
        self.root.attributes('-fullscreen', not is_fullscreen)
        if not is_fullscreen:
             self.root.geometry(f"{self.root.winfo_screenwidth()}x{self.root.winfo_screenheight()}+0+0")

    def create_button_frames(self):
        self.left_button_frame = tk.LabelFrame(
            self.content_frame,
            text="ACCIONES 1",
            bg='#252526',
            fg='#d32f2f',
            font=("Segoe UI", 9, "bold"),
            padx=10, pady=10,
            relief='flat',
            bd=1
        )
        self.left_button_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        self.right_button_frame = tk.LabelFrame(
            self.content_frame,
            text="ACCIONES 2",
            bg='#252526',
            fg='#d32f2f',
            font=("Segoe UI", 9, "bold"),
            padx=10, pady=10,
            relief='flat',
            bd=1
        )
        self.right_button_frame.grid(row=0, column=2, sticky="nsew", padx=(5, 0))
        self.left_button_inner = tk.Frame(self.left_button_frame, bg='#252526')
        self.left_button_inner.pack(fill=tk.BOTH, expand=True)
        self.right_button_inner = tk.Frame(self.right_button_frame, bg='#252526')
        self.right_button_inner.pack(fill=tk.BOTH, expand=True)

    def create_console_frame(self):
        self.center_frame = tk.LabelFrame(
            self.content_frame,
            text="SALIDA",
            bg='#252526',
            fg='#d32f2f',
            font=("Segoe UI", 9, "bold"),
            padx=10, pady=10,
            relief='flat',
            bd=1
        )
        self.center_frame.grid(row=0, column=1, sticky="nsew", padx=(0, 5))
        self.output_text = tk.Text(
            self.center_frame,
            state='disabled',
            bg='#1e1e1e', fg='#dcdcdc',
            insertbackground='#dcdcdc',
            font=("Consolas", 9),
            wrap=tk.WORD,
            padx=10, pady=10,
            relief='flat'
        )
        self.output_text.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        scrollbar_output = tk.Scrollbar(self.center_frame, orient="vertical", command=self.output_text.yview, bg='#333333', troughcolor='#2b2b2b')
        scrollbar_output.pack(side=tk.RIGHT, fill=tk.Y)
        self.output_text.configure(yscrollcommand=scrollbar_output.set)
        self.progress = ttk.Progressbar(self.main_frame, mode='indeterminate', style="Red.Horizontal.TProgressbar")

    def log_output(self, message):
        self.output_text.configure(state='normal')
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.configure(state='disabled')
        self.output_text.see(tk.END)

    def run_in_thread(self, func, *args, description="", **kwargs):
        def target():
            self.progress.pack(fill=tk.X, pady=(5, 0), before=self.output_text.master.master)
            self.progress.start()
            self.log_output(f"[🔄] Iniciando: {description}")
            try:
                result = func(*args, **kwargs)
                if result is not None and isinstance(result, str):
                     self.log_output(result)
                self.log_output(f"[✅] Finalizado: {description}")
            except Exception as e:
                self.log_output(f"[❌] Error en {description}: {str(e)}")
            finally:
                self.progress.stop()
                self.progress.pack_forget()
                if hasattr(main_toolkit, 'selected_device'):
                    self.selected_device.set(getattr(main_toolkit, 'selected_device', None) or "Ninguno")
        thread = threading.Thread(target=target)
        thread.daemon = True
        thread.start()

    def check_tools(self):
        self.log_output("[🔍] Verificando herramientas...")
        tool_paths = getattr(main_toolkit, 'TOOL_PATHS', {})
        missing_tools = []
        for tool_key, expected_path in tool_paths.items():
             if os.path.exists(expected_path):
                 continue
             if shutil.which(tool_key):
                 continue
             missing_tools.append(f"{tool_key} ({expected_path})")
        if missing_tools:
             error_msg = "Herramientas faltantes:\n" + "\n".join(missing_tools)
             self.log_output(f"[⚠️] {error_msg}")
        else:
             self.log_output("[✅] Herramientas básicas verificadas.")

    def get_input_simple(self, prompt, title="Entrada"):
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("500x160")
        dialog.configure(bg='#2d2d30')
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        dialog.attributes('-alpha', 0.95)
        tk.Label(dialog, text=prompt, bg='#2d2d30', fg='white', font=("Segoe UI", 10)).pack(pady=15)
        entry_var = tk.StringVar()
        entry = tk.Entry(dialog, textvariable=entry_var, width=60, bg='#3c3c3c', fg='white', insertbackground='white', font=("Segoe UI", 10), relief='flat', highlightthickness=1, highlightbackground='#555555')
        entry.pack(pady=5, ipady=3)
        entry.focus()
        result = [None]
        def on_ok():
            result[0] = entry_var.get().strip()
            dialog.destroy()
        ok_button = tk.Button(dialog, text="OK", command=on_ok, bg='#d32f2f', fg='white', font=("Segoe UI", 9), relief='flat', padx=20, pady=5, cursor="hand2")
        ok_button.pack(pady=15)
        ok_button.bind("<Enter>", lambda e: ok_button.config(bg='#b71c1c'))
        ok_button.bind("<Leave>", lambda e: ok_button.config(bg='#d32f2f'))
        dialog.bind('<Return>', lambda event: on_ok())
        dialog.wait_window()
        return result[0]

    def get_package_input(self, action_name):
        package = self.get_input_simple(f"Introduce el nombre del paquete para {action_name}:", f"{action_name} - Paquete")
        if package:
             return package
        else:
             self.log_output(f"[⚠️] Acción '{action_name}' cancelada.")
             return None

    def get_file_path_input(self, title, filetypes=[("All files", "*.*")]):
        file_path = filedialog.askopenfilename(title=title, filetypes=filetypes)
        if file_path:
            return file_path
        else:
            self.log_output(f"[⚠️] Selección de archivo para '{title}' cancelada.")
            return None

    def get_folder_path_input(self, title):
        folder_path = filedialog.askdirectory(title=title)
        if folder_path:
            return folder_path
        else:
            self.log_output(f"[⚠️] Selección de carpeta para '{title}' cancelada.")
            return None

    def confirm_action(self, message):
        return messagebox.askyesno("Confirmar", message, parent=self.root)

    def list_and_select_device(self):
        devices = main_toolkit.list_devices()
        if not devices:
            self.log_output("[⚠️] No se encontraron dispositivos conectados.")
            self.selected_device.set("Ninguno")
            return True
        dialog = tk.Toplevel(self.root)
        dialog.title("Seleccionar Dispositivo")
        dialog.geometry("550x400")
        dialog.configure(bg='#2d2d30')
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.attributes('-alpha', 0.95)
        tk.Label(dialog, text="Dispositivos disponibles:", bg='#2d2d30', fg='white', font=("Segoe UI", 10)).pack(pady=15)
        list_frame = tk.Frame(dialog, bg='#2d2d30')
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        listbox = tk.Listbox(list_frame, bg='#3c3c3c', fg='white', selectbackground='#d32f2f', font=("Segoe UI", 9), relief='flat', highlightthickness=0)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=listbox.yview, bg='#333333', troughcolor='#2b2b2b')
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        listbox.configure(yscrollcommand=scrollbar.set)
        for _, dev_id, arch in devices:
            listbox.insert(tk.END, f"{dev_id} [{arch}]")
        result = [None]
        def on_select():
            selection = listbox.curselection()
            if selection:
                idx = selection[0]
                main_toolkit.selected_device = devices[idx][1]
                self.selected_device.set(main_toolkit.selected_device)
                self.log_output(f"[✅] Dispositivo seleccionado: {main_toolkit.selected_device}")
                result[0] = True
            else:
                self.log_output("[⚠️] No se seleccionó ningún dispositivo.")
            dialog.destroy()
        button_frame = tk.Frame(dialog, bg='#2d2d30')
        button_frame.pack(pady=15)
        select_btn = tk.Button(button_frame, text="Seleccionar", command=on_select, bg='#d32f2f', fg='white', font=("Segoe UI", 9), relief='flat', padx=15, pady=5, cursor="hand2")
        select_btn.pack(side=tk.LEFT, padx=10)
        select_btn.bind("<Enter>", lambda e: select_btn.config(bg='#b71c1c'))
        select_btn.bind("<Leave>", lambda e: select_btn.config(bg='#d32f2f'))
        cancel_btn = tk.Button(button_frame, text="Cancelar", command=dialog.destroy, bg='#555555', fg='white', font=("Segoe UI", 9), relief='flat', padx=15, pady=5, cursor="hand2")
        cancel_btn.pack(side=tk.LEFT, padx=10)
        cancel_btn.bind("<Enter>", lambda e: cancel_btn.config(bg='#444444'))
        cancel_btn.bind("<Leave>", lambda e: cancel_btn.config(bg='#555555'))
        dialog.wait_window()
        return result[0]

    def create_modern_button(self, parent, text, command, bg_color='#d32f2f', hover_color='#b71c1c'):
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg_color,
            fg='white',
            font=("Segoe UI", 9),
            anchor='w',
            padx=15,
            pady=8,
            relief='flat',
            cursor="hand2",
            bd=0,
            highlightthickness=0
        )
        btn.bind("<Enter>", lambda e: btn.config(bg=hover_color))
        btn.bind("<Leave>", lambda e: btn.config(bg=bg_color))
        return btn

    def create_and_arrange_buttons(self):
        all_actions = [
            ("🔹 Listar y Seleccionar Dispositivo", self.list_and_select_device),
            ("🔹 Reiniciar en Recovery", lambda: self.run_in_thread(lambda: main_toolkit.reboot_device("recovery"), description="Reiniciar en Recovery")),
            ("🔹 Reiniciar en Fastboot", lambda: self.run_in_thread(lambda: main_toolkit.reboot_device("bootloader"), description="Reiniciar en Fastboot")),
            ("🔹 Desconectar WiFi", lambda: self.run_in_thread(main_toolkit.disconnect_wifi, description="Desconectar WiFi")),
            ("📦 Listar Aplicaciones", lambda: self.run_in_thread(main_toolkit.list_apps, description="Listar Aplicaciones")),
            ("📦 Ver Ruta de APK", lambda: self.run_in_thread(lambda p: main_toolkit.get_apk_path(p), self.get_package_input("Ver Ruta de APK"), description="Ver Ruta de APK")),
            ("📦 Extraer APK", lambda: self.run_in_thread(lambda p: main_toolkit.pull_apk(p), self.get_package_input("Extraer APK"), description="Extraer APK")),
            ("📦 Desinstalar App", lambda: self.run_in_thread(lambda p: main_toolkit.uninstall_app(p), self.get_package_input("Desinstalar App"), description="Desinstalar App")),
            ("📦 Limpiar Datos App", lambda: self.run_in_thread(lambda p: main_toolkit.clear_app_data(p), self.get_package_input("Limpiar Datos App"), description="Limpiar Datos App")),
            ("📦 Forzar Detención App", lambda: self.run_in_thread(lambda p: main_toolkit.force_stop_app(p), self.get_package_input("Forzar Detención App"), description="Forzar Detención App")),
            ("📦 Lanzar App", lambda: self.run_in_thread(lambda p: main_toolkit.launch_app(p), self.get_package_input("Lanzar App"), description="Lanzar App")),
            ("📦 Info Detallada App", lambda: self.run_in_thread(lambda p: main_toolkit.get_app_info(p), self.get_package_input("Info Detallada App"), description="Info Detallada App")),
            ("📦 ¿Permite Backup?", lambda: self.run_in_thread(lambda p: main_toolkit.check_backup_enabled(p), self.get_package_input("¿Permite Backup?"), description="¿Permite Backup?")),
            ("🧱 Firmar APK", lambda: self.run_in_thread(lambda f: main_toolkit.sign_apk(f), self.get_file_path_input("Seleccionar APK para Firmar", [("APK files", "*.apk")]), description="Firmar APK")),
            ("🧱 Decompilar APK", lambda: self.run_in_thread(lambda f: main_toolkit.decompile_apk(f), self.get_file_path_input("Seleccionar APK para Decompilar", [("APK files", "*.apk")]), description="Decompilar APK")),
            ("🧱 Recompilar Carpeta", lambda: self.run_in_thread(lambda f: main_toolkit.recompile_apk(f), self.get_folder_path_input("Seleccionar Carpeta para Recompilar"), description="Recompilar Carpeta")),
            ("🧱 Instalar APK", lambda: self.run_in_thread(lambda f: main_toolkit.install_apk(f), self.get_file_path_input("Seleccionar APK para Instalar", [("APK files", "*.apk")]), description="Instalar APK")),
            ("🛡️ Verificar Root", lambda: self.run_in_thread(main_toolkit.check_root, description="Verificar Root")),
            ("🛡️ Deshabilitar SELinux", lambda: self.run_in_thread(main_toolkit.disable_selinux, description="Deshabilitar SELinux")),
            ("🛡️ Volcar Memoria RAM", lambda: self.run_in_thread(lambda p: main_toolkit.dump_ram(p), self.get_input_simple("Ruta destino en dispositivo (ej: /sdcard/ram.bin):", "Volcar RAM") or "/sdcard/ramdump.bin", description="Volcar Memoria RAM")),
            ("🔧 Mostrar Estado de Batería", lambda: self.run_in_thread(main_toolkit.check_battery, description="Mostrar Estado de Batería")),
            ("🔧 Logcat Completo", lambda: self.run_in_thread(main_toolkit.show_logcat, description="Logcat Completo")),
            ("🔧 Logcat con Filtro", lambda: self.run_in_thread(main_toolkit.filtered_logcat, description="Logcat con Filtro")),
            ("🔧 Acceder a Shell", lambda: self.run_in_thread(main_toolkit.start_shell, description="Acceder a Shell")),
            ("🔧 Deshabilitar Verificación de Apps", lambda: self.run_in_thread(main_toolkit.disable_verify_apps, description="Deshabilitar Verificación de Apps")),
            ("⚙️ Listar Dispositivos Fastboot", lambda: self.run_in_thread(main_toolkit.list_fastboot_devices, description="Listar Dispositivos Fastboot")),
            ("⚙️ Obtener Info del Dispositivo", lambda: self.run_in_thread(main_toolkit.get_fastboot_info, description="Obtener Info del Dispositivo")),
            ("⚙️ Desbloquear Bootloader", lambda: self.run_in_thread(lambda: main_toolkit.unlock_bootloader() if self.confirm_action("¿Desbloquear Bootloader? Esta acción borrará todos los datos.") else None, description="Desbloquear Bootloader")),
            ("⚙️ Bloquear Bootloader", lambda: self.run_in_thread(lambda: main_toolkit.lock_bootloader() if self.confirm_action("¿Bloquear Bootloader?") else None, description="Bloquear Bootloader")),
            ("⚙️ Borrar partición userdata", lambda: self.run_in_thread(lambda: main_toolkit.erase_userdata() if self.confirm_action("¿Borrar partición userdata? Esta acción borrará todos los datos del usuario.") else None, description="Borrar partición userdata")),
            ("⚙️ Flashear recovery", lambda: self.run_in_thread(lambda i: main_toolkit.flash_recovery(i), self.get_file_path_input("Seleccionar Imagen de Recovery", [("IMG files", "*.img"), ("All files", "*.*")]), description="Flashear recovery")),
            ("⚙️ Entrar en modo EDL", lambda: self.run_in_thread(main_toolkit.enter_edl_mode, description="Entrar en modo EDL")),
            ("⚙️ Reiniciar desde Fastboot", lambda: self.run_in_thread(main_toolkit.reboot_fastboot, description="Reiniciar desde Fastboot")),
            ("📷 Escuchar uso de cámara (logcat)", lambda: self.run_in_thread(main_toolkit.monitor_camera_logcat, description="Escuchar uso de cámara")),
            ("📷 Inyectar hook Frida en app activa", lambda: self.run_in_thread(main_toolkit.inject_frida_hook, description="Inyectar hook Frida en app activa")),
            ("🔎 Extraer y buscar URLs en APK", lambda: self.run_in_thread(main_toolkit.analyze_apk_for_urls, description="Extraer y buscar URLs en APK")),
            ("🔎 Analizar componentes del APK (Inspector)", lambda: self.run_in_thread(main_toolkit.analyze_apk_components, description="Analizar componentes del APK (Inspector)")),
        ]
        mid_point = len(all_actions) // 2
        left_actions = all_actions[:mid_point]
        right_actions = all_actions[mid_point:]
        self.populate_button_frame(self.left_button_inner, left_actions)
        self.populate_button_frame(self.right_button_inner, right_actions)
        self.root.after(100, self.resize_buttons)

    def populate_button_frame(self, frame, actions):
        for text, command in actions:
            btn = self.create_modern_button(frame, text, command)
            btn.pack(fill=tk.X, pady=3, ipadx=5)

    def on_window_resize(self, event):
        if event.widget == self.root:
            self.root.after_idle(self.resize_buttons)

    def resize_buttons(self):
        try:
            left_width = self.left_button_frame.winfo_width() - 30
            right_width = self.right_button_frame.winfo_width() - 30
            for widget in self.left_button_inner.winfo_children():
                if isinstance(widget, tk.Button):
                    widget.config(width=left_width // 8)
            for widget in self.right_button_inner.winfo_children():
                if isinstance(widget, tk.Button):
                    widget.config(width=right_width // 8)
        except tk.TclError:
            pass

if __name__ == "__main__":
    try:
        root = tk.Tk()
        style = ttk.Style()
        style.theme_use('default')
        style.configure("Red.Horizontal.TProgressbar", troughcolor='#2b2b2b', background='#d32f2f', thickness=12)
        app = AndroidToolkitGUI_Modern(root)
        root.mainloop()
    except Exception as e:
        messagebox.showerror("Error de Inicio", f"No se pudo iniciar la GUI: {e}")
        print(f"Error detallado: {e}")
