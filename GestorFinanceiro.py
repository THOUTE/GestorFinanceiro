import tkinter as tk
from tkinter import ttk, messagebox, colorchooser, filedialog
import sqlite3
from datetime import datetime
from tkcalendar import DateEntry
import hashlib
import os
from dateutil.relativedelta import relativedelta
import json

DB_FILE = 'financeiro.db'
SETTINGS_FILE = 'settings.json'

class FilterPopup(tk.Toplevel):
    """Uma janela pop-up para seleção de filtros de coluna, similar ao Google Sheets."""
    def __init__(self, parent, column_name, all_values, checked_values, callback):
        super().__init__(parent)
        self.transient(parent)
        self.grab_set()
        self.title(f"Filtrar por {column_name}")
        self.resizable(False, False)

        self.column_name = column_name
        self.callback = callback
        # Tenta ordenar numericamente se possível (para Valores), senão alfabeticamente
        try:
             self.all_values = sorted(list(all_values), key=lambda x: float(str(x).replace(",", ".")))
        except (ValueError, TypeError):
            self.all_values = sorted(list(str(v) for v in all_values))
            
        self.checked_values = checked_values
        self.vars = {}

        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill="both", expand=True)

        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill='x', pady=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.filter_list)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(fill='x', expand=True)

        controls_frame = ttk.Frame(main_frame)
        controls_frame.pack(fill='x', pady=5)
        ttk.Button(controls_frame, text="Selecionar Tudo", command=self.select_all).pack(side="left")
        ttk.Button(controls_frame, text="Limpar", command=self.clear_all).pack(side="left", padx=5)
        ttk.Button(controls_frame, text="A-Z", command=self.sort_asc).pack(side="left", padx=(10, 5))
        ttk.Button(controls_frame, text="Z-A", command=self.sort_desc).pack(side="left")

        canvas = tk.Canvas(main_frame, borderwidth=0, height=250)
        self.list_frame = ttk.Frame(canvas)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.create_window((4, 4), window=self.list_frame, anchor="nw")

        self.list_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=(10, 0))
        ttk.Button(button_frame, text="OK", command=self.on_ok).pack(side="right")
        ttk.Button(button_frame, text="Cancelar", command=self.destroy).pack(side="right", padx=10)

        self.populate_list()
        search_entry.focus_set()

    def populate_list(self, filter_text=""):
        for widget in self.list_frame.winfo_children():
            widget.destroy()

        self.vars.clear()
        filter_text = filter_text.lower()
        
        for value in self.all_values:
            if filter_text in str(value).lower():
                var = tk.BooleanVar(value=(value in self.checked_values))
                self.vars[value] = var
                cb = ttk.Checkbutton(self.list_frame, text=value, variable=var)
                cb.pack(fill='x', anchor='w')

    def filter_list(self, *args):
        self.populate_list(self.search_var.get())

    def sort_asc(self):
        """Ordena a lista de valores A-Z."""
        try:
            self.all_values.sort(key=lambda x: float(str(x).replace(",", ".")), reverse=False)
        except (ValueError, TypeError):
            self.all_values.sort(key=str, reverse=False)
        self.filter_list()

    def sort_desc(self):
        """Ordena a lista de valores Z-A."""
        try:
            self.all_values.sort(key=lambda x: float(str(x).replace(",", ".")), reverse=True)
        except (ValueError, TypeError):
            self.all_values.sort(key=str, reverse=True)
        self.filter_list()

    def select_all(self):
        for var in self.vars.values():
            var.set(True)

    def clear_all(self):
        for var in self.vars.values():
            var.set(False)

    def on_ok(self):
        selected = {value for value, var in self.vars.items() if var.get()}
        self.callback(self.column_name, selected)
        self.destroy()

class SettingsManager:
    def __init__(self, filename=SETTINGS_FILE):
        self.filename = filename
        self.default_settings = {
            "colors": {
                "background": "#F0F0F0", "text": "#000000", "button_bg": "#E0E0E0",
                "entry_bg": "#FFFFFF", "header_bg": "#D0D0D0"
            }
        }

    def load_settings(self):
        try:
            with open(self.filename, 'r') as f:
                settings = json.load(f)
                for key, value in self.default_settings.items():
                    if key not in settings: settings[key] = value
                    elif isinstance(value, dict):
                        for sub_key, sub_value in value.items():
                            if sub_key not in settings[key]: settings[key][sub_key] = sub_value
                return settings
        except (FileNotFoundError, json.JSONDecodeError):
            return self.default_settings.copy()

    def save_settings(self, settings):
        with open(self.filename, 'w') as f:
            json.dump(settings, f, indent=4)

class AuthManager:
    def __init__(self, conn):
        self.conn = conn
        self.cursor = conn.cursor()
        self.criar_tabelas()

    def criar_tabelas(self):
        self.cursor.execute("CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash BLOB NOT NULL, salt BLOB NOT NULL)")
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS transacoes (
                id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, tipo TEXT NOT NULL, 
                descricao TEXT NOT NULL, valor REAL NOT NULL, categoria TEXT, data TEXT NOT NULL,
                recorrencia_id INTEGER, quitado INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES usuarios (id),
                FOREIGN KEY (recorrencia_id) REFERENCES recorrencias (id) ON DELETE SET NULL)
        """)
        # --- ALTERAÇÃO NO FOREIGN KEY: Mudar de ON DELETE CASCADE para ON DELETE SET NULL
        # Isso foi necessário para a Feature 1 (manter transações pagas)
        # No entanto, a lógica de exclusão manual na Feature 1 é mais robusta.
        # Vamos garantir que a FK permita SET NULL.
        
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS recorrencias (
                id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, descricao TEXT NOT NULL,
                valor REAL NOT NULL, tipo TEXT NOT NULL, categoria TEXT, data_inicio TEXT NOT NULL,
                ocorrencias INTEGER NOT NULL, ocorrencias_executadas INTEGER DEFAULT 0, ultima_execucao TEXT,
                meses_selecionados TEXT,
                FOREIGN KEY (user_id) REFERENCES usuarios (id))
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS recorrencia_exclusoes (
                id INTEGER PRIMARY KEY, recorrencia_id INTEGER NOT NULL, user_id INTEGER NOT NULL, data_excluida TEXT NOT NULL,
                FOREIGN KEY (recorrencia_id) REFERENCES recorrencias (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES usuarios (id))
        """)
        
        # Recriar a tabela transacoes se a FK estiver errada (apenas em desenvolvimento)
        # Em um app real, isso exigiria uma migração complexa.
        # Por simplicidade, vamos assumir que a lógica manual (UPDATE SET NULL)
        # que implementaremos na Feature 1 é suficiente.

        try: self.cursor.execute("ALTER TABLE transacoes ADD COLUMN recorrencia_id INTEGER REFERENCES recorrencias(id) ON DELETE SET NULL")
        except: pass
        try: self.cursor.execute("ALTER TABLE transacoes ADD COLUMN quitado INTEGER DEFAULT 0")
        except: pass
        try: self.cursor.execute("ALTER TABLE recorrencias ADD COLUMN data_inicio TEXT NOT NULL DEFAULT '2025-01-01'")
        except: pass
        try: self.cursor.execute("ALTER TABLE recorrencias ADD COLUMN ocorrencias INTEGER NOT NULL DEFAULT 0")
        except: pass
        try: self.cursor.execute("ALTER TABLE recorrencias ADD COLUMN ocorrencias_executadas INTEGER DEFAULT 0")
        except: pass
        try: self.cursor.execute("ALTER TABLE recorrencias ADD COLUMN meses_selecionados TEXT")
        except: pass
        self.conn.commit()

    def hash_password(self, password, salt):
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

    def criar_usuario(self, username, password):
        if self.verificar_usuario_existente(username): return False, "Nome de usuário já existe."
        salt = os.urandom(16)
        password_hash = self.hash_password(password, salt)
        self.cursor.execute("INSERT INTO usuarios (username, password_hash, salt) VALUES (?, ?, ?)", (username, password_hash, salt))
        self.conn.commit()
        return True, "Usuário criado com sucesso."

    def verificar_usuario(self, username, password):
        self.cursor.execute("SELECT password_hash, salt FROM usuarios WHERE username = ?", (username,))
        result = self.cursor.fetchone()
        if result:
            stored_hash, salt = result
            if self.hash_password(password, salt) == stored_hash:
                self.cursor.execute("SELECT id FROM usuarios WHERE username = ?", (username,))
                return True, self.cursor.fetchone()[0]
        return False, None

    def verificar_usuario_existente(self, username):
        self.cursor.execute("SELECT id FROM usuarios WHERE username = ?", (username,))
        return self.cursor.fetchone() is not None

class LoginWindow:
    def __init__(self, root, on_login_success):
        self.root, self.on_login_success = root, on_login_success
        self.root.title("Login - Gestor Financeiro")
        self.root.geometry("350x200")
        self.root.resizable(False, False) 
        self.conn = sqlite3.connect(DB_FILE)
        self.auth = AuthManager(self.conn)
        frame = ttk.Frame(self.root, padding="20"); frame.pack(expand=True, fill="both")
        ttk.Label(frame, text="Usuário:").grid(row=0, column=0, sticky="w", pady=5)
        self.user_entry = ttk.Entry(frame); self.user_entry.grid(row=0, column=1, sticky="ew")
        ttk.Label(frame, text="Senha:").grid(row=1, column=0, sticky="w", pady=5)
        self.pass_entry = ttk.Entry(frame, show="*"); self.pass_entry.grid(row=1, column=1, sticky="ew")
        self.pass_entry.bind("<Return>", self.login)
        ttk.Button(frame, text="Login", command=self.login).grid(row=2, column=1, sticky="e", pady=10)
        ttk.Button(frame, text="Registrar-se", command=self.open_register_window).grid(row=2, column=0, sticky="w", pady=10)
        frame.grid_columnconfigure(1, weight=1)

    def login(self, event=None):
        success, user_id = self.auth.verificar_usuario(self.user_entry.get(), self.pass_entry.get())
        if success: self.root.destroy(); self.on_login_success(user_id)
        else: messagebox.showerror("Falha no Login", "Usuário ou senha inválidos.")

    def open_register_window(self):
        RegisterWindow(tk.Toplevel(self.root), self.auth)

class RegisterWindow:
    def __init__(self, root, auth_manager):
        self.root, self.auth = root, auth_manager
        self.root.title("Registrar Novo Usuário"); self.root.geometry("350x250")
        self.root.resizable(False, False)
        frame = ttk.Frame(self.root, padding="20"); frame.pack(expand=True, fill="both")
        ttk.Label(frame, text="Usuário:").grid(row=0, column=0, sticky="w", pady=5)
        self.user_entry = ttk.Entry(frame); self.user_entry.grid(row=0, column=1, sticky="ew")
        ttk.Label(frame, text="Senha:").grid(row=1, column=0, sticky="w", pady=5)
        self.pass_entry = ttk.Entry(frame, show="*"); self.pass_entry.grid(row=1, column=1, sticky="ew")
        ttk.Label(frame, text="Confirmar Senha:").grid(row=2, column=0, sticky="w", pady=5)
        self.confirm_pass_entry = ttk.Entry(frame, show="*"); self.confirm_pass_entry.grid(row=2, column=1, sticky="ew")
        ttk.Button(frame, text="Registrar", command=self.register).grid(row=3, column=1, sticky="e", pady=20)
        frame.grid_columnconfigure(1, weight=1); self.user_entry.focus()

    def register(self):
        username, password, confirm = self.user_entry.get(), self.pass_entry.get(), self.confirm_pass_entry.get()
        if not username or not password: messagebox.showerror("Erro", "Usuário e senha não podem estar vazios."); return
        if password != confirm: messagebox.showerror("Erro", "As senhas não coincidem."); return
        success, message = self.auth.criar_usuario(username, password)
        if success: messagebox.showinfo("Sucesso", message); self.root.destroy()
        else: messagebox.showerror("Erro", message)

class GestorFinanceiroApp:
    def __init__(self, root, user_id):
        self.root, self.user_id = root, user_id
        self.root.title("Gestor Financeiro Pessoal")
        self.root.minsize(1000, 600)
        
        self.settings_manager = SettingsManager(); self.settings = self.settings_manager.load_settings()
        self.style = ttk.Style(); self.style.theme_use("clam")
        self.conn = sqlite3.connect(DB_FILE)
        self.active_filters = {}
        self.selected_month = tk.IntVar(value=datetime.now().month)
        
        # --- NOVO: Atributos para ordenação e drag-and-drop ---
        self.sort_column = "Data" # Padrão
        self.sort_direction = "asc"
        self._was_dragged = False
        self._click_region = None
        # --- FIM NOVO ---
        
        self.criar_menu()
        self.main_container = ttk.Frame(self.root); self.main_container.pack(fill="both", expand=True)
        self.processar_recorrencias()
        self.criar_widgets()
        self.apply_settings()
        self.popular_filtros()
        self.on_filter_change()

    def criar_menu(self):
        menu_bar = tk.Menu(self.root); self.root.config(menu=menu_bar)
        options_menu = tk.Menu(menu_bar, tearoff=0); menu_bar.add_cascade(label="Opções", menu=options_menu)
        options_menu.add_command(label="Personalizar Aparência...", command=self.open_customization_window)

    def open_customization_window(self):
        CustomizationWindow(tk.Toplevel(self.root), self.settings_manager, self.apply_settings)

    def apply_settings(self):
        self.settings = self.settings_manager.load_settings()
        colors = self.settings.get("colors", {})
        bg_color, fg_color, btn_bg, entry_bg, header_bg = (colors.get("background", "#F0F0F0"), colors.get("text", "#000000"),
                                                           colors.get("button_bg", "#E0E0E0"), colors.get("entry_bg", "#FFFFFF"),
                                                           colors.get("header_bg", "#D0D0D0"))
        self.style.configure("TFrame", background=bg_color)
        self.main_container.config(style="TFrame")
        self.style.configure(".", background=bg_color, foreground=fg_color, fieldbackground=entry_bg)
        self.style.configure("TLabel", background=bg_color, foreground=fg_color)
        self.style.configure("TLabelframe", background=bg_color, foreground=fg_color)
        self.style.configure("TLabelframe.Label", background=bg_color, foreground=fg_color)
        self.style.configure("TButton", background=btn_bg, foreground=fg_color)
        self.style.map("TButton", background=[('active', '#cccccc')])
        self.style.configure("TCombobox", selectbackground=entry_bg)
        self.style.configure("Treeview", background=entry_bg, fieldbackground=entry_bg, foreground=fg_color)
        self.style.configure("Treeview.Heading", background=header_bg, foreground=fg_color)
        self.style.map("Treeview.Heading", background=[('active', '#b0b0b0')])
        self.style.configure("Month.TButton", padding=6, relief="flat", background=btn_bg)
        self.style.map("Month.TButton", background=[('active', '#cccccc'), ('selected', '#0078D7')])
        self.style.configure("Selected.Month.TButton", background="#0078D7", foreground="white")
        self.style.configure("Virtual.Treeview", font=("Arial", 10, "italic"), foreground="#555555")
        try:
            saldo = float(self.lbl_saldo.cget("text").split("R$ ")[-1].replace(",", "."))
            self.lbl_receitas.config(foreground='green'); self.lbl_despesas.config(foreground='red')
            self.lbl_saldo.config(foreground='blue' if saldo >= 0 else 'red')
        except: pass

    # --- MÉTODO MODIFICADO (agora parte do on_tree_release) ---
    def toggle_pago_status(self, event):
        # A lógica de identificação de região foi movida para on_tree_release
        column = self.tree.identify_column(event.x)
        if column == '#1':
            item_id = self.tree.identify_row(event.y)
            if not item_id: return
            
            transacao_id = self.tree.item(item_id, 'values')[1]
            
            if transacao_id == "Virtual": 
                msg = "Esta é uma projeção futura. Deseja lançar esta transação agora e marcá-la como paga?"
                if messagebox.askyesno("Lançar Transação Futura?", msg, parent=self.root):
                    novo_id = self._realizar_transacao_virtual(item_id, novo_status_quitado=1)
                    if novo_id:
                        self.carregar_transacoes() 
                return 
                
            cursor = self.conn.cursor()
            cursor.execute("SELECT quitado FROM transacoes WHERE id = ? AND user_id = ?", (transacao_id, self.user_id))
            result = cursor.fetchone()
            if result:
                novo_status = 1 - result[0]
                cursor.execute("UPDATE transacoes SET quitado = ? WHERE id = ?", (novo_status, transacao_id))
                self.conn.commit()
                self.carregar_transacoes()
    # --- FIM DA MODIFICAÇÃO ---

    def criar_widgets(self):
        # ... (widgets de entrada e filtro permanecem os mesmos) ...
        frame_entrada = ttk.LabelFrame(self.main_container, text="Adicionar Nova Transação", padding=15); frame_entrada.pack(padx=10, pady=10, fill="x")
        ttk.Label(frame_entrada, text="Descrição:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.entry_descricao = ttk.Entry(frame_entrada, width=40); self.entry_descricao.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Label(frame_entrada, text="Valor (R$):").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.entry_valor = ttk.Entry(frame_entrada, width=15); self.entry_valor.grid(row=0, column=3, padx=5, pady=5, sticky="ew")
        ttk.Label(frame_entrada, text="Data:").grid(row=0, column=4, padx=5, pady=5, sticky="w")
        self.entry_data = DateEntry(frame_entrada, width=12, background='darkblue', foreground='white', borderwidth=2, date_pattern='dd/MM/yyyy', locale='pt_BR'); self.entry_data.grid(row=0, column=5, padx=5, pady=5, sticky="ew")
        ttk.Label(frame_entrada, text="Categoria:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.entry_categoria = ttk.Entry(frame_entrada); self.entry_categoria.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        ttk.Label(frame_entrada, text="Tipo:").grid(row=1, column=2, padx=5, pady=5, sticky="w")
        self.tipo_var = tk.StringVar(value="Despesa")
        self.combo_tipo = ttk.Combobox(frame_entrada, textvariable=self.tipo_var, values=["Receita", "Despesa"], state="readonly", width=12); self.combo_tipo.grid(row=1, column=3, padx=5, pady=5, sticky="ew")
        btn_adicionar = ttk.Button(frame_entrada, text="Adicionar", command=self.adicionar_transacao); btn_adicionar.grid(row=0, column=6, rowspan=2, padx=15, pady=5, sticky="nswe")
        frame_entrada.grid_columnconfigure(1, weight=3); frame_entrada.grid_columnconfigure(3, weight=1); frame_entrada.grid_columnconfigure(5, weight=1)
        frame_filtros = ttk.LabelFrame(self.main_container, text="Filtrar Histórico", padding=15); frame_filtros.pack(padx=10, pady=(0, 10), fill="x")
        ttk.Label(frame_filtros, text="Ano:").pack(side="left", padx=(0, 5))
        self.filtro_ano_var = tk.StringVar()
        self.filtro_ano_combo = ttk.Combobox(frame_filtros, textvariable=self.filtro_ano_var, state="readonly", width=8); self.filtro_ano_combo.pack(side="left", padx=5); self.filtro_ano_combo.bind("<<ComboboxSelected>>", lambda e: self.on_filter_change())
        ttk.Label(frame_filtros, text="Tipo:").pack(side="left", padx=(15, 5))
        self.filtro_tipo_var = tk.StringVar(value="Todos")
        self.filtro_tipo_combo = ttk.Combobox(frame_filtros, textvariable=self.filtro_tipo_var, values=["Todos", "Receita", "Despesa"], state="readonly", width=10); self.filtro_tipo_combo.pack(side="left", padx=5)
        ttk.Label(frame_filtros, text="Categoria:").pack(side="left", padx=(15, 5))
        self.filtro_categoria_var = tk.StringVar(value="Todas")
        self.filtro_categoria_combo = ttk.Combobox(frame_filtros, textvariable=self.filtro_categoria_var, state="readonly", width=20); self.filtro_categoria_combo.pack(side="left", padx=5)
        btn_recorrencias = ttk.Button(frame_filtros, text="Gerenciar Recorrências", command=self.abrir_janela_recorrencias); btn_recorrencias.pack(side="right", padx=5)
        btn_limpar = ttk.Button(frame_filtros, text="Limpar", command=self.limpar_filtros); btn_limpar.pack(side="right", padx=5)
        btn_filtrar = ttk.Button(frame_filtros, text="Filtrar", command=self.on_filter_change); btn_filtrar.pack(side="right", padx=5)
        self.filtro_pesquisa_entry = ttk.Entry(frame_filtros); self.filtro_pesquisa_entry.pack(side="right", fill="x", expand=True, padx=5)
        ttk.Label(frame_filtros, text="Pesquisar Descrição:").pack(side="right", padx=(15, 5))
        self.frame_meses = ttk.Frame(self.main_container); self.frame_meses.pack(padx=10, pady=(0, 5), fill="x")
        self.meses = ["Ano Inteiro", "Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho", "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"]
        self.month_buttons = {}
        for i, mes in enumerate(self.meses):
            btn = ttk.Radiobutton(self.frame_meses, text=mes, value=i, variable=self.selected_month, command=self.on_filter_change, style="Month.TButton"); btn.pack(side="left", fill="x", expand=True)
            self.month_buttons[i] = btn
        
        frame_historico = ttk.LabelFrame(self.main_container, text="Histórico de Transações (Clique Esq: Ordenar | Clique Dir: Filtrar)", padding=15); frame_historico.pack(padx=10, pady=10, fill="both", expand=True)
        self.tree = ttk.Treeview(frame_historico, columns=("Pago", "ID", "Data", "Tipo", "Descrição", "Valor", "Categoria", "RecID"), show="headings")
        self.colunas_map = {"Pago": 0, "ID": 1, "Data": 2, "Tipo": 3, "Descrição": 4, "Valor": 5, "Categoria": 6, "RecID": 7}
        colunas_config = {"Pago": 40, "ID": 50, "Data": 120, "Tipo": 100, "Descrição": 400, "Valor": 120, "Categoria": 180}
        
        for col, width in colunas_config.items():
            anchor = 'center' if col in ["Pago", "ID", "Data", "Tipo"] else 'w'
            # --- ALTERAÇÃO: Removido 'command' para habilitar drag-and-drop e binds ---
            self.tree.heading(col, text=col) 
            self.tree.column(col, width=width, anchor=anchor)
        # --- FIM ALTERAÇÃO ---

        self.tree.column("RecID", width=0, stretch=tk.NO); self.tree.column("Valor", anchor='e')
        scrollbar = ttk.Scrollbar(frame_historico, orient="vertical", command=self.tree.yview); self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True); scrollbar.pack(side="right", fill="y")
        self.menu_contexto = tk.Menu(self.root, tearoff=0)
        self.menu_contexto.add_command(label="Editar Transação", command=self.abrir_janela_edicao)
        self.menu_contexto.add_command(label="Duplicar Transação", command=self.duplicar_transacao)
        self.menu_contexto.add_command(label="Excluir Transação", command=self.excluir_transacao)
        
        # --- NOVOS BINDINGS (Feature 2 e 3) ---
        self.tree.bind("<ButtonPress-1>", self.on_tree_press)
        self.tree.bind("<B1-Motion>", self.on_tree_drag)
        self.tree.bind("<ButtonRelease-1>", self.on_tree_release)
        self.tree.bind("<Button-3>", self.on_tree_right_click)
        # --- FIM NOVOS BINDINGS ---
        
        frame_resumo = ttk.LabelFrame(self.main_container, text="Resumo Financeiro (Itens Pendentes)", padding=15); frame_resumo.pack(padx=10, pady=10, fill="x")
        self.lbl_receitas = ttk.Label(frame_resumo, text="Receitas: R$ 0.00", font=('Arial', 12, 'bold')); self.lbl_receitas.pack(side="left", padx=20)
        self.lbl_despesas = ttk.Label(frame_resumo, text="Despesas: R$ 0.00", font=('Arial', 12, 'bold')); self.lbl_despesas.pack(side="left", padx=20)
        self.lbl_saldo = ttk.Label(frame_resumo, text="Saldo Atual: R$ 0.00", font=('Arial', 14, 'bold')); self.lbl_saldo.pack(side="right", padx=20)

    # --- NOVOS MÉTODOS (Feature 2 e 3) ---
    def on_tree_press(self, event):
        """Armazena a região do clique para diferenciar clique de arrastar."""
        self._was_dragged = False
        self._click_region = self.tree.identify("region", event.x, event.y)

    def on_tree_drag(self, event):
        """Marca como 'arrastado' se o mouse se mover após clicar no cabeçalho."""
        if self._click_region == "heading":
            self._was_dragged = True

    def on_tree_release(self, event):
        """No soltar do mouse, decide se foi um clique (ordenar/pagar) ou um arrastar (mover coluna)."""
        if self._was_dragged:
            # Foi um drag-and-drop de coluna, o Tcl/Tk cuida disso
            self._was_dragged = False
            return
        
        # Foi um clique (sem arrastar)
        if self._click_region == "heading":
            self.handle_sort_click(event)
        elif self._click_region == "cell":
            # Passa o evento para a função de pagamento, que agora só lida com a lógica da célula
            self.toggle_pago_status(event)

    def handle_sort_click(self, event):
        """Lida com a lógica de ordenação ao clicar no cabeçalho."""
        region = self.tree.identify("region", event.x, event.y)
        if region != "heading":
             return

        col_id = self.tree.identify_column(event.x)
        # Limpa o nome da coluna de indicadores (▾▲▼)
        col_name = self.tree.heading(col_id, "text").split(" ")[0]
        
        if not col_name: return

        if self.sort_column == col_name:
            # Inverte a direção
            self.sort_direction = "desc" if self.sort_direction == "asc" else "asc"
        else:
            # Nova coluna
            self.sort_column = col_name
            self.sort_direction = "asc"
            
        self.carregar_transacoes() # Recarrega os dados com a nova ordenação

    def on_tree_right_click(self, event):
        """Lida com cliques do botão direito: Filtro no cabeçalho, Menu de Contexto na célula."""
        region = self.tree.identify("region", event.x, event.y)
        
        if region == "heading":
            # --- NOVO: Botão direito no cabeçalho abre o filtro ---
            col_id = self.tree.identify_column(event.x)
            col_name = self.tree.heading(col_id, "text").split(" ")[0] # Limpa o nome
            if col_name:
                self.open_filter_popup(col_name)
        elif region == "cell" or region == "tree":
            # --- Lógica original mantida ---
            self.mostrar_menu_contexto(event)
    # --- FIM NOVOS MÉTODOS ---

    def open_filter_popup(self, column):
        if column in ["RecID"]: return
        base_data = self._get_base_data()
        
        view_start, view_end = self._get_viewing_period()
        if view_end and view_end > datetime.now():
             base_data.extend(self._get_future_virtual_transactions(view_start, view_end))

        other_filters = {k: v for k, v in self.active_filters.items() if k != column}
        if other_filters:
            filtered_subset = [row for row in base_data if all(self._get_formatted_cell_value(row, c) in v for c, v in other_filters.items())]
        else:
            filtered_subset = base_data

        if column == "Valor":
             unique_values = {float(self._get_formatted_cell_value(row, column)) for row in filtered_subset}
        else:
            unique_values = {self._get_formatted_cell_value(row, column) for row in filtered_subset}
            
        checked_values = self.active_filters.get(column, unique_values)
        FilterPopup(self.root, column, unique_values, checked_values, self.apply_filter)

    def _get_formatted_cell_value(self, row_data, column_name):
        col_index = self.colunas_map.get(column_name)
        if col_index is None: return ""
        val = row_data[col_index]
        if column_name == 'Pago': return "☑" if val else "☐"
        if column_name == 'Data': return datetime.strptime(row_data[col_index], "%Y-%m-%d %H:%M:%S").strftime("%d/%m/%Y")
        if column_name == 'Valor': return f"{val:.2f}"
        return val

    def apply_filter(self, column, selected_values):
        base_data = self._get_base_data() 
        
        if column == "Valor":
            all_possible = {float(self._get_formatted_cell_value(row, column)) for row in base_data}
            view_start, view_end = self._get_viewing_period()
            if view_end and view_end > datetime.now():
                future_virtuals = self._get_future_virtual_transactions(view_start, view_end)
                all_possible.update({float(self._get_formatted_cell_value(v, column)) for v in future_virtuals})
        else:
            all_possible = {self._get_formatted_cell_value(row, column) for row in base_data}
            view_start, view_end = self._get_viewing_period()
            if view_end and view_end > datetime.now():
                future_virtuals = self._get_future_virtual_transactions(view_start, view_end)
                all_possible.update({self._get_formatted_cell_value(v, column) for v in future_virtuals})

        if selected_values and selected_values != all_possible: 
            self.active_filters[column] = selected_values
        elif column in self.active_filters: 
            del self.active_filters[column]
        
        self.carregar_transacoes()

    # --- MÉTODO MODIFICADO (Feature 2) ---
    def update_header_indicators(self):
        """Atualiza cabeçalhos com indicadores de filtro (▾) e ordenação (▲/▼)."""
        for col_name in self.colunas_map.keys():
            if col_name in ["RecID"]: continue
            text = col_name
            
            # 1. Indicador de Filtro
            if col_name in self.active_filters:
                text += " ▾"
                
            # 2. Indicador de Ordenação
            if hasattr(self, 'sort_column') and self.sort_column == col_name:
                text += " ▲" if self.sort_direction == 'asc' else " ▼"
                
            self.tree.heading(col_name, text=text)
    # --- FIM DA MODIFICAÇÃO ---

    def on_filter_change(self, event=None):
        self.carregar_transacoes()
        self.update_month_buttons_style()

    def update_month_buttons_style(self):
        selected = self.selected_month.get()
        for i, btn in self.month_buttons.items():
            btn.config(style="Selected.Month.TButton" if i == selected else "Month.TButton")

    def adicionar_transacao(self):
        data_obj = self.entry_data.get_date()
        data_db_format = data_obj.strftime("%Y-%m-%d %H:%M:%S")
        tipo, descricao, valor_str, categoria = self.tipo_var.get(), self.entry_descricao.get(), self.entry_valor.get().replace(",", "."), self.entry_categoria.get()
        if not descricao or not valor_str: messagebox.showerror("Erro", "Descrição e Valor são obrigatórios."); return
        try: valor = float(valor_str); assert valor > 0
        except: messagebox.showerror("Erro", "Insira um valor numérico positivo."); return
        self.conn.cursor().execute("INSERT INTO transacoes (user_id, tipo, descricao, valor, categoria, data, quitado) VALUES (?, ?, ?, ?, ?, ?, 0)", (self.user_id, tipo, descricao, valor, categoria, data_db_format))
        self.conn.commit()
        self.limpar_campos_entrada(); self.popular_filtros(); self.carregar_transacoes()

    def abrir_janela_edicao(self):
        if not self.tree.selection(): return
        
        selection = self.tree.selection()[0] 
        item_values = self.tree.item(selection, 'values')
        transacao_id = item_values[1]
        
        if transacao_id == "Virtual":
            msg = "Esta é uma projeção futura. Deseja lançar esta transação agora para poder editá-la?"
            if messagebox.askyesno("Lançar Transação Futura?", msg, parent=self.root):
                novo_id = self._realizar_transacao_virtual(selection, novo_status_quitado=0) 
                if novo_id:
                    EditTransactionWindow(tk.Toplevel(self.root), self.conn, novo_id, self.carregar_transacoes)
            return 
            
        EditTransactionWindow(tk.Toplevel(self.root), self.conn, transacao_id, self.carregar_transacoes)

    def abrir_janela_recorrencias(self):
        RecorrenciasWindow(tk.Toplevel(self.root), self.conn, self.user_id, self.atualizar_apos_recorrencia)

    def atualizar_apos_recorrencia(self):
        self.processar_recorrencias(); self.popular_filtros(); self.carregar_transacoes()

    def processar_recorrencias(self):
        cursor = self.conn.cursor()
        hoje = datetime.now()
        recorrencias = cursor.execute("SELECT * FROM recorrencias WHERE user_id = ?", (self.user_id,)).fetchall()
        
        for rec in recorrencias:
            meses_selecionados_str = rec[10] if len(rec) > 10 else None
            target_months = set(int(m) for m in meses_selecionados_str.split(',')) if meses_selecionados_str else None
            
            rec_id, _, desc, val, tipo, cat, start_str, total_runs, runs_done, _ = rec[:10]
            start_date = datetime.strptime(start_str, "%Y-%m-%d")
    
            # --- LÓGICA DE PROCESSAMENTO MODIFICADA ---
            # Seleciona apenas transações PENDENTES. As pagas não contam para
            # o processamento de "já existe".
            cursor.execute("SELECT data FROM transacoes WHERE recorrencia_id = ? AND user_id = ? AND quitado = 0", (rec_id, self.user_id))
            pending_exist_dates = {datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S').date() for row in cursor.fetchall()}
            
            # Seleciona transações PAGAS para evitar recriá-las.
            cursor.execute("SELECT data FROM transacoes WHERE recorrencia_id = ? AND user_id = ? AND quitado = 1", (rec_id, self.user_id))
            paid_exist_dates = {datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S').date() for row in cursor.fetchall()}
            
            cursor.execute("SELECT data_excluida FROM recorrencia_exclusoes WHERE recorrencia_id = ? AND user_id = ?", (rec_id, self.user_id))
            excluded_dates = {datetime.strptime(row[0], '%Y-%m-%d').date() for row in cursor.fetchall()}
            # --- FIM DA MODIFICAÇÃO ---

            dates_to_create = set()
            next_due_date = start_date
            run_count = 0
            
            while next_due_date <= hoje:
                is_target_month = (not target_months) or (next_due_date.month in target_months)

                if is_target_month:
                    if total_runs > 0 and run_count >= total_runs:
                        break
                    
                    # --- LÓGICA MODIFICADA ---
                    # Só cria se não estiver pendente, não estiver pago E não estiver excluído
                    if next_due_date.date() not in pending_exist_dates and \
                       next_due_date.date() not in paid_exist_dates and \
                       next_due_date.date() not in excluded_dates:
                        dates_to_create.add(next_due_date.date())
                    # --- FIM DA MODIFICAÇÃO ---
                    
                    run_count += 1
                
                next_due_date += relativedelta(months=1)
            
            if dates_to_create:
                for dt_obj in sorted(list(dates_to_create)):
                    data_db_format = dt_obj.strftime("%Y-%m-%d 12:00:00")
                    cursor.execute("INSERT INTO transacoes (user_id, tipo, descricao, valor, categoria, data, recorrencia_id, quitado) VALUES (?, ?, ?, ?, ?, ?, ?, 0)", 
                                   (self.user_id, tipo, f"[R] {desc}", val, cat, data_db_format, rec_id))
            
            # Atualiza o status da recorrência (contando pagas + pendentes)
            cursor.execute("SELECT COUNT(id), MAX(data) FROM transacoes WHERE recorrencia_id = ?", (rec_id,))
            count_result = cursor.fetchone()
            new_runs_done = count_result[0] if count_result[0] is not None else 0
            last_exec_date = datetime.strptime(count_result[1], '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d') if count_result[1] else None
            cursor.execute("UPDATE recorrencias SET ultima_execucao = ?, ocorrencias_executadas = ? WHERE id = ?", (last_exec_date, new_runs_done, rec_id))
        
        self.conn.commit()

    def _get_base_data(self):
        query = "SELECT quitado, id, data, tipo, descricao, valor, categoria, recorrencia_id FROM transacoes WHERE user_id = ?"
        params = [self.user_id]
        if self.filtro_ano_var.get(): query += " AND strftime('%Y', data) = ?"; params.append(self.filtro_ano_var.get())
        if self.selected_month.get() > 0: query += " AND strftime('%m', data) = ?"; params.append(f"{self.selected_month.get():02d}")
        if self.filtro_tipo_var.get() != "Todos": query += " AND tipo = ?"; params.append(self.filtro_tipo_var.get())
        if self.filtro_categoria_var.get() != "Todas": query += " AND categoria = ?"; params.append(self.filtro_categoria_var.get())
        if self.filtro_pesquisa_entry.get(): query += " AND descricao LIKE ?"; params.append(f"%{self.filtro_pesquisa_entry.get()}%")
        cursor = self.conn.cursor(); cursor.execute(query, tuple(params)); return cursor.fetchall()

    def _get_viewing_period(self):
        selected_year_str = self.filtro_ano_var.get()
        if not selected_year_str:
            return None, None
        year = int(selected_year_str)
        month = self.selected_month.get()
        if month > 0:
            view_start = datetime(year, month, 1)
            view_end = (view_start + relativedelta(months=1)) - relativedelta(days=1)
        else:
            view_start = datetime(year, 1, 1)
            view_end = datetime(year, 12, 31)
        view_end = view_end.replace(hour=23, minute=59, second=59)
        return view_start, view_end

    def _get_future_virtual_transactions(self, view_start_date, view_end_date):
        virtual_transactions = []
        hoje = datetime.now()
        cursor = self.conn.cursor()
        recorrencias = cursor.execute("SELECT * FROM recorrencias WHERE user_id = ?", (self.user_id,)).fetchall()

        for rec in recorrencias:
            meses_selecionados_str = rec[10] if len(rec) > 10 else None
            target_months = set(int(m) for m in meses_selecionados_str.split(',')) if meses_selecionados_str else None
            
            rec_id, _, desc, val, tipo, cat, start_str, total_runs, runs_done, _ = rec[:10]
            start_date = datetime.strptime(start_str, "%Y-%m-%d")

            if total_runs > 0 and runs_done is not None and runs_done >= total_runs:
                continue

            cursor.execute("SELECT data_excluida FROM recorrencia_exclusoes WHERE recorrencia_id = ? AND user_id = ?", (rec_id, self.user_id))
            excluded_dates = {datetime.strptime(row[0], '%Y-%m-%d').date() for row in cursor.fetchall()}
            
            # --- ALTERAÇÃO: Não mostrar virtual se já foi paga ou pendente ---
            cursor.execute("SELECT data FROM transacoes WHERE recorrencia_id = ? AND user_id = ?", (rec_id, self.user_id))
            already_exist_dates = {datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S').date() for row in cursor.fetchall()}

            next_due_date = start_date
            run_count = 0
            
            while next_due_date < view_start_date:
                is_target_month = (not target_months) or (next_due_date.month in target_months)
                if is_target_month:
                    if total_runs > 0 and run_count >= total_runs: break
                    run_count += 1 
                next_due_date += relativedelta(months=1)
            
            if total_runs > 0 and run_count >= total_runs: continue 
            
            while next_due_date <= view_end_date:
                is_target_month = (not target_months) or (next_due_date.month in target_months)
                
                if is_target_month:
                    if total_runs > 0 and run_count >= total_runs: break
                    
                    if next_due_date > hoje and \
                       next_due_date.date() not in excluded_dates and \
                       next_due_date.date() not in already_exist_dates:
                        
                        data_str = next_due_date.strftime("%Y-%m-%d 12:00:00")
                        virtual_row = (0, "Virtual", data_str, tipo, f"[R] {desc}", val, cat, rec_id)
                        virtual_transactions.append(virtual_row)
                    
                    run_count += 1 
                next_due_date += relativedelta(months=1) 
        return virtual_transactions

    # --- MÉTODO MODIFICADO (Feature 2) ---
    def carregar_transacoes(self):
        for i in self.tree.get_children(): self.tree.delete(i)

        all_data = self._get_base_data()
        
        view_start, view_end = self._get_viewing_period()
        if view_end and view_end > datetime.now():
            virtual_transactions = self._get_future_virtual_transactions(view_start, view_end)
            all_data.extend(virtual_transactions)

        if self.active_filters:
            display_data = []
            for row in all_data:
                match = True
                for col_name, allowed_values in self.active_filters.items():
                    if col_name == "Valor":
                        cell_value = float(self._get_formatted_cell_value(row, col_name))
                    else:
                        cell_value = self._get_formatted_cell_value(row, col_name)
                    if cell_value not in allowed_values:
                        match = False; break
                if match:
                    display_data.append(row)
        else:
            display_data = all_data

        total_receitas, total_despesas = 0.0, 0.0
        
        # --- NOVA LÓGICA DE ORDENAÇÃO ---
        if hasattr(self, 'sort_column') and self.sort_column:
            col_index = self.colunas_map.get(self.sort_column)
            if col_index is not None:
                is_reverse = (self.sort_direction == 'desc')
                
                def sort_key(row):
                    val = row[col_index]
                    # Lida com tipos de dados para ordenação correta
                    if self.sort_column == 'Valor':
                        return float(val)
                    if self.sort_column == 'Data':
                        return datetime.strptime(row[col_index], "%Y-%m-%d %H:%M:%S")
                    if self.sort_column == 'ID':
                        return 99999999 if val == 'Virtual' else int(val) # Põe Virtual no fim
                    if self.sort_column == 'Pago':
                        return int(val) # 0 ou 1
                    return str(val).lower() # Padrão string

                display_data.sort(key=sort_key, reverse=is_reverse)
            else:
                # Fallback se a coluna de ordenação não for encontrada
                display_data.sort(key=lambda row: datetime.strptime(row[2], "%Y-%m-%d %H:%M:%S"))
        else:
            # Ordenação padrão original (Data)
            display_data.sort(key=lambda row: datetime.strptime(row[2], "%Y-%m-%d %H:%M:%S"))
        # --- FIM DA LÓGICA DE ORDENAÇÃO ---

        for row in display_data:
            quitado_val, id_trans, data_str, tipo, desc, valor, cat, rec_id = row
            data_formatada = datetime.strptime(data_str, "%Y-%m-%d %H:%M:%S").strftime("%d/%m/%Y")
            tags = ['receita' if tipo == 'Receita' else 'despesa']
            if id_trans == "Virtual": tags.append('virtual')
            pago_char = "☑" if quitado_val else "☐"
            self.tree.insert("", "end", values=(pago_char, id_trans, data_formatada, tipo, desc, f"{valor:.2f}", cat, rec_id), tags=tuple(tags))
            if not quitado_val:
                if tipo == 'Receita': total_receitas += float(valor)
                else: total_despesas += float(valor)

        self.tree.tag_configure('receita', background='#D4EDDA', foreground='#155724')
        self.tree.tag_configure('despesa', background='#F8D7DA', foreground='#721C24')
        self.tree.tag_configure('virtual', font=("Arial", 10, "italic"), foreground="#555555")
        
        self.atualizar_resumo(total_receitas, total_despesas)
        self.update_header_indicators() # Atualiza indicadores de filtro/ordenação
    # --- FIM DA MODIFICAÇÃO ---

    def popular_filtros(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT DISTINCT categoria FROM transacoes WHERE user_id = ? AND categoria IS NOT NULL AND categoria != '' ORDER BY categoria", (self.user_id,))
        self.filtro_categoria_combo['values'] = ["Todas"] + [row[0] for row in cursor.fetchall()]
        anos = [row[0] for row in cursor.execute("SELECT DISTINCT strftime('%Y', data) FROM transacoes WHERE user_id = ? ORDER BY 1 DESC", (self.user_id,)).fetchall()]
        current_year = str(datetime.now().year)
        if current_year not in anos: anos.insert(0, current_year)
        self.filtro_ano_combo['values'] = anos
        if not self.filtro_ano_var.get(): self.filtro_ano_var.set(anos[0])

    def mostrar_menu_contexto(self, event):
        item_id = self.tree.identify_row(event.y)
        if item_id: self.tree.selection_set(item_id); self.menu_contexto.post(event.x_root, event.y_root)

    def excluir_transacao(self):
        if not self.tree.selection(): return
        selection = self.tree.selection()[0]
        item_values = self.tree.item(selection, 'values')
        transacao_id, data_str, descricao, valor, recorrencia_id = item_values[1], item_values[2], item_values[4], item_values[5], item_values[7]

        if transacao_id == "Virtual":
            msg = f"A transação '{descricao}' é uma projeção futura. Deseja impedir que ela seja criada no futuro?"
            if messagebox.askyesno("Excluir Projeção Futura", msg, icon='question', parent=self.root):
                try:
                    data_obj = datetime.strptime(data_str, '%d/%m/%Y')
                    data_exclusao_db = data_obj.strftime('%Y-%m-%d')
                    cursor = self.conn.cursor()
                    cursor.execute("INSERT INTO recorrencia_exclusoes (recorrencia_id, user_id, data_excluida) VALUES (?, ?, ?)",
                                   (recorrencia_id, self.user_id, data_exclusao_db))
                    self.conn.commit()
                except Exception as e:
                    messagebox.showerror("Erro", f"Ocorreu um erro ao criar a exceção: {e}")
                    self.conn.rollback()
        elif not recorrencia_id or recorrencia_id == 'None':
            if messagebox.askyesno("Confirmar Exclusão", f"Excluir '{descricao}' (R$ {valor})?"):
                self.conn.cursor().execute("DELETE FROM transacoes WHERE id = ? AND user_id = ?", (transacao_id, self.user_id))
                self.conn.commit()
        else: 
            msg = f"'{descricao}' é uma transação recorrente. Deseja excluí-la apenas para este mês?"
            if messagebox.askyesno("Excluir Ocorrência", msg, icon='question'):
                try:
                    data_obj = datetime.strptime(data_str, '%d/%m/%Y')
                    data_exclusao_db = data_obj.strftime('%Y-%m-%d')
                    cursor = self.conn.cursor()
                    cursor.execute("INSERT INTO recorrencia_exclusoes (recorrencia_id, user_id, data_excluida) VALUES (?, ?, ?)",
                                   (recorrencia_id, self.user_id, data_exclusao_db))
                    cursor.execute("DELETE FROM transacoes WHERE id = ? AND user_id = ?", (transacao_id, self.user_id))
                    self.conn.commit()
                except Exception as e:
                    messagebox.showerror("Erro", f"Ocorreu um erro ao criar a exceção: {e}")
                    self.conn.rollback()

        self.carregar_transacoes(); self.popular_filtros()

    def duplicar_transacao(self):
        if not self.tree.selection(): return
        selection = self.tree.selection()[0]
        item_values = self.tree.item(selection, 'values')
        data_str_original, tipo, desc_orig, valor_str, categoria = item_values[2], item_values[3], item_values[4], item_values[5], item_values[6]
        nova_descricao = f"[Cópia] {desc_orig.replace('[R] ', '')}"
        try:
            valor = float(valor_str)
            data_original_obj = datetime.strptime(data_str_original, '%d/%m/%Y')
            nova_data_db = data_original_obj.strftime("%Y-%m-%d 12:00:00")
        except (ValueError, TypeError): messagebox.showerror("Erro", "Não foi possível duplicar a transação."); return
        self.conn.cursor().execute("INSERT INTO transacoes (user_id, tipo, descricao, valor, categoria, data, quitado) VALUES (?, ?, ?, ?, ?, ?, 0)", (self.user_id, tipo, nova_descricao, valor, categoria, nova_data_db))
        self.conn.commit()
        self.carregar_transacoes(); self.popular_filtros()
        messagebox.showinfo("Sucesso", "Transação duplicada com sucesso.")

    def limpar_filtros(self):
        self.filtro_tipo_var.set("Todos"); self.filtro_categoria_var.set("Todas")
        self.filtro_pesquisa_entry.delete(0, tk.END); self.selected_month.set(datetime.now().month)
        self.filtro_ano_var.set(str(datetime.now().year)); self.active_filters.clear()
        # --- NOVO: Resetar ordenação ---
        self.sort_column = "Data"
        self.sort_direction = "asc"
        # --- FIM NOVO ---
        self.on_filter_change()

    def atualizar_resumo(self, total_receitas, total_despesas):
        saldo = total_receitas - total_despesas
        self.lbl_receitas.config(text=f"Receitas: R$ {total_receitas:.2f}")
        self.lbl_despesas.config(text=f"Despesas: R$ {total_despesas:.2f}")
        self.lbl_saldo.config(text=f"Saldo: R$ {saldo:.2f}", foreground='blue' if saldo >= 0 else 'red')

    def limpar_campos_entrada(self):
        self.entry_descricao.delete(0, tk.END); self.entry_valor.delete(0, tk.END)
        self.entry_categoria.delete(0, tk.END); self.combo_tipo.set("Despesa")
        self.entry_data.set_date(datetime.now())

    def _realizar_transacao_virtual(self, item_id, novo_status_quitado=0):
        """Converte uma transação virtual da Treeview em um registro real no DB."""
        item_values = self.tree.item(item_id, 'values')
        try:
            data_str_original = item_values[2]; tipo = item_values[3]
            desc_orig = item_values[4]; valor_str = item_values[5]
            categoria = item_values[6]; recorrencia_id = item_values[7]
            valor = float(valor_str)
            data_obj = datetime.strptime(data_str_original, '%d/%m/%Y')
            data_db = data_obj.strftime("%Y-%m-%d 12:00:00") 
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO transacoes (user_id, tipo, descricao, valor, categoria, data, quitado, recorrencia_id) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (self.user_id, tipo, desc_orig, valor, categoria, data_db, novo_status_quitado, recorrencia_id))
            novo_id = cursor.lastrowid
            self.conn.commit()
            return novo_id 
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível criar a transação: {e}", parent=self.root)
            self.conn.rollback()
            return None

class CustomizationWindow:
    def __init__(self, root, settings_manager, apply_callback):
        self.root, self.settings_manager, self.apply_callback = root, settings_manager, apply_callback
        self.settings = self.settings_manager.load_settings()
        self.root.title("Personalizar Aparência"); self.root.transient(root.master); self.root.resizable(False, False)
        main_frame = ttk.Frame(self.root, padding=20); main_frame.pack(fill="both", expand=True)
        colors_frame = ttk.LabelFrame(main_frame, text="Cores da Interface", padding=10); colors_frame.pack(fill="x", pady=5)
        self.color_vars = {}
        color_labels = {"background": "Fundo Principal:", "text": "Texto Principal:", "button_bg": "Fundo dos Botões:",
                        "entry_bg": "Fundo de Entradas/Listas:", "header_bg": "Cabeçalho da Lista:"}
        for i, (key, label) in enumerate(color_labels.items()):
            ttk.Label(colors_frame, text=label).grid(row=i, column=0, sticky="w", pady=2)
            self.color_vars[key] = tk.StringVar(value=self.settings["colors"].get(key, "#FFFFFF"))
            preview = ttk.Label(colors_frame, text="      ", background=self.color_vars[key].get(), relief="solid", borderwidth=1); preview.grid(row=i, column=1, padx=10)
            ttk.Button(colors_frame, text="Escolher...", command=lambda k=key, p=preview: self.pick_color(k, p)).grid(row=i, column=2)
        colors_frame.grid_columnconfigure(1, weight=1)
        button_frame = ttk.Frame(main_frame); button_frame.pack(fill="x", side="bottom", pady=(10, 0))
        ttk.Button(button_frame, text="Resetar Cores", command=self.reset_colors).pack(side="left")
        ttk.Button(button_frame, text="Salvar e Aplicar", command=self.save_and_apply).pack(side="right")
        ttk.Button(button_frame, text="Cancelar", command=self.root.destroy).pack(side="right", padx=10)

    def pick_color(self, key, preview_label):
        code = colorchooser.askcolor(title=f"Escolha a cor para {key}", initialcolor=self.color_vars[key].get())
        if code and code[1]: self.color_vars[key].set(code[1]); preview_label.config(background=code[1])

    def reset_colors(self):
        default = self.settings_manager.default_settings['colors']
        for key, color in default.items(): self.color_vars[key].set(color)
        messagebox.showinfo("Reset", "Cores padrões restauradas. Clique em 'Salvar e Aplicar' para finalizar.", parent=self.root)

    def save_and_apply(self):
        new_settings = {"colors": {key: var.get() for key, var in self.color_vars.items()}}
        self.settings_manager.save_settings(new_settings); self.apply_callback(); self.root.destroy()
        messagebox.showinfo("Sucesso", "Aparência atualizada!", parent=self.root.master)

class EditTransactionWindow:
    def __init__(self, root, conn, transacao_id, refresh_callback):
        self.root, self.conn, self.refresh_callback = root, conn, refresh_callback
        self.root.title("Editar Transação"); self.root.geometry("500x250"); self.root.transient(root.master); self.root.resizable(False, False)
        data = conn.cursor().execute("SELECT descricao, valor, categoria, tipo, data FROM transacoes WHERE id=?", (transacao_id,)).fetchone()
        frame = ttk.Frame(self.root, padding=20); frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Descrição:").grid(row=0, column=0, sticky="w", pady=5)
        self.desc_entry = ttk.Entry(frame); self.desc_entry.grid(row=0, column=1, sticky="ew", pady=5); self.desc_entry.insert(0, data[0])
        ttk.Label(frame, text="Valor (R$):").grid(row=1, column=0, sticky="w", pady=5)
        self.val_entry = ttk.Entry(frame); self.val_entry.grid(row=1, column=1, sticky="ew", pady=5); self.val_entry.insert(0, f"{data[1]:.2f}")
        ttk.Label(frame, text="Categoria:").grid(row=2, column=0, sticky="w", pady=5)
        self.cat_entry = ttk.Entry(frame); self.cat_entry.grid(row=2, column=1, sticky="ew", pady=5); self.cat_entry.insert(0, data[2])
        ttk.Label(frame, text="Tipo:").grid(row=3, column=0, sticky="w", pady=5)
        self.tipo_var = tk.StringVar(value=data[3])
        tipo_combo = ttk.Combobox(frame, textvariable=self.tipo_var, values=["Receita", "Despesa"], state="readonly"); tipo_combo.grid(row=3, column=1, sticky="ew", pady=5)
        ttk.Label(frame, text="Data:").grid(row=4, column=0, sticky="w", pady=5)
        self.data_entry = DateEntry(frame, date_pattern='dd/MM/yyyy', locale='pt_BR'); self.data_entry.grid(row=4, column=1, sticky="ew", pady=5); self.data_entry.set_date(datetime.strptime(data[4], '%Y-%m-%d %H:%M:%S'))
        frame.grid_columnconfigure(1, weight=1)
        def salvar():
            try: novo_valor = float(self.val_entry.get().replace(",", ".")); assert novo_valor > 0
            except: messagebox.showerror("Erro", "Valor inválido.", parent=self.root); return
            nova_data = self.data_entry.get_date().strftime("%Y-%m-%d %H:%M:%S")
            self.conn.cursor().execute("UPDATE transacoes SET descricao=?, valor=?, categoria=?, tipo=?, data=? WHERE id=?", (self.desc_entry.get(), novo_valor, self.cat_entry.get(), self.tipo_var.get(), nova_data, transacao_id))
            self.conn.commit(); self.root.destroy(); self.refresh_callback()
        ttk.Button(frame, text="Salvar Alterações", command=salvar).grid(row=5, column=1, sticky="e", pady=10)
        ttk.Button(frame, text="Cancelar", command=self.root.destroy).grid(row=5, column=0, sticky="w", pady=10)

class RecorrenciasWindow:
    def __init__(self, root, conn, user_id, refresh_callback):
        self.root, self.conn, self.user_id, self.refresh_callback = root, conn, user_id, refresh_callback
        self.root.title("Gerenciar Transações Recorrentes")
        self.root.minsize(950, 550) 
        self.root.transient(root.master)
        
        self.active_filters = {}
        self.colunas_map = {"ID": 0, "Descrição": 1, "Valor": 2, "Tipo": 3, "Início": 4, "Parcelas": 5}
        
        # --- NOVO: Atributos para ordenação e drag-and-drop ---
        self.sort_column = None
        self.sort_direction = "asc"
        self._was_dragged = False
        self._click_region = None
        # --- FIM NOVO ---

        list_frame = ttk.LabelFrame(self.root, text="Recorrências Cadastradas (Clique Esq: Ordenar | Clique Dir: Filtrar)", padding=10); list_frame.pack(padx=10, pady=10, fill="both", expand=True)
        self.tree = ttk.Treeview(list_frame, columns=list(self.colunas_map.keys()), show="headings")
        
        # --- ALTERAÇÃO: Removido 'command' de todos os cabeçalhos ---
        self.tree.heading("ID", text="ID"); self.tree.column("ID", width=40)
        self.tree.heading("Descrição", text="Descrição"); self.tree.column("Descrição", width=250)
        self.tree.heading("Valor", text="Valor"); self.tree.column("Valor", width=100, anchor="e")
        self.tree.heading("Tipo", text="Tipo"); self.tree.column("Tipo", width=100)
        self.tree.heading("Início", text="Início"); self.tree.column("Início", width=120, anchor="center")
        self.tree.heading("Parcelas", text="Parcelas"); self.tree.column("Parcelas", width=100, anchor="center")
        # --- FIM ALTERAÇÃO ---

        self.tree.pack(fill="both", expand=True)

        self.tree.tag_configure('receita', background='#D4EDDA', foreground='#155724')
        self.tree.tag_configure('despesa', background='#F8D7DA', foreground='#721C24')

        self.menu_contexto = tk.Menu(self.root, tearoff=0); self.menu_contexto.add_command(label="Editar", command=self.abrir_edicao); self.menu_contexto.add_command(label="Duplicar", command=self.duplicar_recorrencia); self.menu_contexto.add_command(label="Excluir", command=self.excluir_recorrencia)
        
        # --- NOVOS BINDINGS (Feature 2 e 3) ---
        self.tree.bind("<ButtonPress-1>", self.on_tree_press)
        self.tree.bind("<B1-Motion>", self.on_tree_drag)
        self.tree.bind("<ButtonRelease-1>", self.on_tree_release)
        self.tree.bind("<Button-3>", self.on_tree_right_click)
        # --- FIM NOVOS BINDINGS ---
        
        # ... (Restante do __init__ permanece o mesmo) ...
        add_frame = ttk.LabelFrame(self.root, text="Adicionar/Editar Recorrência Mensal", padding=10); add_frame.pack(padx=10, pady=10, fill="x")
        ttk.Label(add_frame, text="Descrição:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.desc_entry = ttk.Entry(add_frame); self.desc_entry.grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        ttk.Label(add_frame, text="Valor:").grid(row=0, column=2, padx=5, pady=2, sticky="w")
        self.val_entry = ttk.Entry(add_frame); self.val_entry.grid(row=0, column=3, padx=5, pady=2, sticky="ew")
        ttk.Label(add_frame, text="Categoria:").grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.cat_entry = ttk.Entry(add_frame); self.cat_entry.grid(row=1, column=1, padx=5, pady=2, sticky="ew")
        ttk.Label(add_frame, text="Tipo:").grid(row=1, column=2, padx=5, pady=2, sticky="w")
        self.tipo_var = tk.StringVar(value="Despesa"); self.tipo_combo = ttk.Combobox(add_frame, textvariable=self.tipo_var, values=["Receita", "Despesa"], state="readonly"); self.tipo_combo.grid(row=1, column=3, padx=5, pady=2, sticky="ew")
        ttk.Label(add_frame, text="Data de Início:").grid(row=0, column=4, padx=5, pady=2, sticky="w")
        self.data_entry = DateEntry(add_frame, date_pattern='dd/MM/yyyy', locale='pt_BR'); self.data_entry.grid(row=0, column=5, padx=5, pady=2, sticky="ew")
        ttk.Label(add_frame, text="Nº de Parcelas (0=Infinito):").grid(row=1, column=4, padx=5, pady=2, sticky="w")
        self.parc_entry = ttk.Entry(add_frame); self.parc_entry.grid(row=1, column=5, padx=5, pady=2, sticky="ew"); self.parc_entry.insert(0, "0")
        self.months_frame = ttk.LabelFrame(add_frame, text="Meses Específicos (Deixe todos desmarcados para 'Todo Mês')")
        self.months_frame.grid(row=2, column=0, columnspan=6, sticky="ew", padx=5, pady=(5, 2))
        self.month_vars = {}
        meses_nomes = ["Jan", "Fev", "Mar", "Abr", "Mai", "Jun", "Jul", "Ago", "Set", "Out", "Nov", "Dez"]
        for i, mes in enumerate(meses_nomes):
            var = tk.BooleanVar()
            cb = ttk.Checkbutton(self.months_frame, text=mes, variable=var, width=5)
            cb.grid(row=i // 6, column=i % 6, padx=2, pady=2, sticky="w")
            self.month_vars[i+1] = var 
        self.btn_salvar = ttk.Button(add_frame, text="Adicionar", command=self.salvar_recorrencia); self.btn_salvar.grid(row=0, column=6, rowspan=3, padx=10, pady=2, sticky="nswe")
        ttk.Button(add_frame, text="Limpar", command=self.limpar_campos).grid(row=0, column=7, rowspan=3, padx=(0,10), pady=2, sticky="nswe")
        ttk.Button(add_frame, text="Limpar Filtros", command=self.limpar_filtros).grid(row=0, column=8, rowspan=3, padx=(0, 10), pady=2, sticky="nswe")
        add_frame.grid_columnconfigure(1, weight=1); self.edit_id = None; self.carregar_recorrencias()

    # --- MÉTODO MODIFICADO (Feature 2) ---
    def carregar_recorrencias(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        
        base_data = self._get_base_data()

        if self.active_filters:
            display_data = []
            for row in base_data:
                match = True
                for col_name, allowed_values in self.active_filters.items():
                    if col_name == "Valor":
                        cell_value = float(self._get_formatted_cell_value(row, col_name))
                    else:
                        cell_value = self._get_formatted_cell_value(row, col_name)
                    if cell_value not in allowed_values:
                        match = False; break
                if match:
                    display_data.append(row)
        else:
            display_data = base_data

        # --- NOVA LÓGICA DE ORDENAÇÃO ---
        if hasattr(self, 'sort_column') and self.sort_column:
            col_index = self.colunas_map.get(self.sort_column)
            if col_index is not None:
                is_reverse = (self.sort_direction == 'desc')

                def sort_key(row):
                    val = row[col_index]
                    if self.sort_column == 'Valor':
                        return float(val.replace(",", "."))
                    if self.sort_column == 'ID':
                        return int(val)
                    if self.sort_column == 'Início':
                        return datetime.strptime(val, '%d/%m/%Y')
                    if self.sort_column == 'Parcelas':
                        # Ordena por "Executadas / Total" (ex: "5/12", "1/∞")
                        parts = val.split('/')
                        return int(parts[0]) if parts[0].isdigit() else 0
                    return str(val).lower()
                    
                display_data.sort(key=sort_key, reverse=is_reverse)
        # --- FIM DA LÓGICA DE ORDENAÇÃO ---

        for row in display_data:
            tipo_recorrencia = row[3] 
            tag_cor = 'receita' if tipo_recorrencia == 'Receita' else 'despesa'
            self.tree.insert("", "end", values=row, tags=(tag_cor,))
        
        self.update_header_indicators() # Atualiza indicadores de filtro/ordenação
    # --- FIM DA MODIFICAÇÃO ---

    def _get_base_data(self):
        base_data = []
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, descricao, valor, tipo, data_inicio, ocorrencias, ocorrencias_executadas FROM recorrencias WHERE user_id = ?", (self.user_id,))
        for row in cursor.fetchall():
            tipo_recorrencia = row[3]
            parc_str = f"{row[6]}/{row[5]}" if row[5] != 0 else f"{row[6]}/∞"
            data_fmt = datetime.strptime(row[4], '%Y-%m-%d').strftime('%d/%m/%Y')
            valor_fmt = f"{row[2]:.2f}"
            formatted_row = (row[0], row[1], valor_fmt, tipo_recorrencia, data_fmt, parc_str)
            base_data.append(formatted_row)
        return base_data

    def _get_formatted_cell_value(self, row_data, column_name):
        col_index = self.colunas_map.get(column_name)
        if col_index is None: return ""
        return str(row_data[col_index])

    def open_filter_popup(self, column):
        base_data = self._get_base_data()
        
        other_filters = {k: v for k, v in self.active_filters.items() if k != column}
        if other_filters:
            filtered_subset = [row for row in base_data if all(self._get_formatted_cell_value(row, c) in v for c, v in other_filters.items())]
        else:
            filtered_subset = base_data
        
        if column == "Valor":
            unique_values = {float(self._get_formatted_cell_value(row, column)) for row in filtered_subset}
        else:
            unique_values = {self._get_formatted_cell_value(row, column) for row in filtered_subset}
            
        checked_values = self.active_filters.get(column, unique_values)
        FilterPopup(self.root, column, unique_values, checked_values, self.apply_filter)

    def apply_filter(self, column, selected_values):
        base_data = self._get_base_data() 
        
        if column == "Valor":
            all_possible = {float(self._get_formatted_cell_value(row, column)) for row in base_data}
        else:
            all_possible = {self._get_formatted_cell_value(row, column) for row in base_data}

        if selected_values and selected_values != all_possible:
            self.active_filters[column] = selected_values
        elif column in self.active_filters:
            del self.active_filters[column]
        
        self.carregar_recorrencias() 

    # --- MÉTODO MODIFICADO (Feature 2) ---
    def update_header_indicators(self):
        """Adiciona o indicador '▾' (filtro) e '▲'/'▼' (sort) aos cabeçalhos."""
        # Garante que o mapa de colunas inclua "Início"
        if "Início" not in self.colunas_map:
             self.colunas_map["Início"] = 4 

        for col_name in self.colunas_map.keys():
            text = col_name
            # 1. Indicador de Filtro
            if col_name in self.active_filters:
                text += " ▾"
            # 2. Indicador de Ordenação
            if hasattr(self, 'sort_column') and self.sort_column == col_name:
                text += " ▲" if self.sort_direction == 'asc' else " ▼"
            self.tree.heading(col_name, text=text)
    # --- FIM DA MODIFICAÇÃO ---
    
    # --- MÉTODO MODIFICADO (Feature 2) ---
    def limpar_filtros(self):
        """Limpa todos os filtros ativos e recarrega a lista."""
        self.active_filters.clear()
        # --- NOVO: Resetar ordenação ---
        self.sort_column = None
        self.sort_direction = "asc"
        # --- FIM NOVO ---
        self.carregar_recorrencias()
    # --- FIM DA MODIFICAÇÃO ---

    # --- NOVOS MÉTODOS (Feature 2 e 3) ---
    def on_tree_press(self, event):
        """Armazena a região do clique para diferenciar clique de arrastar."""
        self._was_dragged = False
        self._click_region = self.tree.identify("region", event.x, event.y)

    def on_tree_drag(self, event):
        """Marca como 'arrastado' se o mouse se mover após clicar no cabeçalho."""
        if self._click_region == "heading":
            self._was_dragged = True

    def on_tree_release(self, event):
        """No soltar do mouse, decide se foi um clique (ordenar) ou um arrastar (mover coluna)."""
        if self._was_dragged:
            self._was_dragged = False
            return 
        
        if self._click_region == "heading":
            self.handle_sort_click(event)
        # Nenhum evento de clique de célula nesta janela

    def handle_sort_click(self, event):
        """Lida com a lógica de ordenação ao clicar no cabeçalho."""
        region = self.tree.identify("region", event.x, event.y)
        if region != "heading": return

        col_id = self.tree.identify_column(event.x)
        col_name = self.tree.heading(col_id, "text").split(" ")[0]
        
        if not col_name: return

        if self.sort_column == col_name:
            self.sort_direction = "desc" if self.sort_direction == "asc" else "asc"
        else:
            self.sort_column = col_name
            self.sort_direction = "asc"
            
        self.carregar_recorrencias()

    def on_tree_right_click(self, event):
        """Lida com cliques do botão direito: Filtro no cabeçalho, Menu de Contexto na célula."""
        region = self.tree.identify("region", event.x, event.y)
        
        if region == "heading":
            col_id = self.tree.identify_column(event.x)
            col_name = self.tree.heading(col_id, "text").split(" ")[0]
            if col_name:
                self.open_filter_popup(col_name)
        elif region == "cell" or region == "tree":
            self.mostrar_menu(event) # Lógica original mantida
    # --- FIM NOVOS MÉTODOS ---

    # --- MÉTODO MODIFICADO (Feature 1) ---
    def salvar_recorrencia(self):
        try:
            valor = float(self.val_entry.get().replace(",", ".")); assert valor > 0
            ocorrencias = int(self.parc_entry.get()); assert ocorrencias >= 0
        except: messagebox.showerror("Erro", "Valor ou Nº de Parcelas inválido.", parent=self.root); return
        
        desc, cat, tipo, data_inicio = self.desc_entry.get(), self.cat_entry.get(), self.tipo_var.get(), self.data_entry.get_date().strftime("%Y-%m-%d")
        
        selected_months = [str(m) for m, var in self.month_vars.items() if var.get()]
        meses_db = ",".join(selected_months) if selected_months else None
        
        cursor = self.conn.cursor()
        if self.edit_id:
            msg = "Editar esta recorrência irá apagar e recriar todas as transações PENDENTES.\n\nTransações já pagas NÃO serão alteradas.\n\nDeseja continuar?"
            if messagebox.askyesno("Confirmar Edição", msg, icon='warning', parent=self.root):
                # --- ALTERAÇÃO: Deleta apenas transações NÃO PAGAS (quitado = 0) ---
                cursor.execute("DELETE FROM transacoes WHERE recorrencia_id = ? AND user_id = ? AND quitado = 0", (self.edit_id, self.user_id))
                cursor.execute("DELETE FROM recorrencia_exclusoes WHERE recorrencia_id = ? AND user_id = ?", (self.edit_id, self.user_id))
                # --- FIM ALTERAÇÃO ---
                
                cursor.execute("""
                    UPDATE recorrencias 
                    SET descricao=?, valor=?, tipo=?, categoria=?, data_inicio=?, ocorrencias=?, meses_selecionados=? 
                    WHERE id=?
                """, (desc, valor, tipo, cat, data_inicio, ocorrencias, meses_db, self.edit_id))
            else: return
        else:
            cursor.execute("""
                INSERT INTO recorrencias (user_id, descricao, valor, tipo, categoria, data_inicio, ocorrencias, meses_selecionados) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (self.user_id, desc, valor, tipo, cat, data_inicio, ocorrencias, meses_db))
            
        self.conn.commit(); self.limpar_campos(); self.carregar_recorrencias(); self.refresh_callback()
    # --- FIM DA MODIFICAÇÃO ---

    # --- MÉTODO MODIFICADO (Feature 1) ---
    def excluir_recorrencia(self):
        if not self.tree.selection(): return
        rec_id = self.tree.item(self.tree.selection()[0], 'values')[0]
        
        msg = "Isso irá apagar a REGRA de recorrência e todas as transações PENDENTES associadas.\n\nTransações já pagas serão mantidas no histórico, mas desvinculadas desta regra.\n\nDeseja continuar?"
        if messagebox.askyesno("Confirmar Exclusão", msg, icon='warning', parent=self.root):
            cursor = self.conn.cursor()
            
            # --- NOVAS REGRAS DE EXCLUSÃO (Feature 1) ---
            # 1. Deleta apenas transações pendentes
            cursor.execute("DELETE FROM transacoes WHERE recorrencia_id = ? AND user_id = ? AND quitado = 0", (rec_id, self.user_id))
            # 2. Desvincula (orfana) transações pagas
            cursor.execute("UPDATE transacoes SET recorrencia_id = NULL WHERE recorrencia_id = ? AND user_id = ? AND quitado = 1", (rec_id, self.user_id))
            # 3. Deleta as exclusões (pois a regra não existe mais)
            cursor.execute("DELETE FROM recorrencia_exclusoes WHERE recorrencia_id = ? AND user_id = ?", (rec_id, self.user_id))
            # 4. Deleta a regra de recorrência
            cursor.execute("DELETE FROM recorrencias WHERE id = ? AND user_id = ?", (rec_id, self.user_id))
            # --- FIM DAS NOVAS REGRAS ---
            
            self.conn.commit(); self.carregar_recorrencias(); self.refresh_callback()
    # --- FIM DA MODIFICAÇÃO ---

    def duplicar_recorrencia(self):
        if not self.tree.selection(): return
        rec_id = self.tree.item(self.tree.selection()[0], 'values')[0]
        cursor = self.conn.cursor()
        cursor.execute("SELECT user_id, descricao, valor, tipo, categoria, data_inicio, ocorrencias, meses_selecionados FROM recorrencias WHERE id=?", (rec_id,))
        original = cursor.fetchone()
        if original:
            user_id, desc, val, tipo, cat, data_inicio_orig, ocorrencias, meses_selecionados = original
            nova_desc = f"{desc} (Cópia)"
            cursor.execute("""
                INSERT INTO recorrencias (user_id, descricao, valor, tipo, categoria, data_inicio, ocorrencias, meses_selecionados) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, nova_desc, val, tipo, cat, data_inicio_orig, ocorrencias, meses_selecionados))
            self.conn.commit(); self.carregar_recorrencias(); self.refresh_callback()
            messagebox.showinfo("Sucesso", "Recorrência duplicada com sucesso.", parent=self.root)

    def abrir_edicao(self):
        if not self.tree.selection(): return
        self.edit_id = self.tree.item(self.tree.selection()[0], 'values')[0]
        data = self.conn.cursor().execute("SELECT * FROM recorrencias WHERE id=?", (self.edit_id,)).fetchone()
        
        self.desc_entry.delete(0, tk.END); self.desc_entry.insert(0, data[2])
        self.val_entry.delete(0, tk.END); self.val_entry.insert(0, f"{data[3]:.2f}")
        self.tipo_var.set(data[4]); self.cat_entry.delete(0, tk.END); self.cat_entry.insert(0, data[5])
        self.data_entry.set_date(datetime.strptime(data[6], '%Y-%m-%d'))
        self.parc_entry.delete(0, tk.END); self.parc_entry.insert(0, str(data[7]))
        
        meses_db = data[10] if len(data) > 10 else None
        selected_months = set(int(m) for m in meses_db.split(',')) if meses_db else set()
        for m, var in self.month_vars.items():
            var.set(m in selected_months)
            
        self.btn_salvar.config(text="Salvar Alterações")

    def limpar_campos(self):
        self.edit_id = None
        self.desc_entry.delete(0, tk.END); self.val_entry.delete(0, tk.END)
        self.cat_entry.delete(0, tk.END); self.parc_entry.delete(0, tk.END); self.parc_entry.insert(0, "0")
        self.data_entry.set_date(datetime.now()); self.btn_salvar.config(text="Adicionar")
        for var in self.month_vars.values():
            var.set(False)

    def mostrar_menu(self, event):
        item_id = self.tree.identify_row(event.y)
        if item_id: self.tree.selection_set(item_id); self.menu_contexto.post(event.x_root, event.y_root)

def main():
    def launch_app(user_id):
        root = tk.Tk(); GestorFinanceiroApp(root, user_id); root.mainloop()
    login_root = tk.Tk(); LoginWindow(login_root, on_login_success=launch_app); login_root.mainloop()

if __name__ == "__main__":
    main()
    