import tkinter as tk
from sys import version as py_version
from tkinter import filedialog
from tkinter import messagebox
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

from crypt import CaesarCipher, DecryptIter, \
    TrithemiusAssocReplace, TrithemiusLinearEquation, TrithemiusCipher, \
    LinearEquationException, GammaCipher, DESCipher, AsymmetricCipher
from gui.translations import i10n


class MultiTextBox(ScrolledText):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, wrap=tk.WORD, undo=True, **kwargs)
        self.context_menu = tk.Menu(self, tearoff=0)
        self.init_context()

    def init_context(self):
        menu = self.context_menu
        menu.add_command(label=i10n.MultiTextBoxContextMenuUndo, command=self.undo)
        menu.add_command(label=i10n.MultiTextBoxContextMenuRedo, command=self.redo)
        menu.add_separator()

        menu.add_command(label=i10n.MultiTextBoxContextMenuCut, command=self.cut)
        menu.add_command(label=i10n.MultiTextBoxContextMenuCopy, command=self.copy)
        menu.add_command(label=i10n.MultiTextBoxContextMenuPaste, command=self.paste)
        menu.add_separator()

        menu.add_command(label=i10n.MultiTextBoxContextMenuClear, command=self.clear)
        menu.add_command(label=i10n.MultiTextBoxContextMenuSelectAll, command=self.select_all)
        menu.master.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        self.context_menu.post(event.x_root, event.y_root)

    @property
    def value(self):
        return self.get(1.0, tk.END).rstrip('\n\r')

    @value.setter
    def value(self, value):
        self.clear()
        self.insert(tk.END, value)

    def undo(self):
        try:
            self.edit_undo()
        except tk.TclError:
            pass

    def redo(self):
        try:
            self.edit_redo()
        except tk.TclError:
            pass

    def clear(self):
        self.delete("1.0", tk.END)

    def copy(self):
        if not self.tag_ranges("sel"):
            self.select_all()

        self.event_generate('<<Copy>>')

    def paste(self):
        self.event_generate('<<Paste>>')

    def cut(self):
        self.event_generate('<<Cut>>')

    def select_all(self):
        self.tag_add(tk.SEL, "1.0", tk.END)


class MainWindow(ttk.Frame):
    def __init__(self, *args, **kwargs):
        ttk.Frame.__init__(self, *args, **kwargs)

        self._root().title(i10n.AppTitle)

        self.app = App()

        self.key_label = ttk.Label(self, text=i10n.MainWindowKeyLabel)
        self.key_box = MultiTextBox(self, height=3, width=1)
        self.msg_label = ttk.Label(self, text=i10n.MainWindowMessageLabel)
        self.msg_box = MultiTextBox(self, width=40, height=10)
        self.action_bar = ActionBar(self)

        self.task_label = tk.Frame(self)
        self.lp_label = ttk.Label(self.task_label, text=i10n.MainWindowCipherLabel)
        self.box_value = tk.StringVar()
        self.box = ttk.Combobox(self.task_label, textvariable=self.box_value,
                                state='readonly')
        self.box["values"] = list(self.app.ciphers_collection.keys())
        self.box.current(0)

        self.box.bind("<<ComboboxSelected>>", self.select_cipher_event)

        self.settings_btn = ttk.Button(self.task_label,
                                       text=i10n.MainWindowSettingsLabel,
                                       compound="left",
                                       command=self.call_settings)

        self.lp_label.grid(column=0, row=0, columnspan=20, sticky=tk.NSEW)
        self.box.grid(column=0, row=1, columnspan=15, sticky=tk.NSEW)
        self.settings_btn.grid(column=16, row=1, columnspan=5, sticky=tk.NSEW, padx=(6, 0))

        self.task_label.columnconfigure(0, weight=1)

        self.task_label.grid(column=0, row=0, columnspan=20, padx=6, pady=6, sticky=tk.NSEW)

        separator = ttk.Separator(self, orient=tk.HORIZONTAL)
        separator.grid(column=0, row=1, columnspan=20, sticky=(tk.N, tk.E, tk.W), pady=3)

        self.key_label.grid(column=0, row=2, columnspan=20, padx=6, sticky=tk.NSEW)
        self.key_box.grid(column=0, row=3, columnspan=20, padx=7, sticky=(tk.N, tk.E, tk.W))
        self.msg_label.grid(column=0, row=4, columnspan=20, padx=6, sticky=tk.EW)
        self.msg_box.grid(column=0, row=5, columnspan=20, padx=7, sticky=tk.NSEW)
        self.action_bar.grid(column=0, row=6, sticky=(tk.N, tk.E, tk.W))

        self.grid(column=0, row=0, sticky=tk.NSEW)
        self._root().columnconfigure(0, weight=1)
        self._root().rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=3)
        self.rowconfigure(5, weight=5)
        self.rowconfigure(5, weight=5)

        self.master.minsize(width=360, height=280)

        MenuBar(self)

    def call_settings(self):
        self.app.settings_wnd(self, self.app)

    def select_cipher_event(self, event):
        selected_cipher = self.box.get()
        self.app.select_cipher(selected_cipher)


class AsymmetricWindow(ttk.Frame):
    def __init__(self, *args, **kwargs):
        ttk.Frame.__init__(self, *args, **kwargs)

        self._root().title(i10n.AppTitle)

        self.secret_key_lb = ttk.Label(self, text=i10n.SecretKeyLabel)
        self.secret_key = MultiTextBox(self, height=3, width=1)
        self.m_lb = ttk.Label(self, text=i10n.AsymmetricMLabel)
        m_var = tk.StringVar()
        self.m_key_part = ttk.Entry(self, textvariable=m_var)
        self.s_lb = ttk.Label(self, text=i10n.AsymmetricSLabel)
        s_var = tk.StringVar()
        self.s_key_part = ttk.Entry(self, textvariable=s_var)
        self.public_key_lb = ttk.Label(self, text=i10n.AsymmetricPublicKeyLabel)
        self.public_key_part = MultiTextBox(self, height=3, width=1)

        self.msg_label = ttk.Label(self, text=i10n.AsymmetricWindowTextLabel)
        self.msg_box = MultiTextBox(self, width=40, height=10)

        self.secret_key_lb.grid(column=0, row=1, padx=6, columnspan=1, pady=6, sticky=tk.W)
        self.secret_key.grid(column=1, row=1, columnspan=15, padx=6, pady=6, sticky=tk.NSEW)
        self.m_lb.grid(column=16, row=1, columnspan=1, padx=6, pady=6, sticky=tk.W)
        self.m_key_part.grid(column=17, row=1, columnspan=1, padx=6, pady=6, sticky=tk.W)
        self.s_lb.grid(column=18, row=1, padx=6, columnspan=1, pady=6, sticky=tk.W)
        self.s_key_part.grid(column=19, row=1, columnspan=1, padx=6, pady=6, sticky=tk.W)

        self.public_key_lb.grid(column=0, row=2, padx=6, sticky=tk.W)
        self.public_key_part.grid(column=1, row=2, columnspan=19, padx=6, sticky=tk.NSEW)

        actions = ttk.Frame(self)

        separator = ttk.Separator(self, orient=tk.HORIZONTAL)
        separator.grid(column=0, row=3, columnspan=20, sticky=(tk.N, tk.E, tk.W), pady=3)

        self.msg_label.grid(column=0, row=4, columnspan=20, padx=6, sticky=tk.EW)
        self.msg_box.grid(column=0, row=5, columnspan=20, padx=7, sticky=tk.NSEW)

        self.button_1 = ttk.Button(actions, text=i10n.AsymmetricWindowEncryptButton, command=self.encrypt_click)
        self.button_1.grid(column=0, row=0, padx=6, pady=6, sticky=tk.W)
        self.button_2 = ttk.Button(actions, text=i10n.AsymmetricWindowCryptButton, command=self.crypt_click)
        self.button_2.grid(column=1, row=0, padx=6, pady=6, sticky=tk.W)

        actions.grid(column=0, row=6, columnspan=20, sticky=tk.NSEW)

        self.grid(column=0, row=0, sticky=tk.NSEW)
        self._root().columnconfigure(0, weight=1)
        self._root().rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=3)
        self.columnconfigure(1, weight=5)
        self.rowconfigure(5, weight=5)

        self.master.minsize(width=600, height=180)

        MenuBar(self)

    def crypt_click(self):
        crt_text = self.msg_box.value
        secret_key = self.secret_key.value

        cipher = AsymmetricCipher()

        try:
            s = int(self.s_key_part.get())
            m = int(self.m_key_part.get())

            crt_text = crt_text.split(' ')
            crt_text = [int(i.strip()) for i in crt_text]
            secret_key = secret_key.split(',')
            secret_key = [int(i.strip()) for i in secret_key]

            plain_text = cipher.decrypt(crt_text, secret_key, s, m)
            self.msg_box.value = plain_text
        except Exception as e:
            messagebox.showerror(message=e)

    def encrypt_click(self):
        msg = self.msg_box.value
        key = self.public_key_part.value

        cipher = AsymmetricCipher()

        try:
            public_key = key.split(',')
            public_key = [int(i.strip()) for i in public_key]

            crt_text = cipher.encrypt(msg, public_key)
            self.msg_box.value = crt_text
        except Exception as e:
            messagebox.showerror(message=e)


class MenuBar(tk.Menu):
    def __init__(self, parent):
        super().__init__(parent)
        file_menu = tk.Menu(self, tearoff=0)
        file_menu.add_command(label=i10n.MenuBarCreate, command=self.new)
        file_menu.add_command(label=i10n.MenuBarOpen, command=self._open_file)
        file_menu.add_command(label=i10n.MenuBarSave, command=self.save_file)
        file_menu.add_separator()
        file_menu.add_command(label=i10n.MenuBarExit, command=self.quit)

        tools_menu = tk.Menu(self, tearoff=0)
        tools_menu.add_command(label=i10n.MenuBarAsymmetric, command=self.show_asymmetric_wnd)
        tools_menu.add_command(label=i10n.MenuBarSymmetric, command=self.show_symmetric_wnd)

        help_menu = tk.Menu(self, tearoff=0)
        help_menu.add_command(label=i10n.MenuBarInfo, command=self.show_help_index)
        help_menu.add_command(label=i10n.MenuBarAbout, command=self.show_help)

        self.add_cascade(label=i10n.MenuBarFile, menu=file_menu)
        self.add_cascade(label=i10n.MenuBarMode, menu=tools_menu)
        self.add_cascade(label=i10n.MenuBarEdit, menu=self.master.msg_box.context_menu)
        self.add_cascade(label=i10n.MenuBarHelp, menu=help_menu)

        self._root().config(menu=self)

    def show_help(self):
        info_format = "{}\n{}\n\n{}: {}\n{}: {}"
        info_message = info_format.format(i10n.AppTitle, i10n.AppCopyright,
                                          i10n.PyVersionLabel, py_version,
                                          i10n.TkVersionLabel, tk.TclVersion)

        messagebox.showinfo(i10n.AppInfoTitle, info_message)

    def show_help_index(self):
        messagebox.showinfo(i10n.MenuBarHelpTitle, i10n.MenuBarHelpMessage)

    def show_asymmetric_wnd(self):
        AsymmetricWindow()

    def show_symmetric_wnd(self):
        MainWindow()

    def new(self):
        if hasattr(self.master, 'key_box'):
            self.master.key_box.clear()

        self.master.msg_box.clipboard_clear()
        self.master.msg_box.edit_reset()
        self.master.msg_box.clear()

    def _open_file(self):
        path = filedialog.askopenfilename()

        if not path:
            return

        self.new()

        with open(path, "rb") as file:
            bin_file_content = file.read()

            try:
                file_content = bin_file_content.decode('utf-8')
            except UnicodeDecodeError:
                file_content = bin_file_content

            self.master.msg_box.value = file_content

    def save_file(self):
        file = filedialog.asksaveasfile(
            mode='w',
            initialfile='file.txt',
            defaultextension=".txt",
            filetypes=[
                ("Text document", ".txt"),
                ('All files', "*")
            ]
        )

        if file:
            value = self.master.msg_box.value
            file.write(value)
            file.close()


class SettingsDialog(tk.Toplevel):
    def __init__(self, master, app):
        super().__init__(master)
        self.app = app

        self.grab_set()
        self.minsize(width=300, height=78)

        self.title(i10n.SettingsTitle)

        self.frame = ttk.Frame(self)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        frame_bottom = ttk.Frame(self)
        frame_bottom.pack(fill=tk.BOTH)

        separator = ttk.Separator(frame_bottom, orient=tk.HORIZONTAL)
        separator.pack(side=tk.TOP, fill=tk.X, expand=True)

        close_btn = ttk.Button(frame_bottom, text=i10n.SettingsCancelButton, command=self.destroy)
        close_btn.pack(side=tk.RIGHT, padx=6, pady=6)
        ok_btn = ttk.Button(frame_bottom, text=i10n.SettingsApplyButton, command=self._apply_btn_click)
        ok_btn.pack(side=tk.RIGHT, padx=0, pady=6)

        # inner:
        self.wrap = tk.Frame(self.frame)
        self.wrap.pack(fill=tk.BOTH, expand=True)
        self.wrap.columnconfigure(1, weight=1)

    def _apply_btn_click(self):
        self.app.settings = self.apply()
        self.destroy()

    def apply(self):
        raise NotImplementedError


class AlphabetSettingsField(ttk.Combobox):
    def __init__(self, master):
        self.box_value = tk.StringVar()
        super().__init__(master, textvariable=self.box_value, state='readonly')

        self['values'] = (i10n.LanguageLabelEnglish,
                          i10n.LanguageLabelUkraine,
                          i10n.LanguageLabelRussian)

        self.current(0)

    def get_current_alphabet(self):
        index = self.current()
        alphabet_map = ["EN", "UA", "RU"]

        return alphabet_map[index] if index < len(alphabet_map) else "EN"


class CaesarSettingsDialog(SettingsDialog):
    def __init__(self, master, app):
        super().__init__(master, app)

        self.alphabet = AlphabetSettingsField(self.wrap)
        self.storage = (self.alphabet.get_current_alphabet(),)

        alphabet_lb = tk.Label(self.wrap, text=i10n.SettingsAlphabetLabel)
        alphabet_lb.grid(row=0, column=0, sticky="e", pady=3)

        self.alphabet.grid(column=1, row=0, sticky="news", pady=3)

    def apply(self):
        settings = (self.alphabet.get_current_alphabet(),)
        return settings


class TrithemiusSettingsDialog(SettingsDialog):
    def __init__(self, master, app):
        super().__init__(master, app)

        self.alphabet = AlphabetSettingsField(self.wrap)
        self.storage = (self.alphabet.get_current_alphabet(),)

        alphabet_lb = tk.Label(self.wrap, text=i10n.SettingsAlphabetLabel)
        handle_lb = tk.Label(self.wrap, text=i10n.TrithemiusSettingsTypeLabel)

        self.handle_box_value = tk.StringVar()
        self.handle_box = ttk.Combobox(
            self.wrap,
            textvariable=self.handle_box_value,
            state='readonly'
        )

        self.handle_box["values"] = (
            i10n.TrithemiusTypeLinear,
            i10n.TrithemiusTypeNotLinear,
            i10n.TrithemiusTypeSloganLinear
        )

        self.handle_box.current(0)

        alphabet_lb.grid(row=0, column=0, sticky="e", pady=3)
        handle_lb.grid(row=1, column=0, sticky="e", pady=3)
        self.alphabet.grid(column=1, row=0, sticky="news", pady=3)
        self.handle_box.grid(column=1, row=1, sticky="news", pady=3)

    def get_current_handle_type(self):
        index = self.handle_box.current()
        alphabet_map = [
            TrithemiusLinearEquation,
            TrithemiusLinearEquation,
            TrithemiusAssocReplace
        ]

        return alphabet_map[index] if index < len(alphabet_map) else TrithemiusLinearEquation

    def apply(self):
        handle = self.get_current_handle_type()
        alphabet = self.alphabet.get_current_alphabet()
        return handle, alphabet


class EmptySettingsDialog(SettingsDialog):
    def apply(self):
        return tuple()


class DecryptDialog(tk.Toplevel):
    def __init__(self, master, app, params):
        super().__init__(master)
        self.grab_set()
        self.app = app
        self.params = params

        self.minsize(width=380, height=85)
        self.title(i10n.DecryptDialogTitle)

        self.frame = ttk.Frame(self)
        self.log = MultiTextBox(self.frame, width=40, height=10)

        xsb = ttk.Scrollbar(self.frame, orient='horizontal', command=self.log.xview)
        self.log.configure(xscroll=xsb.set)

        settings_frame = tk.LabelFrame(self, text=i10n.DecryptDialogSettingsLabel)
        settings_frame.pack(side=tk.TOP, fill=tk.X, padx=6, pady=6)

        lb = tk.Label(settings_frame, text=i10n.DecryptDialogRangeLabel)
        lb.grid(row=0, column=1, sticky=tk.EW, padx=6, pady=6)
        self.min_range = ttk.Entry(settings_frame)
        self.min_range.grid(row=0, column=2, sticky=tk.EW, padx=6, pady=6)
        self.max_range = ttk.Entry(settings_frame)
        self.max_range.grid(row=0, column=3, sticky=tk.EW, padx=6, pady=6)

        lb = tk.Label(settings_frame, text=i10n.DecryptDialogCharsLabel)
        lb.grid(row=1, column=1, sticky=tk.EW, padx=6, pady=6)
        self.chars = ttk.Entry(settings_frame)
        self.chars.grid(row=1, column=2, columnspan=2, sticky=tk.EW, padx=6, pady=6)

        msg, _ = self.params
        in_msg = tk.LabelFrame(self, text=i10n.DecryptDialogInputTextLabel)
        in_msg_lb = tk.Label(in_msg, text=msg)
        in_msg_lb.pack(side=tk.TOP, fill=tk.X, padx=6, pady=6)
        in_msg.pack(side=tk.TOP, fill=tk.X, padx=6, pady=6)

        xsb.grid(row=1, column=0, columnspan=20, sticky=tk.EW)
        self.log.grid(row=0, column=0, columnspan=19, sticky=tk.NSEW)
        self.frame.pack(fill=tk.BOTH, expand=True)

        frame_bottom = ttk.Frame(self)
        frame_bottom.pack(fill=tk.BOTH)

        separator = ttk.Separator(frame_bottom, orient=tk.HORIZONTAL)
        separator.pack(side=tk.TOP, fill=tk.X, expand=True)

        close_btn = ttk.Button(frame_bottom, text=i10n.DecryptDialogCloseButton, command=self.destroy)
        close_btn.pack(side=tk.RIGHT, padx=6, pady=6)
        ok_btn = ttk.Button(frame_bottom, text=i10n.DecryptDialogDecryptButton, command=self.start)
        ok_btn.pack(side=tk.RIGHT, padx=0, pady=6)

        self.frame.rowconfigure(0, weight=5)
        settings_frame.rowconfigure(0, weight=5)
        settings_frame.columnconfigure(0, weight=5)
        self.rowconfigure(0, weight=5)
        self.columnconfigure(0, weight=5)
        self.frame.columnconfigure(0, weight=5)

    def get_available_chars(self):
        chars = str(self.chars.get())

        if len(chars) > 1:
            return chars

        messagebox.showerror(message=i10n.DecryptDialogErrorNumOfChars)

    def get_limit(self):
        try:
            min_limit = int(self.min_range.get())
            max_limit = int(self.max_range.get())

            if min_limit < 0 or min_limit > max_limit:
                raise ValueError

            return min_limit, max_limit + 1
        except ValueError:
            messagebox.showerror(message=i10n.DecryptDialogErrorRangeValues)

    def start(self):
        self.log.clear()

        limit_range = self.get_limit()
        chars = self.get_available_chars()

        if (not chars) or (not limit_range):
            return

        in_msg, settings = self.params
        cipher = self.app.cipher('0', *settings)

        dc = DecryptIter(cipher, in_msg, chars, limit_range)

        for item in dc:
            key, msg = item
            self.log.insert(tk.END, "Key:\n%s\nPain text:\n%s\n\n" % (key, msg))


class ActionBar(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.button_1 = ttk.Button(self, text=i10n.ActionBarEncryptButton, command=self.encrypt_click)
        self.button_1.grid(column=0, row=0, padx=6, pady=6)
        self.button_2 = ttk.Button(self, text=i10n.ActionBarCryptButton, command=self.crypt_click)
        self.button_2.grid(column=1, row=0, padx=6, pady=6)
        self.button_3 = ttk.Button(self, text=i10n.ActionBarDecryptButton, command=self.decrypt_click)
        self.button_3.grid(column=2, row=0, padx=6, pady=6)

    def crypt_click(self):
        self._call_cipher('decrypt')

    def encrypt_click(self):
        self._call_cipher('encrypt')

    def _call_cipher(self, method):
        msg = self.master.msg_box.value
        key = self.master.key_box.value
        settings = self.master.app.settings

        try:
            cipher = self.master.app.cipher(key, *settings)
            self.master.msg_box.value = getattr(cipher, method)(msg)
        except ValueError:
            messagebox.showerror(message=i10n.ErrorKeyFormat)
        except TypeError:
            messagebox.showerror(message=i10n.ErrorExpressionFormat)
        except SyntaxError:
            messagebox.showerror(message=i10n.ErrorKeySyntax)
        except LinearEquationException:
            messagebox.showerror(message=i10n.ErrorLinearEquationException)
        except Exception as e:
            messagebox.showerror(message=e)

    def decrypt_click(self):
        msg = self.master.msg_box.value

        if msg:
            params = self.master.msg_box.value, self.master.app.settings
            DecryptDialog(self.master, self.master.app, params)
        else:
            messagebox.showerror(message=i10n.ErrorDecryptEmptyText)


class App(object):
    def __init__(self):
        self.ciphers_collection = {
            "Caesar cipher": (CaesarCipher, CaesarSettingsDialog, ()),
            "Trithemius cipher": (TrithemiusCipher, TrithemiusSettingsDialog, (TrithemiusLinearEquation,)),
            "Gamma cipher": (GammaCipher, CaesarSettingsDialog, ()),
            "DES": (DESCipher, EmptySettingsDialog, ())
        }

        self.settings = ()
        self.cipher = None
        self.settings_wnd = None
        self.select_cipher()

    def select_cipher(self, cipher_name=None):
        selected = self.ciphers_collection.get(cipher_name, self.ciphers_collection["Caesar cipher"])
        cipher, _, _ = selected

        if self.cipher != cipher:
            self.cipher, self.settings_wnd, self.settings = selected
