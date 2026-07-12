import json
import os
import re
import tkinter as tk
import ctypes
from ctypes import wintypes
from tkinter import ttk
from tkinter import font as tkfont
from tkinter import colorchooser
from tkinter import messagebox
from typing import Any
from urllib.parse import quote

DEFAULT_KEYWORDS = [
    "예시회사",
    "예시프로젝트",
    "내부식별자-0000",
    "샘플담당자",
    "예시주소",
]

SENSITIVE_PATTERNS = [
    ("이메일", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("휴대폰번호", re.compile(r"\b01[016789]-?\d{3,4}-?\d{4}\b")),
    ("일반전화", re.compile(r"\b0(?!1[016789])\d{1,2}-?\d{3,4}-?\d{4}\b")),
    ("주민등록번호", re.compile(r"\b\d{6}-?\d{7}\b")),
    ("신용카드번호", re.compile(r"\b(?:\d{4}-?){3}\d{4}\b")),
    ("신용카드번호(공백)", re.compile(r"\b(?:\d{4}\s+){3}\d{4}\b")),
    ("IPv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("IPv6", re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b")),
    ("계좌번호(일반)", re.compile(r"\b\d{2,4}-\d{2,4}-\d{2,6}\b")),
    ("JWT 토큰", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    ("Bearer 토큰", re.compile(r"\bBearer\s+[A-Za-z0-9\-._=]+\b", re.IGNORECASE)),
    ("OAuth 토큰(일반)", re.compile(r"\b(?:access|refresh|id)[-_]?token\b\s*[:=]\s*['\"]?[A-Za-z0-9\-._=]{8,}['\"]?", re.IGNORECASE)),
    ("클라우드 키(Azure)", re.compile(r"\b(?:azure|storage|account)?[_-]?(?:key|secret)\b\s*[:=]\s*['\"]?[A-Za-z0-9+/=]{20,}['\"]?", re.IGNORECASE)),
    ("클라우드 키(GCP)", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("클라우드 키(GCP OAuth)", re.compile(r"\bya29\.[0-9A-Za-z_-]+\b")),
    ("클라우드 키(AWS Session)", re.compile(r"\bASIA[0-9A-Z]{16}\b")),
    ("API 키(일반)", re.compile(r"\b(?:api[_-]?key|access[_-]?key|secret[_-]?key)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{8,}['\"]?", re.IGNORECASE)),
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Secret Key", re.compile(r"\baws(.{0,20})?(secret|access)?(.{0,20})?['\"][A-Za-z0-9/+=]{40}['\"]\b", re.IGNORECASE)),
    ("Private Key 블록", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Public Key 블록", re.compile(r"-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----")),
    ("Slack 토큰", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("GitHub 토큰", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("Google API 키", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("데이터베이스 커넥션 문자열", re.compile(r"\b(?:postgres|mysql|mariadb|sqlserver|mongodb)://[^\s]+\b", re.IGNORECASE)),
    ("Azure 커넥션 문자열", re.compile(r"\b(?:DefaultEndpointsProtocol|AccountName|AccountKey|SharedAccessSignature)=[^;\s]+(?:;[^;\s]+)*\b", re.IGNORECASE)),
]

SENSITIVE_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-session-id",
    "x-forwarded-for",
    "x-real-ip",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-csrf-token",
    "x-xsrf-token",
    "x-amz-security-token",
    "x-azure-key",
    "x-azure-sas",
    "x-goog-api-key",
    "x-goog-authenticated-user-email",
    "x-goog-authenticated-user-id",
}

SENSITIVE_PARAM_KEYS = {
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "private_key",
    "signature",
    "api_key",
    "apikey",
    "key",
    "auth",
    "authorization",
    "authcode",
    "code_verifier",
    "session",
    "sesskey",
    "sessionid",
    "jsessionid",
    "sid",
    "ssn",
    "social",
    "birth",
    "dob",
    "name",
    "firstname",
    "lastname",
    "fullname",
    "address",
    "addr",
    "zipcode",
    "postal",
    "phone",
    "mobile",
    "email",
    "cookie",
    "csrf",
    "xsrf",
    "session_token",
    "accesskey",
    "secretkey",
    "privatekey",
    "publickey",
}


class SecurePromptMaskerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Prompt Masker - 민감 텍스트 마스킹")
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        window_w = min(1440, max(1100, screen_w - 80))
        window_h = min(900, max(640, screen_h - 80))
        self.geometry(f"{window_w}x{window_h}")
        self.minsize(1040, 640)

        self.is_dark_mode = False
        self.text_font = tkfont.Font(family="맑은 고딕", size=11)
        self.theme_colors = {
            "bg": "#f4f4f4",
            "fg": "#111111",
            "entry_bg": "#ffffff",
            "select_bg": "#cce0ff",
            "search_bg": "#ffd54f",
            "search_fg": "#000000",
        }
        self.custom_fg = None
        self.saved_keywords = None
        self.saved_sensitive_unchecked = {}
        self.saved_category_unchecked = []
        self.saved_transform_mode = "mask"
        self.saved_controls_visible = True
        self.settings_needs_scrub = False
        self.settings_path = os.path.join(os.path.dirname(__file__), "settings.json")
        self._load_settings()
        self.transform_mode = tk.StringVar(value=self.saved_transform_mode)
        self.controls_visible_var = tk.BooleanVar(value=self.saved_controls_visible)

        self.search_state = {
            "input": {"query": "", "index": "1.0"},
            "output": {"query": "", "index": "1.0"},
        }
        self.viewer_windows = {}

        self._build_ui()
        self._load_defaults()
        self._apply_theme()
        if self.settings_needs_scrub:
            self._save_settings()
            self.settings_needs_scrub = False
        self.input_text.focus_set()
        self.bind_all("<Control-c>", self._on_copy_shortcut, add="+")
        self.bind_all("<Control-Return>", self._transform_from_shortcut, add="+")

    def _build_ui(self):
        main = ttk.Frame(self, padding=12)
        main.pack(fill="both", expand=True)
        main.rowconfigure(2, weight=1, minsize=260)
        main.columnconfigure(0, weight=1)

        header = ttk.Frame(main)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="Secure Prompt Masker - 민감 텍스트 마스킹", font=("맑은 고딕", 14, "bold")).grid(
            row=0, column=0, sticky="w"
        )
        self.controls_toggle_btn = ttk.Button(header, command=self.toggle_controls)
        self.controls_toggle_btn.grid(row=0, column=1, sticky="e")

        search_frame = ttk.Frame(main)
        search_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        search_frame.columnconfigure(0, weight=3)
        search_frame.columnconfigure(1, weight=2)

        input_search = ttk.LabelFrame(search_frame, text="입력 검색", padding=6)
        input_search.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        input_search.columnconfigure(1, weight=1)

        ttk.Label(input_search, text="검색어").grid(row=0, column=0, sticky="w")
        self.input_search_var = tk.StringVar()
        self.input_search_entry = ttk.Entry(input_search, textvariable=self.input_search_var)
        self.input_search_entry.grid(row=0, column=1, sticky="ew", padx=(5, 5))
        ttk.Button(input_search, text="↑", width=3, command=lambda: self.search_input("prev")).grid(
            row=0, column=2
        )
        ttk.Button(input_search, text="↓", width=3, command=lambda: self.search_input("next")).grid(
            row=0, column=3, padx=(5, 0)
        )

        output_search = ttk.LabelFrame(search_frame, text="결과 검색", padding=6)
        output_search.grid(row=0, column=1, sticky="ew", padx=(5, 0))
        output_search.columnconfigure(1, weight=1)

        ttk.Label(output_search, text="검색어").grid(row=0, column=0, sticky="w")
        self.output_search_var = tk.StringVar()
        self.output_search_entry = ttk.Entry(output_search, textvariable=self.output_search_var)
        self.output_search_entry.grid(row=0, column=1, sticky="ew", padx=(5, 5))
        ttk.Button(output_search, text="↑", width=3, command=lambda: self.search_output("prev")).grid(
            row=0, column=2
        )
        ttk.Button(output_search, text="↓", width=3, command=lambda: self.search_output("next")).grid(
            row=0, column=3, padx=(5, 0)
        )

        self.input_search_entry.bind("<Return>", lambda _e: self.search_input("next"))
        self.output_search_entry.bind("<Return>", lambda _e: self.search_output("next"))

        text_frame = ttk.Frame(main)
        text_frame.grid(row=2, column=0, sticky="nsew")
        text_frame.rowconfigure(0, weight=1, minsize=240)
        text_frame.columnconfigure(0, weight=3)
        text_frame.columnconfigure(1, weight=2)

        input_container = ttk.LabelFrame(text_frame, text="원본 패킷", padding=6)
        self.output_container = ttk.LabelFrame(text_frame, text="변환 결과", padding=6)
        input_container.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self.output_container.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        input_container.rowconfigure(1, weight=1)
        input_container.columnconfigure(0, weight=1)
        self.output_container.rowconfigure(1, weight=1)
        self.output_container.columnconfigure(0, weight=1)

        input_toolbar = ttk.Frame(input_container)
        input_toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        input_toolbar.columnconfigure(0, weight=1)
        self.input_stats_var = tk.StringVar(value="0줄 · 0자")
        ttk.Label(input_toolbar, textvariable=self.input_stats_var, style="Hint.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Button(input_toolbar, text="변환", command=self.transform).grid(
            row=0, column=1, sticky="e", padx=(0, 5)
        )
        ttk.Button(input_toolbar, text="붙여넣기", command=self.paste_input).grid(
            row=0, column=2, sticky="e", padx=(0, 5)
        )
        ttk.Button(input_toolbar, text="비우기", command=self.clear_input).grid(
            row=0, column=3, sticky="e", padx=(0, 5)
        )
        ttk.Button(input_toolbar, text="확대 보기/편집", command=self.open_input_viewer).grid(
            row=0, column=4, sticky="e"
        )

        output_toolbar = ttk.Frame(self.output_container)
        output_toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        output_toolbar.columnconfigure(0, weight=1)
        self.output_stats_var = tk.StringVar(value="0줄 · 0자")
        ttk.Label(output_toolbar, textvariable=self.output_stats_var, style="Hint.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Button(output_toolbar, text="결과 복사", command=self.copy_output).grid(
            row=0, column=1, sticky="e"
        )
        ttk.Button(output_toolbar, text="확대 보기", command=self.open_output_viewer).grid(
            row=0, column=2, sticky="e", padx=(5, 0)
        )

        self.input_text = tk.Text(input_container, wrap="word", height=14, font=self.text_font, undo=True, maxundo=-1)
        self.output_text = tk.Text(self.output_container, wrap="word", height=14, state="disabled", font=self.text_font)
        self._configure_text_widget_base(self.input_text)
        self._configure_text_widget_base(self.output_text)

        input_scroll = ttk.Scrollbar(input_container, orient="vertical", command=self.input_text.yview)
        output_scroll = ttk.Scrollbar(self.output_container, orient="vertical", command=self.output_text.yview)
        self.input_text.configure(yscrollcommand=input_scroll.set)
        self.output_text.configure(yscrollcommand=output_scroll.set)

        self.input_text.grid(row=1, column=0, sticky="nsew")
        input_scroll.grid(row=1, column=1, sticky="ns")
        self.output_text.grid(row=1, column=0, sticky="nsew")
        output_scroll.grid(row=1, column=1, sticky="ns")

        self.input_text.bind("<Control-z>", lambda _e: self.input_text.edit_undo())
        self.input_text.bind("<Control-y>", lambda _e: self.input_text.edit_redo())
        self.input_text.bind("<Control-a>", lambda e: self._select_all(e, self.input_text))
        self.output_text.bind("<Control-a>", lambda e: self._select_all(e, self.output_text))
        self.input_text.bind("<Control-f>", lambda e: self._focus_search(e, "input"))
        self.output_text.bind("<Control-f>", lambda e: self._focus_search(e, "output"))
        self.input_text.bind("<<Modified>>", self._on_input_modified)
        self.input_text.edit_modified(False)

        self.controls_frame = ttk.Frame(main, padding=(0, 8, 0, 0))
        self.controls_frame.grid(row=3, column=0, sticky="ew")
        control = self.controls_frame

        kw_frame = ttk.LabelFrame(control, text="마스킹 키워드 관리", padding=10)
        kw_frame.pack(side="left", fill="both", expand=True)

        self.kw_entry = ttk.Entry(kw_frame, width=30)
        self.kw_entry.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        kw_btns = ttk.Frame(kw_frame)
        kw_btns.grid(row=0, column=1, padx=5, pady=5, sticky="e")
        add_btn = ttk.Button(kw_btns, text="추가", command=self.add_keyword)
        add_btn.pack(side="left", padx=(0, 6))
        del_btn = ttk.Button(kw_btns, text="삭제", command=self.delete_keyword)
        del_btn.pack(side="left")

        self.kw_list = tk.Listbox(kw_frame, height=4, selectmode="single", font=self.text_font)
        kw_scroll = ttk.Scrollbar(kw_frame, orient="vertical", command=self.kw_list.yview)
        self.kw_list.configure(yscrollcommand=kw_scroll.set)
        self.kw_list.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        kw_scroll.grid(row=1, column=1, padx=(0, 5), pady=5, sticky="ns")

        kw_frame.columnconfigure(0, weight=1)
        kw_frame.rowconfigure(1, weight=1)
        kw_frame.columnconfigure(1, weight=0)

        action_frame = ttk.LabelFrame(control, text="동작", padding=10)
        action_frame.pack(side="left", fill="both", padx=(10, 0))
        action_frame.columnconfigure(1, weight=1)

        mode_frame = ttk.LabelFrame(action_frame, text="변환 방식", padding=6)
        mode_frame.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(0, 10))
        ttk.Radiobutton(
            mode_frame,
            text="마스킹",
            value="mask",
            variable=self.transform_mode,
            command=self._on_transform_mode_changed,
        ).pack(anchor="w")
        ttk.Radiobutton(
            mode_frame,
            text="URL 인코딩 (마스킹 아님)",
            value="url_encode",
            variable=self.transform_mode,
            command=self._on_transform_mode_changed,
        ).pack(anchor="w", pady=(4, 0))

        button_frame = ttk.Frame(action_frame)
        button_frame.grid(row=0, column=1, rowspan=2, sticky="nsew", padx=(0, 10))
        mask_btn = ttk.Button(button_frame, text="변환", command=self.transform)
        mask_btn.pack(fill="x", pady=(0, 5))

        copy_btn = ttk.Button(button_frame, text="결과 복사", command=self.copy_output)
        copy_btn.pack(fill="x")

        font_frame = ttk.LabelFrame(action_frame, text="글자 크기", padding=6)
        font_frame.grid(row=0, column=2, sticky="nsew", padx=(0, 10))

        self.font_size = tk.IntVar(value=self.text_font.actual("size"))
        self.font_spin = ttk.Spinbox(
            font_frame,
            from_=8,
            to=28,
            textvariable=self.font_size,
            width=5,
            command=self.update_font_size,
        )
        self.font_spin.pack(side="left")

        font_apply_btn = ttk.Button(font_frame, text="적용", command=self.update_font_size)
        font_apply_btn.pack(side="left", padx=(5, 0))

        self.dark_mode_var = tk.BooleanVar(value=self.is_dark_mode)
        dark_toggle = ttk.Checkbutton(
            action_frame,
            text="다크 모드",
            variable=self.dark_mode_var,
            command=self.toggle_dark_mode,
        )
        dark_toggle.grid(row=1, column=2, sticky="w", padx=(0, 10), pady=(8, 0))

        style_frame = ttk.LabelFrame(action_frame, text="스타일", padding=6)
        style_frame.grid(row=0, column=3, rowspan=2, sticky="nsew")

        ttk.Label(style_frame, text="글꼴").grid(row=0, column=0, sticky="w")
        self.font_family = tk.StringVar(value="맑은 고딕")
        families = sorted(tkfont.families())
        if "맑은 고딕" not in families:
            families.insert(0, "맑은 고딕")
        self.font_combo = ttk.Combobox(
            style_frame,
            textvariable=self.font_family,
            values=families,
            state="readonly",
            width=12,
        )
        self.font_combo.grid(row=0, column=1, sticky="we", padx=(5, 0))
        self.font_combo.bind("<<ComboboxSelected>>", self.update_font_family)

        ttk.Label(style_frame, text="테마").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.palette_var = tk.StringVar(value="다크" if self.is_dark_mode else "라이트")
        self.palette_combo = ttk.Combobox(
            style_frame,
            textvariable=self.palette_var,
            values=["라이트", "다크", "블루", "그린"],
            state="readonly",
            width=12,
        )
        self.palette_combo.grid(row=1, column=1, sticky="we", padx=(5, 0), pady=(6, 0))
        self.palette_combo.bind("<<ComboboxSelected>>", self.update_palette)

        ttk.Label(style_frame, text="글자색").grid(row=2, column=0, sticky="w", pady=(6, 0))
        fg_btn = ttk.Button(style_frame, text="색상 선택", command=self.pick_text_color)
        fg_btn.grid(row=2, column=1, sticky="w", padx=(5, 0), pady=(6, 0))

        style_frame.columnconfigure(1, weight=1)

        status = ttk.Frame(main)
        status.grid(row=4, column=0, sticky="ew", pady=(8, 0))
        status.columnconfigure(0, weight=1)
        self.status_var = tk.StringVar(value="준비됨")
        ttk.Label(status, textvariable=self.status_var).grid(row=0, column=0, sticky="w")

        self.notice_slot = ttk.Frame(main, height=72)
        self.notice_slot.grid(row=5, column=0, sticky="ew", pady=(6, 0))
        self.notice_slot.grid_propagate(False)
        self.notice_slot.columnconfigure(0, weight=1)
        self.notice_slot.rowconfigure(0, weight=1)

        self.notice_frame = ttk.LabelFrame(self.notice_slot, text="알림", padding=8, style="Notice.TLabelframe")
        self.notice_frame.grid(row=0, column=0, sticky="nsew")
        self.notice_frame.columnconfigure(0, weight=1)
        self.notice_var = tk.StringVar(value="")
        self.notice_label = tk.Label(
            self.notice_frame,
            textvariable=self.notice_var,
            justify="left",
            wraplength=1000,
            anchor="w",
        )
        self.notice_label.grid(row=0, column=0, sticky="ew")
        self.notice_frame.grid_remove()
        self.notice_after_id = None
        self.notice_mode = None
        self._apply_controls_visibility()
        self._update_output_title()
        self._update_input_stats()
        self._update_output_stats()

    def toggle_controls(self):
        self.controls_visible_var.set(not self.controls_visible_var.get())
        self._apply_controls_visibility()
        self._save_settings()

    def _apply_controls_visibility(self):
        if not hasattr(self, "controls_frame"):
            return
        visible = bool(self.controls_visible_var.get())
        if visible:
            self.controls_frame.grid()
            label = "설정 접기"
        else:
            self.controls_frame.grid_remove()
            label = "설정 펼치기"
        if hasattr(self, "controls_toggle_btn"):
            self.controls_toggle_btn.configure(text=label)

    def _load_defaults(self):
        keywords = self.saved_keywords if self.saved_keywords else DEFAULT_KEYWORDS
        for kw in keywords:
            self.kw_list.insert("end", kw)
        self._sort_keywords()

    def add_keyword(self):
        kw = self.kw_entry.get().strip()
        if kw:
            self.kw_list.insert("end", kw)
            self.kw_entry.delete(0, "end")
            self._sort_keywords()
            self._save_settings()
            self.status_var.set(f"키워드 추가: {kw}")

    def delete_keyword(self):
        sel = self.kw_list.curselection()
        if sel:
            removed = self.kw_list.get(sel[0])
            self.kw_list.delete(sel[0])
            self._sort_keywords()
            self._save_settings()
            self.status_var.set(f"키워드 삭제: {removed}")

    def _get_keywords(self):
        return [self.kw_list.get(i) for i in range(self.kw_list.size())]

    def _sort_keywords(self):
        keywords = self._get_keywords()

        def category(word):
            if not word:
                return 3
            ch = word[0]
            if "A" <= ch <= "Z" or "a" <= ch <= "z":
                return 0
            if "가" <= ch <= "힣":
                return 1
            if ch.isdigit():
                return 2
            return 3

        keywords.sort(key=lambda w: (category(w), w.lower()))
        self.kw_list.delete(0, "end")
        for kw in keywords:
            self.kw_list.insert("end", kw)

    def _configure_text_widget_base(self, widget):
        widget.configure(
            padx=10,
            pady=8,
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            spacing1=1,
            spacing3=1,
        )

    def _on_input_modified(self, _event=None):
        if not self.input_text.edit_modified():
            return
        self.input_text.edit_modified(False)
        self._update_input_stats()

    def _update_input_stats(self):
        if not hasattr(self, "input_stats_var"):
            return
        text = self.input_text.get("1.0", "end-1c")
        lines = text.count("\n") + 1 if text else 0
        self.input_stats_var.set(f"{lines:,}줄 · {len(text):,}자")

    def _update_output_stats(self):
        if not hasattr(self, "output_stats_var"):
            return
        text = self.output_text.get("1.0", "end-1c")
        lines = text.count("\n") + 1 if text else 0
        self.output_stats_var.set(f"{lines:,}줄 · {len(text):,}자")

    def _replace_output_text(self, text):
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", text)
        self.output_text.configure(state="disabled")
        self._update_output_stats()

    def paste_input(self):
        try:
            text = self.clipboard_get()
        except tk.TclError:
            self._set_notice("WARN: 클립보드에서 텍스트를 읽을 수 없습니다.", status="붙여넣기 실패")
            return
        if not text:
            self._set_notice("WARN: 클립보드에 붙여넣을 텍스트가 없습니다.", status="붙여넣기 실패")
            return
        self.input_text.insert("insert", text)
        self.input_text.focus_set()
        self._update_input_stats()
        self.status_var.set("원본 패킷 붙여넣기 완료")

    def clear_input(self):
        text = self.input_text.get("1.0", "end-1c")
        if not text:
            self.status_var.set("원본 패킷 입력창이 이미 비어 있습니다.")
            return
        confirmed = messagebox.askyesno("원본 패킷 비우기", "원본 패킷 입력 내용을 비울까요?", parent=self)
        if not confirmed:
            return
        self.input_text.delete("1.0", "end")
        self.input_text.focus_set()
        self._update_input_stats()
        self._replace_output_text("")
        self.status_var.set("원본 패킷 입력창을 비웠습니다.")

    def _transform_from_shortcut(self, _event=None):
        self.transform()
        return "break"

    def transform(self):
        if not self.input_text.get("1.0", "end-1c"):
            self._set_notice("WARN: 원본 패킷이 비어 있습니다.", status="변환 실패")
            return
        self._save_settings()
        if self.transform_mode.get() == "url_encode":
            self.url_encode()
        else:
            self.masking()

    def _on_transform_mode_changed(self):
        self._update_output_title()
        self._save_settings()

    def _update_output_title(self):
        if not hasattr(self, "output_container"):
            return
        title = (
            "URL 인코딩 결과 (마스킹되지 않음)"
            if self.transform_mode.get() == "url_encode"
            else "마스킹 결과"
        )
        self.output_container.configure(text=title)

    def masking(self):
        text = self.input_text.get("1.0", "end-1c")
        keywords = self._get_keywords()
        masked = text
        notice_parts = []

        details = self._collect_sensitive_details_raw(text)
        detected = self._summarize_sensitive_raw(details)
        if detected:
            selected = self._show_detection_dialog(details, detected)
            if selected is None:
                return
            if selected:
                masked = self._mask_sensitive_patterns(masked, selected)

        masked = self._mask_structured_sensitive(masked)

        for kw in keywords:
            if not kw:
                continue
            pattern = re.escape(kw)
            masked = re.sub(
                pattern,
                lambda m: "*" * len(m.group(0)),
                masked,
                flags=re.IGNORECASE,
            )

        self._replace_output_text(masked)

        remaining = self._collect_sensitive_details_raw(masked)
        if remaining:
            auto_masked = self._mask_sensitive_patterns(masked)
            if auto_masked != masked:
                masked = auto_masked
                self._replace_output_text(masked)
            remaining_after = self._collect_sensitive_details_raw(masked)
            if remaining_after:
                notice_parts.append(
                    "WARN: " + self._format_remaining_notice(remaining_after, auto_masked=True)
                )
                status = "마스킹 완료 (일부 잔여 탐지)"
            else:
                status = "마스킹 완료 (잔여 자동 마스킹 적용)"
        else:
            status = "마스킹 완료"

        self._copy_output_to_clipboard()
        notice_parts.append("OK: 변환 결과가 클립보드에 복사되었습니다.")
        self._set_notice("\n".join([p for p in notice_parts if p]), status=status)

    def url_encode(self):
        text = self.input_text.get("1.0", "end-1c")
        encoded = quote(text, safe="/:?&=#%[]@!$&'()*+,;-_.~\r\n")
        self._replace_output_text(encoded)
        self._copy_output_to_clipboard()
        self._set_notice(
            "WARN: URL 인코딩은 민감정보를 숨기지 않습니다. 결과가 클립보드에 복사되었습니다.",
            status="URL 인코딩 완료 (마스킹되지 않음)",
        )

    def copy_output(self):
        if not self.output_text.get("1.0", "end-1c"):
            self._set_notice("WARN: 복사할 결과가 없습니다.", status="결과 복사 실패")
            return
        self._copy_output_to_clipboard()
        self._set_notice("OK: 결과가 클립보드에 복사되었습니다.", status="결과 복사 완료")

    def _copy_output_to_clipboard(self):
        text = self.output_text.get("1.0", "end-1c")
        self._set_clipboard_persistent(text)

    def _on_copy_shortcut(self, event=None):
        widget = self.focus_get()
        selected_text = self._extract_selected_text(widget)
        if selected_text:
            self._set_clipboard_persistent(selected_text)
            return "break"
        return None

    def _extract_selected_text(self, widget):
        if widget is None:
            return ""
        try:
            if isinstance(widget, tk.Text):
                return widget.get("sel.first", "sel.last")
            if isinstance(widget, (tk.Entry, ttk.Entry)):
                return widget.selection_get()
            if isinstance(widget, tk.Listbox):
                selected = [widget.get(i) for i in widget.curselection()]
                return "\n".join(selected)
        except tk.TclError:
            return ""
        return ""

    def _set_clipboard_persistent(self, text):
        if os.name == "nt":
            if self._set_windows_clipboard(text):
                return

        # Fallback: keep tkinter clipboard synchronized for non-Windows environments.
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update_idletasks()
        self.update()

    def _set_windows_clipboard(self, text):
        if text is None:
            text = ""
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        CF_UNICODETEXT = 13
        GMEM_MOVEABLE = 0x0002
        GHND = GMEM_MOVEABLE | 0x0040

        if not user32.OpenClipboard(None):
            return False
        try:
            if not user32.EmptyClipboard():
                return False

            data = str(text)
            data_size = (len(data) + 1) * ctypes.sizeof(wintypes.WCHAR)
            h_global = kernel32.GlobalAlloc(GHND, data_size)
            if not h_global:
                return False

            ptr = kernel32.GlobalLock(h_global)
            if not ptr:
                kernel32.GlobalFree(h_global)
                return False

            try:
                ctypes.memmove(ptr, ctypes.create_unicode_buffer(data), data_size)
            finally:
                kernel32.GlobalUnlock(h_global)

            if not user32.SetClipboardData(CF_UNICODETEXT, h_global):
                kernel32.GlobalFree(h_global)
                return False

            # On success, clipboard owns the memory; do not free h_global.
            return True
        finally:
            user32.CloseClipboard()

    def _set_notice(self, message, status=None):
        if status:
            self.status_var.set(status)
        if hasattr(self, "notice_var"):
            if hasattr(self, "notice_frame"):
                if message:
                    self.notice_frame.grid()
                else:
                    self.notice_frame.grid_remove()
            notice_mode = None
            if message.startswith("OK:"):
                notice_mode = "ok"
            elif message.startswith("WARN:"):
                notice_mode = "warn"
            if notice_mode == "ok":
                message = message.replace("OK:", "✅", 1).strip()
            elif notice_mode == "warn":
                message = message.replace("WARN:", "⚠️", 1).strip()
            self.notice_var.set(message)
            if notice_mode:
                self.notice_mode = notice_mode
                if hasattr(self, "notice_colors"):
                    colors = self.notice_colors.get(notice_mode, {})
                    self.notice_label.configure(
                        bg=colors.get("bg") or self.current_theme["bg"],
                        fg=colors.get("fg") or self.current_theme["fg"],
                    )
            if self.notice_after_id:
                self.after_cancel(self.notice_after_id)
                self.notice_after_id = None
            if message:
                self.notice_after_id = self.after(3000, self._clear_notice)
            else:
                self.notice_mode = None

    def _clear_notice(self):
        self.notice_var.set("")
        self.notice_mode = None
        if hasattr(self, "notice_frame"):
            self.notice_frame.grid_remove()
        if hasattr(self, "notice_label") and hasattr(self, "current_theme"):
            self.notice_label.configure(bg=self.current_theme["bg"], fg=self.current_theme["fg"])

    def open_input_viewer(self):
        self._open_text_viewer(
            title="원본 패킷 (확대 보기)",
            text=self.input_text.get("1.0", "end-1c"),
            editable=True,
            viewer_key="input",
        )

    def open_output_viewer(self):
        title = (
            "URL 인코딩 결과 (확대 보기, 마스킹되지 않음)"
            if self.transform_mode.get() == "url_encode"
            else "마스킹 결과 (확대 보기)"
        )
        self._open_text_viewer(
            title=title,
            text=self.output_text.get("1.0", "end-1c"),
            editable=False,
            viewer_key="output",
        )

    def _open_text_viewer(self, title, text, editable, viewer_key):
        existing = self.viewer_windows.get(viewer_key)
        if existing is not None:
            try:
                if existing.winfo_exists():
                    existing.deiconify()
                    existing.lift()
                    existing.focus_force()
                    return
            except tk.TclError:
                pass
            self.viewer_windows.pop(viewer_key, None)

        window = tk.Toplevel(self)
        self.viewer_windows[viewer_key] = window
        window.title(title)
        window.geometry("900x650")
        try:
            window.state("zoomed")
        except tk.TclError:
            pass

        def close_window():
            if self.viewer_windows.get(viewer_key) is window:
                self.viewer_windows.pop(viewer_key, None)
            window.destroy()

        window.protocol("WM_DELETE_WINDOW", close_window)

        container = ttk.Frame(window, padding=10)
        container.pack(fill="both", expand=True)
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

        big_font = tkfont.Font(family=self.text_font.actual("family"), size=self.text_font.actual("size") + 4)
        text_widget = tk.Text(container, wrap="word", font=big_font, undo=editable, maxundo=-1)
        self._configure_text_widget_base(text_widget)
        scroll = ttk.Scrollbar(container, orient="vertical", command=text_widget.yview)
        text_widget.configure(yscrollcommand=scroll.set)

        text_widget.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        text_widget.bind("<Control-a>", lambda e: self._select_all(e, text_widget))
        window.bind("<Escape>", lambda _e: close_window())

        if hasattr(self, "current_theme"):
            text_widget.configure(
                bg=self.current_theme["entry_bg"],
                fg=self.current_theme["fg"],
                insertbackground=self.current_theme["fg"],
            )

        text_widget.insert("1.0", text)
        if not editable:
            text_widget.configure(state="disabled")

        controls = ttk.Frame(container)
        controls.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        controls.columnconfigure(0, weight=1)

        size_frame = ttk.Frame(controls)
        size_frame.grid(row=0, column=0, sticky="w")
        ttk.Label(size_frame, text="글자 크기").pack(side="left")
        size_var = tk.IntVar(value=big_font.actual("size"))
        size_spin = ttk.Spinbox(
            size_frame,
            from_=8,
            to=48,
            textvariable=size_var,
            width=5,
        )
        size_spin.pack(side="left", padx=(6, 0))

        def apply_size():
            big_font.configure(size=size_var.get())

        ttk.Button(size_frame, text="적용", command=apply_size).pack(side="left", padx=(6, 0))

        btn_frame = ttk.Frame(controls)
        btn_frame.grid(row=0, column=1, sticky="e")

        def apply_changes():
            if editable:
                updated = text_widget.get("1.0", "end-1c")
                self.input_text.delete("1.0", "end")
                self.input_text.insert("1.0", updated)
                self._update_input_stats()
                self.status_var.set("원본 패킷 수정 완료")
            close_window()

        ttk.Button(btn_frame, text="닫기", command=close_window).pack(side="right")
        if editable:
            ttk.Button(btn_frame, text="적용", command=apply_changes).pack(side="right", padx=(0, 5))

    def search_input(self, direction):
        query = self.input_search_var.get().strip()
        self._search_text(self.input_text, query, direction, "input")

    def search_output(self, direction):
        query = self.output_search_var.get().strip()
        self._search_text(self.output_text, query, direction, "output")

    def _search_text(self, widget, query, direction, key):
        if not query:
            return

        state = self.search_state[key]
        if state["query"] != query:
            state["query"] = query
            state["index"] = "1.0" if direction == "next" else "end"

        widget.tag_remove("search", "1.0", "end")

        if direction == "next":
            start = state["index"]
            idx = widget.search(query, start, stopindex="end", nocase=True)
            if not idx:
                idx = widget.search(query, "1.0", stopindex="end", nocase=True)
        else:
            start = state["index"]
            idx = widget.search(query, start, stopindex="1.0", nocase=True, backwards=True)
            if not idx:
                idx = widget.search(query, "end", stopindex="1.0", nocase=True, backwards=True)

        if idx:
            end = f"{idx}+{len(query)}c"
            widget.tag_add("search", idx, end)
            if hasattr(self, "current_theme"):
                widget.tag_config(
                    "search",
                    background=self.current_theme.get("search_bg", "#ffd54f"),
                    foreground=self.current_theme.get("search_fg", "#000000"),
                )
            else:
                widget.tag_config("search", background="#ffd54f", foreground="#000000")
            widget.see(idx)
            state["index"] = end if direction == "next" else idx

    def _select_all(self, event, widget):
        widget.tag_add("sel", "1.0", "end-1c")
        return "break"

    def _focus_search(self, event, target):
        if target == "input" and hasattr(self, "input_search_entry"):
            self.input_search_entry.focus_set()
            self.input_search_entry.select_range(0, "end")
        elif target == "output" and hasattr(self, "output_search_entry"):
            self.output_search_entry.focus_set()
            self.output_search_entry.select_range(0, "end")
        return "break"

    def _collect_sensitive_details_raw(self, text):
        details = {}
        for name, pattern in SENSITIVE_PATTERNS:
            matches = list(pattern.finditer(text))
            if matches:
                values = []
                for m in matches:
                    value = m.group(0)
                    if value:
                        if name == "IPv4" and self._looks_like_product_version(text, m):
                            continue
                        if name == "주민등록번호" and not self._is_valid_rrn(value):
                            continue
                        if name == "계좌번호(일반)" and self._looks_like_date(value):
                            continue
                        if name == "계좌번호(일반)" and self._looks_like_phone_number(value):
                            continue
                        values.append(value)
                if values:
                    details[name] = values
        return details

    def _looks_like_product_version(self, text, match):
        # Exclude browser/app version tokens such as Chrome/145.0.0.0 from IPv4 detection.
        prefix = text[max(0, match.start() - 80) : match.start()]
        suffix = text[match.end() : min(len(text), match.end() + 8)]

        # Typical UA/product token: ProductName/1.2.3.4
        if re.search(r"(?:^|[\s(;\[,])([A-Za-z][A-Za-z0-9._-]{0,40})/$", prefix):
            if not suffix or re.match(r"^[\s;,)\]/]", suffix):
                return True

        # Generic version context: version/build/release followed by numeric token.
        if re.search(r"(?:version|build|release)\s*[:=/\-]?\s*$", prefix, flags=re.IGNORECASE):
            if not suffix or re.match(r"^[\s;,)\]/]", suffix):
                return True

        return False

    def _looks_like_date(self, value):
        return bool(re.match(r"^\d{4}-\d{2}-\d{2}$", value))

    def _looks_like_phone_number(self, value):
        compact = re.sub(r"\s", "", value)
        mobile_pattern = re.compile(r"^01[016789]-?\d{3,4}-?\d{4}$")
        landline_pattern = re.compile(r"^0(?!1[016789])\d{1,2}-?\d{3,4}-?\d{4}$")
        return bool(mobile_pattern.match(compact) or landline_pattern.match(compact))

    def _is_valid_rrn(self, value):
        digits = re.sub(r"\D", "", value)
        if len(digits) != 13:
            return False
        weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
        total = sum(int(d) * w for d, w in zip(digits[:12], weights))
        check = (11 - (total % 11)) % 10
        return check == int(digits[12])

    def _summarize_sensitive_raw(self, details):
        detected = {}
        for name, values in details.items():
            if not values:
                continue
            samples = []
            for v in values:
                label = self._format_value_label(v)
                if label not in samples:
                    samples.append(label)
                if len(samples) == 3:
                    break
            detected[name] = {"count": len(values), "samples": samples}
        return detected

    def _format_value_label(self, value, max_len=80):
        label = value.replace("\r", "").replace("\n", " ").strip()
        if len(label) > max_len:
            label = f"{label[:max_len]}..."
        return label

    def update_font_size(self):
        size = self.font_size.get()
        self.text_font.configure(size=size)
        self._save_settings()

    def update_font_family(self, _event=None):
        family = self.font_family.get()
        self.text_font.configure(family=family)
        self._save_settings()

    def toggle_dark_mode(self):
        self.is_dark_mode = bool(self.dark_mode_var.get())
        self.palette_var.set("다크" if self.is_dark_mode else "라이트")
        self._apply_theme()
        self._save_settings()

    def update_palette(self, _event=None):
        self.is_dark_mode = self.palette_var.get() == "다크"
        self._apply_theme()
        self._save_settings()

    def pick_text_color(self):
        color = colorchooser.askcolor(title="글자색 선택")
        if color and color[1]:
            self.custom_fg = color[1]
            self._apply_theme()
            self._save_settings()

    def _load_settings(self):
        if not os.path.exists(self.settings_path):
            return
        try:
            with open(self.settings_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            family = data.get("font_family", "맑은 고딕")
            size = int(data.get("font_size", 11))
            self.text_font.configure(family=family, size=size)
            self.is_dark_mode = bool(data.get("dark_mode", False))
            palette = data.get("palette", "다크" if self.is_dark_mode else "라이트")
            palette_map = {
                "Light": "라이트",
                "Dark": "다크",
                "Blue": "블루",
                "Green": "그린",
                "Custom": "라이트",
            }
            palette = palette_map.get(palette, palette)
            self.theme_colors.update(data.get("theme_colors", {}))
            self.custom_fg = data.get("custom_fg")
            self._pending_palette = palette
            self.settings_needs_scrub = "sensitive_unchecked" in data
            keywords = data.get("keywords")
            if isinstance(keywords, list) and keywords:
                self.saved_keywords = [str(k) for k in keywords if str(k).strip()]
            category_unchecked = data.get("category_unchecked", [])
            if isinstance(category_unchecked, list):
                self.saved_category_unchecked = [str(v) for v in category_unchecked]
            transform_mode = data.get("transform_mode", "mask")
            if transform_mode in {"mask", "url_encode"}:
                self.saved_transform_mode = transform_mode
            self.saved_controls_visible = True
        except (OSError, ValueError, json.JSONDecodeError):
            self._pending_palette = "다크" if self.is_dark_mode else "라이트"

    def _save_settings(self):
        data = {
            "font_family": self.text_font.actual("family"),
            "font_size": self.text_font.actual("size"),
            "dark_mode": self.is_dark_mode,
            "palette": self.palette_var.get(),
            "theme_colors": self.theme_colors,
            "custom_fg": self.custom_fg,
            "keywords": self._get_keywords() if hasattr(self, "kw_list") else [],
            "category_unchecked": self.saved_category_unchecked,
            "transform_mode": self.transform_mode.get() if hasattr(self, "transform_mode") else self.saved_transform_mode,
            "controls_visible": True,
        }
        try:
            with open(self.settings_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def _apply_theme(self):
        palette = self.palette_var.get()
        if hasattr(self, "_pending_palette"):
            palette = self._pending_palette or palette
            self.palette_var.set(palette)
            self._pending_palette = None
        if palette == "다크":
            bg, fg, entry_bg, select_bg = "#000000", "#ffffff", "#111111", "#333333"
            muted_fg, border = "#b7b7b7", "#2f2f2f"
        elif palette == "블루":
            bg, fg, entry_bg, select_bg = "#e9f1ff", "#0b1f44", "#ffffff", "#bcd6ff"
            muted_fg, border = "#4e6488", "#adc7ea"
        elif palette == "그린":
            bg, fg, entry_bg, select_bg = "#e8f5ee", "#103b2a", "#ffffff", "#bfe6d0"
            muted_fg, border = "#416652", "#a8d6bc"
        else:
            bg, fg, entry_bg, select_bg = "#f4f4f4", "#111111", "#ffffff", "#cce0ff"
            muted_fg, border = "#606060", "#d4d4d4"

        self.configure(bg=bg)
        fg = self.custom_fg or fg
        self.current_theme = {
            "bg": bg,
            "fg": fg,
            "entry_bg": entry_bg,
            "select_bg": select_bg,
            "muted_fg": muted_fg,
            "border": border,
            "search_bg": self.theme_colors.get("search_bg", "#ffd54f"),
            "search_fg": self.theme_colors.get("search_fg", "#000000"),
        }
        if palette == "다크":
            self.notice_colors = {
                "ok": {"bg": "#0f2a1a", "fg": "#c8f7d1"},
                "warn": {"bg": "#3a2a00", "fg": "#ffe29a"},
            }
        else:
            self.notice_colors = {
                "ok": {"bg": "#e6f4ea", "fg": "#1b5e20"},
                "warn": {"bg": "#fff4cc", "fg": "#5d3a00"},
            }
        style = ttk.Style()
        style.configure("TFrame", background=bg)
        style.configure("TLabelframe", background=bg, foreground=fg)
        style.configure("TLabelframe.Label", background=bg, foreground=fg)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("Hint.TLabel", background=bg, foreground=muted_fg)
        style.configure("Notice.TLabelframe", background=bg, foreground=fg)
        style.configure("Notice.TLabelframe.Label", background=bg, foreground=fg)
        style.configure("TButton", padding=(8, 4))
        style.configure("TCheckbutton", background=bg, foreground=fg)
        style.configure("TRadiobutton", background=bg, foreground=fg)

        text_options = {
            "bg": entry_bg,
            "fg": fg,
            "insertbackground": fg,
            "selectbackground": select_bg,
            "selectforeground": fg,
            "highlightbackground": border,
            "highlightcolor": select_bg,
        }
        self.input_text.configure(**text_options)
        self.output_text.configure(**text_options)
        self.kw_list.configure(
            bg=entry_bg,
            fg=fg,
            selectbackground=select_bg,
            selectforeground=fg,
            highlightbackground=border,
            highlightcolor=select_bg,
            highlightthickness=1,
        )
        if hasattr(self, "notice_label"):
            if self.notice_mode and self.notice_mode in self.notice_colors:
                colors = self.notice_colors[self.notice_mode]
                self.notice_label.configure(bg=colors["bg"], fg=colors["fg"])
            else:
                self.notice_label.configure(bg=bg, fg=fg)

        self.input_text.tag_config("search", background=self.current_theme["search_bg"], foreground=self.current_theme["search_fg"])
        self.output_text.tag_config("search", background=self.current_theme["search_bg"], foreground=self.current_theme["search_fg"])

    def _show_detection_dialog(self, details, detected):
        window = tk.Toplevel(self)
        window.title("민감정보 탐지 결과")
        window.geometry("920x620")
        window.minsize(780, 520)
        window.resizable(True, True)
        if self.tk.call("tk", "windowingsystem") != "win32":
            window.transient(self)
        window.lift()
        window.focus_force()
        try:
            window.attributes("-topmost", True)
            def release_topmost():
                try:
                    if window.winfo_exists():
                        window.attributes("-topmost", False)
                except tk.TclError:
                    pass

            window.after(250, release_topmost)
        except tk.TclError:
            pass

        container = ttk.Frame(window, padding=10)
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)
        container.columnconfigure(1, weight=2)
        container.rowconfigure(1, weight=1)

        ttk.Label(container, text="항목별로 마스킹할 값을 선택하세요.").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8)
        )

        list_frame = ttk.Frame(container)
        list_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        list_frame.rowconfigure(1, weight=1)
        list_frame.rowconfigure(3, weight=1)
        list_frame.columnconfigure(0, weight=1)

        detail_frame = ttk.Frame(container)
        detail_frame.grid(row=1, column=1, sticky="nsew")
        detail_frame.rowconfigure(1, weight=1)
        detail_frame.columnconfigure(0, weight=1)

        names = list(detected.keys())

        ttk.Label(list_frame, text="상세 확인 항목").grid(row=0, column=0, sticky="w", pady=(0, 4))
        listbox = tk.Listbox(list_frame, height=10)
        for name in names:
            count = detected[name]["count"]
            listbox.insert("end", f"{name} ({count}건)")
        listbox.selection_set(0)
        listbox.grid(row=1, column=0, sticky="nsew")
        list_scroll = ttk.Scrollbar(list_frame, orient="vertical", command=listbox.yview)
        listbox.configure(yscrollcommand=list_scroll.set)
        list_scroll.grid(row=1, column=1, sticky="ns")

        header_frame = ttk.Frame(detail_frame)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        header_frame.columnconfigure(1, weight=1)
        ttk.Label(header_frame, text="선택 항목:").grid(row=0, column=0, sticky="w")
        category_var = tk.StringVar(value=names[0])
        ttk.Label(header_frame, textvariable=category_var).grid(row=0, column=1, sticky="w")
        value_count_var = tk.StringVar(value="")
        ttk.Label(header_frame, textvariable=value_count_var).grid(row=0, column=2, sticky="e")

        select_frame = ttk.LabelFrame(detail_frame, text="항목별 선택", padding=6)
        select_frame.grid(row=1, column=0, sticky="nsew")
        select_frame.columnconfigure(0, weight=1)
        select_frame.rowconfigure(0, weight=1)

        canvas = tk.Canvas(select_frame, highlightthickness=0)
        vsb = ttk.Scrollbar(select_frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        inner = ttk.Frame(canvas)
        canvas.create_window((0, 0), window=inner, anchor="nw")

        value_vars = {}
        value_labels = {}
        for name in names:
            counts = {}
            order = []
            for v in details.get(name, []):
                if v not in counts:
                    counts[v] = 0
                    order.append(v)
                counts[v] += 1
            unchecked = set(self.saved_sensitive_unchecked.get(name, []))
            value_vars[name] = {v: tk.BooleanVar(value=(v not in unchecked)) for v in order}
            value_labels[name] = [
                (v, f"{self._format_value_label(v)} ({counts[v]}건)") for v in order
            ]

        def render_values(name):
            for child in inner.winfo_children():
                child.destroy()
            values = value_labels.get(name, [])
            value_count_var.set(f"총 {len(values)}개 항목")

            max_items = 1000
            if len(values) > max_items:
                hidden_count = len(values) - max_items
                notice = (
                    f"항목이 너무 많아 상위 {max_items}개만 화면에 표시합니다.\n"
                    "민감정보 노출 방지를 위해 전체 목록은 파일로 자동 저장하지 않습니다.\n"
                    f"표시하지 않은 항목: {hidden_count}개"
                )
                ttk.Label(inner, text=notice).pack(anchor="w", pady=(0, 8))
                values = values[:max_items]

            for raw, label in values:
                var = value_vars[name][raw]
                cb = ttk.Checkbutton(inner, text=label, variable=var)
                cb.pack(anchor="w")

            canvas.configure(scrollregion=canvas.bbox("all"))

        def on_select(_event=None):
            sel = listbox.curselection()
            if sel:
                name = names[sel[0]]
                category_var.set(name)
                render_values(name)

        listbox.bind("<<ListboxSelect>>", on_select)
        render_values(names[0])

        def on_frame_configure(_event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        inner.bind("<Configure>", on_frame_configure)

        category_frame = ttk.LabelFrame(list_frame, text="카테고리 선택", padding=6)
        category_frame.grid(row=2, column=0, sticky="nsew", pady=(10, 6))
        category_frame.columnconfigure(0, weight=1)
        category_frame.rowconfigure(1, weight=1)

        cat_canvas = tk.Canvas(category_frame, highlightthickness=0)
        cat_scroll = ttk.Scrollbar(category_frame, orient="vertical", command=cat_canvas.yview)
        cat_canvas.configure(yscrollcommand=cat_scroll.set)
        cat_canvas.grid(row=1, column=0, sticky="nsew")
        cat_scroll.grid(row=1, column=1, sticky="ns")

        cat_inner = ttk.Frame(cat_canvas)
        cat_canvas.create_window((0, 0), window=cat_inner, anchor="nw")

        unchecked_categories = set(self.saved_category_unchecked or [])
        category_vars = {name: tk.BooleanVar(value=(name not in unchecked_categories)) for name in names}

        def apply_category(name, state):
            for var in value_vars.get(name, {}).values():
                var.set(state)

        def select_category(name):
            if name in names:
                index = names.index(name)
                listbox.selection_clear(0, "end")
                listbox.selection_set(index)
                listbox.see(index)
                category_var.set(name)
                render_values(name)

        def render_categories():
            for child in cat_inner.winfo_children():
                child.destroy()
            for name in names:
                count = detected[name]["count"]
                var = category_vars[name]
                cb = ttk.Checkbutton(
                    cat_inner,
                    text=f"{name} ({count}건)",
                    variable=var,
                    command=lambda n=name, v=var: (apply_category(n, v.get()), select_category(n)),
                )
                cb.pack(anchor="w")
            cat_canvas.configure(scrollregion=cat_canvas.bbox("all"))

        render_categories()

        def on_cat_frame_configure(_event=None):
            cat_canvas.configure(scrollregion=cat_canvas.bbox("all"))

        cat_inner.bind("<Configure>", on_cat_frame_configure)

        cat_buttons = ttk.Frame(category_frame)
        cat_buttons.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 6))

        def set_all_categories(state):
            for name, var in category_vars.items():
                var.set(state)
                apply_category(name, state)

        ttk.Button(cat_buttons, text="전체 선택", command=lambda: set_all_categories(True)).pack(
            side="left"
        )
        ttk.Button(cat_buttons, text="전체 해제", command=lambda: set_all_categories(False)).pack(
            side="left", padx=(5, 0)
        )

        action_frame = ttk.Frame(container)
        action_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        action_frame.columnconfigure(2, weight=1)

        result: dict[str, Any] = {"selected": None}

        if hasattr(self, "current_theme"):
            theme = self.current_theme
            window.configure(bg=theme["bg"])
            listbox.configure(
                bg=theme["entry_bg"],
                fg=theme["fg"],
                selectbackground=theme["select_bg"],
                selectforeground=theme["fg"],
            )
            canvas.configure(bg=theme["entry_bg"])
            inner.configure(style="TFrame")
            cat_canvas.configure(bg=theme["entry_bg"])
            cat_inner.configure(style="TFrame")

        def select_current(state):
            name = category_var.get()
            for var in value_vars.get(name, {}).values():
                var.set(state)

        def select_all(state):
            for vars_map in value_vars.values():
                for var in vars_map.values():
                    var.set(state)

        def apply_and_close():
            selected = {}
            for name, vars_map in value_vars.items():
                chosen = [val for val, var in vars_map.items() if var.get()]
                if chosen:
                    selected[name] = chosen
            self._persist_sensitive_unchecked(value_vars)
            self._persist_category_unchecked(category_vars)
            result["selected"] = selected
            window.destroy()

        def cancel_and_close():
            self._persist_sensitive_unchecked(value_vars)
            self._persist_category_unchecked(category_vars)
            result["selected"] = None
            window.destroy()

        window.protocol("WM_DELETE_WINDOW", cancel_and_close)
        window.grab_set()

        current_group = ttk.LabelFrame(action_frame, text="현재 항목", padding=(8, 5))
        current_group.grid(row=0, column=0, sticky="w")
        ttk.Button(
            current_group,
            text="전체 선택",
            width=12,
            command=lambda: select_current(True),
        ).pack(side="left")
        ttk.Button(
            current_group,
            text="전체 해제",
            width=12,
            command=lambda: select_current(False),
        ).pack(side="left", padx=(5, 0))

        all_group = ttk.LabelFrame(action_frame, text="모든 항목", padding=(8, 5))
        all_group.grid(row=0, column=1, sticky="w", padx=(10, 0))
        ttk.Button(
            all_group,
            text="전체 선택",
            width=12,
            command=lambda: select_all(True),
        ).pack(side="left")
        ttk.Button(
            all_group,
            text="전체 해제",
            width=12,
            command=lambda: select_all(False),
        ).pack(side="left", padx=(5, 0))

        confirm_group = ttk.Frame(action_frame)
        confirm_group.grid(row=0, column=2, sticky="e", padx=(12, 0))
        ttk.Button(
            confirm_group,
            text="취소",
            width=10,
            command=cancel_and_close,
        ).pack(
            side="left", padx=(5, 0)
        )
        ttk.Button(
            confirm_group,
            text="마스킹 적용",
            width=16,
            command=apply_and_close,
        ).pack(side="left", padx=(5, 0))

        window.wait_window()
        return result["selected"]

    def _persist_sensitive_unchecked(self, value_vars):
        unchecked = {}
        for name, vars_map in value_vars.items():
            unchecked_values = [val for val, var in vars_map.items() if not var.get()]
            if unchecked_values:
                unchecked[name] = unchecked_values
        self.saved_sensitive_unchecked = unchecked

    def _persist_category_unchecked(self, category_vars):
        unchecked = [name for name, var in category_vars.items() if not var.get()]
        self.saved_category_unchecked = unchecked
        self._save_settings()

    def _mask_structured_sensitive(self, text):
        text = self._mask_sensitive_headers(text)
        text = self._mask_sensitive_params(text)
        text = self._mask_sensitive_json(text)
        text = self._mask_sensitive_xml(text)
        text = self._mask_basic_auth_url(text)
        return text

    def _mask_sensitive_headers(self, text):
        def repl(match):
            key = match.group("key")
            value = match.group("value")
            key_lower = key.lower()
            if key_lower not in SENSITIVE_HEADER_KEYS:
                return match.group(0)

            if key_lower in {"authorization", "proxy-authorization"}:
                parts = value.split(None, 1)
                if len(parts) == 2:
                    return f"{key}: {parts[0]} {'*' * len(parts[1])}"

            if key_lower in {"cookie", "set-cookie"}:
                return f"{key}: {self._mask_cookie_values(value)}"

            return f"{key}: {'*' * len(value)}"

        return re.sub(
            r"^(?P<key>[A-Za-z0-9-]+)\s*:\s*(?P<value>.*)$",
            repl,
            text,
            flags=re.MULTILINE,
        )

    def _mask_cookie_values(self, value):
        def repl(match):
            k = match.group(1)
            v = match.group(2)
            return f"{k}={'*' * len(v)}"

        return re.sub(r"([^=;\s]+)=([^;]*)", repl, value)

    def _mask_sensitive_params(self, text):
        for key in SENSITIVE_PARAM_KEYS:
            pattern = re.compile(rf"(?i)(\b{re.escape(key)}\b\s*=\s*)([^&\s\r\n]+)")
            text = pattern.sub(lambda m: m.group(1) + "*" * len(m.group(2)), text)
        return text

    def _mask_sensitive_json(self, text):
        for key in SENSITIVE_PARAM_KEYS:
            pattern = re.compile(rf"(?i)(\"{re.escape(key)}\"\s*:\s*\")([^\"\r\n]*)(\")")
            text = pattern.sub(lambda m: m.group(1) + "*" * len(m.group(2)) + m.group(3), text)
            pattern = re.compile(rf"(?i)('{re.escape(key)}'\s*:\s*')([^'\r\n]*)(')")
            text = pattern.sub(lambda m: m.group(1) + "*" * len(m.group(2)) + m.group(3), text)
            pattern = re.compile(rf"(?i)(\"{re.escape(key)}\"\s*:\s*)([^,\r\n}}\s][^,\r\n}}]*)")
            text = pattern.sub(lambda m: m.group(1) + "*" * len(m.group(2)), text)
            pattern = re.compile(rf"(?i)('{re.escape(key)}'\s*:\s*)([^,\r\n}}\s][^,\r\n}}]*)")
            text = pattern.sub(lambda m: m.group(1) + "*" * len(m.group(2)), text)
        return text

    def _mask_sensitive_xml(self, text):
        for key in SENSITIVE_PARAM_KEYS:
            pattern = re.compile(rf"(?is)(<\s*{re.escape(key)}\s*>)([^<]*)(</\s*{re.escape(key)}\s*>)")
            text = pattern.sub(lambda m: m.group(1) + "*" * len(m.group(2)) + m.group(3), text)
        return text

    def _mask_basic_auth_url(self, text):
        return re.sub(
            r"(?i)(https?://)([^/\s:@]+):([^/\s@]+)@",
            lambda m: f"{m.group(1)}{m.group(2)}:{'*' * len(m.group(3))}@",
            text,
        )

    def _format_remaining_notice(self, details, auto_masked=False):
        detected = self._summarize_sensitive_raw(details)
        if not detected:
            return ""
        summary_lines = []
        for name, info in detected.items():
            summary_lines.append(f"- {name}: {info['count']}건")
            samples = info.get("samples", [])
            if samples:
                summary_lines.append(f"  예시: {', '.join(samples)}")
        summary = "\n".join(summary_lines)
        if auto_masked:
            header = "자동 마스킹 후에도 일부 민감정보가 남아 있을 수 있습니다."
        else:
            header = "마스킹 후에도 일부 민감정보가 남아 있을 수 있습니다."
        return f"{header}\n\n{summary}"

    def _mask_sensitive_patterns(self, text, selected_values=None):
        if selected_values is None:
            selected_values = self._collect_sensitive_details_raw(text)

        masked = text
        for _, values in selected_values.items():
            for v in values:
                if not v:
                    continue
                masked = re.sub(re.escape(v), lambda m: "*" * len(m.group(0)), masked)
        return masked


if __name__ == "__main__":
    app = SecurePromptMaskerApp()
    app.mainloop()
