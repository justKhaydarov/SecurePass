#!/usr/bin/env python3
"""
SecurePass GUI - Graphical User Interface using Tkinter
Intelligent Password Security Analyzer
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from typing import Optional

from securepass.analyzer import PasswordAnalyzer
from securepass.dictionary_checker import DictionaryChecker
from securepass.hasher import PasswordHasher, BCRYPT_AVAILABLE
from securepass.cracker import PasswordCracker
from securepass.policy import PasswordPolicy, PolicyLevel
from securepass.report import SecurityReportGenerator


class SecurePassGUI:
    """Main GUI application for SecurePass."""
    
    def __init__(self):
        """Initialize the GUI."""
        self.root = tk.Tk()
        self.root.title("SecurePass - Password Security Analyzer")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Initialize components (lazy load heavy ones)
        self.analyzer = PasswordAnalyzer()
        self._dict_checker = None  # Lazy load
        self._hasher = None  # Lazy load
        self.policy = PasswordPolicy(PolicyLevel.STANDARD)
        self.report_generator = None  # Lazy load
        
        # Variables
        self.password_var = tk.StringVar()
        self.show_password_var = tk.BooleanVar(value=False)
        self.policy_level_var = tk.StringVar(value="standard")
        
        # Debounce timer for delayed analysis
        self._debounce_timer = None
        self._debounce_delay = 300  # milliseconds
        
        # Cache for analysis results
        self._last_password = ""
        self._cached_analysis = None
        
        # Configure style
        self.setup_style()
        
        # Create UI
        self.create_widgets()
        
        # Bind events
        self.password_var.trace('w', self.on_password_change)
    
    @property
    def dict_checker(self):
        """Lazy load dictionary checker."""
        if self._dict_checker is None:
            self._dict_checker = DictionaryChecker()
        return self._dict_checker
    
    @property
    def hasher(self):
        """Lazy load hasher."""
        if self._hasher is None:
            self._hasher = PasswordHasher()
        return self._hasher
    
    def setup_style(self):
        """Configure ttk styles."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Custom colors
        style.configure('TFrame', background='#f5f5f5')
        style.configure('TLabel', background='#f5f5f5', font=('Helvetica', 10))
        style.configure('TButton', font=('Helvetica', 10))
        style.configure('Header.TLabel', font=('Helvetica', 14, 'bold'))
        style.configure('Title.TLabel', font=('Helvetica', 20, 'bold'), foreground='#2196F3')
        style.configure('Score.TLabel', font=('Helvetica', 36, 'bold'))
        
        # Progress bar styles
        style.configure("red.Horizontal.TProgressbar", troughcolor='#e0e0e0', background='#f44336')
        style.configure("orange.Horizontal.TProgressbar", troughcolor='#e0e0e0', background='#ff9800')
        style.configure("yellow.Horizontal.TProgressbar", troughcolor='#e0e0e0', background='#ffeb3b')
        style.configure("green.Horizontal.TProgressbar", troughcolor='#e0e0e0', background='#4caf50')
    
    def create_widgets(self):
        """Create all GUI widgets."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        
        # Title
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        title_label = ttk.Label(title_frame, text="🔐 SecurePass", style='Title.TLabel')
        title_label.pack()
        
        subtitle_label = ttk.Label(title_frame, text="Intelligent Password Security Analyzer")
        subtitle_label.pack()
        
        # Password Input Section
        input_frame = ttk.LabelFrame(main_frame, text="Password Input", padding="10")
        input_frame.grid(row=1, column=0, sticky="ew", pady=5)
        input_frame.columnconfigure(0, weight=1)
        
        # Password entry
        password_frame = ttk.Frame(input_frame)
        password_frame.grid(row=0, column=0, sticky="ew")
        password_frame.columnconfigure(0, weight=1)
        
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var,
                                        font=('Courier', 12), show='•')
        self.password_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        
        # Bind Ctrl+A to select all
        self.password_entry.bind('<Control-a>', self._select_all)
        self.password_entry.bind('<Control-A>', self._select_all)
        
        show_btn = ttk.Checkbutton(password_frame, text="Show", variable=self.show_password_var,
                                   command=self.toggle_password_visibility)
        show_btn.grid(row=0, column=1)
        
        # Policy selection
        policy_frame = ttk.Frame(input_frame)
        policy_frame.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        
        ttk.Label(policy_frame, text="Policy Level:").pack(side=tk.LEFT)
        
        for level in ['basic', 'standard', 'strong', 'enterprise']:
            ttk.Radiobutton(policy_frame, text=level.capitalize(),
                          variable=self.policy_level_var, value=level,
                          command=self.on_policy_change).pack(side=tk.LEFT, padx=5)
        
        # Strength Meter
        meter_frame = ttk.LabelFrame(main_frame, text="Password Strength", padding="10")
        meter_frame.grid(row=2, column=0, sticky="ew", pady=5)
        meter_frame.columnconfigure(0, weight=1)
        
        # Score display
        score_frame = ttk.Frame(meter_frame)
        score_frame.grid(row=0, column=0, sticky="ew")
        
        self.score_label = ttk.Label(score_frame, text="0", style='Score.TLabel')
        self.score_label.pack(side=tk.LEFT)
        
        self.strength_label = ttk.Label(score_frame, text="Enter a password", font=('Helvetica', 14))
        self.strength_label.pack(side=tk.LEFT, padx=20)
        
        # Progress bar
        self.strength_bar = ttk.Progressbar(meter_frame, length=400, mode='determinate',
                                           style="green.Horizontal.TProgressbar")
        self.strength_bar.grid(row=1, column=0, sticky="ew", pady=10)
        
        # Time to crack
        self.crack_time_label = ttk.Label(meter_frame, text="Time to crack: -")
        self.crack_time_label.grid(row=2, column=0, sticky="w")
        
        # Notebook for detailed results
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=3, column=0, sticky="nsew", pady=5)
        main_frame.rowconfigure(3, weight=1)
        
        # Analysis Tab
        analysis_frame = ttk.Frame(notebook, padding="10")
        notebook.add(analysis_frame, text="Analysis")
        self.create_analysis_tab(analysis_frame)
        
        # Dictionary Check Tab
        dict_frame = ttk.Frame(notebook, padding="10")
        notebook.add(dict_frame, text="Dictionary Check")
        self.create_dictionary_tab(dict_frame)
        
        # Hash Demo Tab
        hash_frame = ttk.Frame(notebook, padding="10")
        notebook.add(hash_frame, text="Hash Demo")
        self.create_hash_tab(hash_frame)
        
        # Policy Tab
        policy_tab_frame = ttk.Frame(notebook, padding="10")
        notebook.add(policy_tab_frame, text="Policy Check")
        self.create_policy_tab(policy_tab_frame)
        
        # Crack Demo Tab
        crack_frame = ttk.Frame(notebook, padding="10")
        notebook.add(crack_frame, text="Crack Demo")
        self.create_crack_tab(crack_frame)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, sticky="ew", pady=10)
        
        ttk.Button(button_frame, text="Generate Report", command=self.generate_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="About", command=self.show_about).pack(side=tk.RIGHT, padx=5)
    
    def create_analysis_tab(self, parent):
        """Create the analysis tab content."""
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        
        # Character types
        char_frame = ttk.LabelFrame(parent, text="Character Types", padding="5")
        char_frame.grid(row=0, column=0, sticky="ew", pady=5)
        
        self.char_labels = {}
        char_types = [
            ('lowercase', 'Lowercase (a-z)'),
            ('uppercase', 'Uppercase (A-Z)'),
            ('digits', 'Digits (0-9)'),
            ('special', 'Special (!@#$...)')
        ]
        
        for i, (key, text) in enumerate(char_types):
            frame = ttk.Frame(char_frame)
            frame.grid(row=0, column=i, padx=10, pady=5)
            
            self.char_labels[key] = ttk.Label(frame, text="✗", foreground="gray")
            self.char_labels[key].pack()
            ttk.Label(frame, text=text).pack()
        
        # Details
        details_frame = ttk.LabelFrame(parent, text="Details", padding="5")
        details_frame.grid(row=1, column=0, sticky="nsew", pady=5)
        details_frame.columnconfigure(0, weight=1)
        details_frame.rowconfigure(0, weight=1)
        
        self.analysis_text = tk.Text(details_frame, height=10, wrap=tk.WORD,
                                     font=('Courier', 10), state='disabled')
        scrollbar = ttk.Scrollbar(details_frame, orient="vertical", command=self.analysis_text.yview)
        self.analysis_text.configure(yscrollcommand=scrollbar.set)
        
        self.analysis_text.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
    
    def create_dictionary_tab(self, parent):
        """Create the dictionary check tab."""
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        
        self.dict_text = tk.Text(parent, height=15, wrap=tk.WORD,
                                 font=('Courier', 10), state='disabled')
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.dict_text.yview)
        self.dict_text.configure(yscrollcommand=scrollbar.set)
        
        self.dict_text.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
    
    def create_hash_tab(self, parent):
        """Create the hash demonstration tab."""
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        
        self.hash_text = tk.Text(parent, height=15, wrap=tk.WORD,
                                 font=('Courier', 10), state='disabled')
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.hash_text.yview)
        self.hash_text.configure(yscrollcommand=scrollbar.set)
        
        self.hash_text.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
    
    def create_policy_tab(self, parent):
        """Create the policy validation tab."""
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        
        # Requirements
        req_frame = ttk.LabelFrame(parent, text="Policy Requirements", padding="5")
        req_frame.grid(row=0, column=0, sticky="ew", pady=5)
        
        self.requirements_label = ttk.Label(req_frame, text="", justify=tk.LEFT)
        self.requirements_label.pack(anchor="w")
        
        # Results
        results_frame = ttk.LabelFrame(parent, text="Validation Results", padding="5")
        results_frame.grid(row=1, column=0, sticky="nsew", pady=5)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        self.policy_text = tk.Text(results_frame, height=10, wrap=tk.WORD,
                                   font=('Courier', 10), state='disabled')
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.policy_text.yview)
        self.policy_text.configure(yscrollcommand=scrollbar.set)
        
        self.policy_text.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
    
    def create_crack_tab(self, parent):
        """Create the crack demonstration tab."""
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        
        # Warning
        warning_frame = ttk.Frame(parent)
        warning_frame.grid(row=0, column=0, sticky="ew", pady=5)
        
        warning_label = ttk.Label(warning_frame, text="⚠️ EDUCATIONAL DEMONSTRATION ONLY",
                                 font=('Helvetica', 12, 'bold'), foreground='#ff9800')
        warning_label.pack()
        
        ttk.Label(warning_frame, text="This demonstrates how weak passwords can be cracked.").pack()
        
        # Controls
        control_frame = ttk.Frame(parent)
        control_frame.grid(row=1, column=0, sticky="ew", pady=5)
        
        ttk.Label(control_frame, text="Hash Type:").pack(side=tk.LEFT)
        self.crack_hash_var = tk.StringVar(value="md5")
        hash_combo = ttk.Combobox(control_frame, textvariable=self.crack_hash_var,
                                  values=['md5', 'sha256', 'bcrypt'], state='readonly', width=10)
        hash_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="Run Demo", command=self.run_crack_demo).pack(side=tk.LEFT, padx=5)
        
        # Results
        results_frame = ttk.Frame(parent)
        results_frame.grid(row=2, column=0, sticky="nsew", pady=5)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        parent.rowconfigure(2, weight=1)
        
        self.crack_text = tk.Text(results_frame, height=15, wrap=tk.WORD,
                                  font=('Courier', 10), state='disabled')
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.crack_text.yview)
        self.crack_text.configure(yscrollcommand=scrollbar.set)
        
        self.crack_text.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
    
    def toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.show_password_var.get():
            self.password_entry.config(show='')
        else:
            self.password_entry.config(show='•')
    
    def _select_all(self, event):
        """Select all text in the password entry."""
        self.password_entry.select_range(0, tk.END)
        self.password_entry.icursor(tk.END)
        return 'break'  # Prevent default behavior
    
    def on_password_change(self, *args):
        """Handle password input changes with debouncing."""
        # Cancel previous timer
        if self._debounce_timer:
            self.root.after_cancel(self._debounce_timer)
        
        # Quick visual feedback (instant)
        password = self.password_var.get()
        if password:
            # Fast preview - just update the basic meter
            self._quick_update(password)
        else:
            self.reset_displays()
            return
        
        # Schedule full analysis after delay
        self._debounce_timer = self.root.after(self._debounce_delay, self._run_full_analysis)
    
    def _quick_update(self, password: str):
        """Quick visual update - show analyzing state."""
        # Show analyzing indicator instead of fake score
        self.strength_label.config(text="Analyzing...")
    
    def _run_full_analysis(self):
        """Run full analysis (called after debounce delay)."""
        password = self.password_var.get()
        if password:
            self.update_analysis(password)
    
    def on_policy_change(self):
        """Handle policy level change."""
        level_map = {
            'basic': PolicyLevel.BASIC,
            'standard': PolicyLevel.STANDARD,
            'strong': PolicyLevel.STRONG,
            'enterprise': PolicyLevel.ENTERPRISE
        }
        self.policy = PasswordPolicy(level_map[self.policy_level_var.get()])
        self.requirements_label.config(text=self.policy.get_requirements_text())
        
        # Re-run analysis only if there's a password
        password = self.password_var.get()
        if password:
            # Only update policy tab
            policy_result = self.policy.validate(password)
            self.update_text_widget(self.policy_text, self.format_policy(policy_result))
    
    def update_analysis(self, password: str):
        """Update all analysis displays."""
        if not password:
            self.reset_displays()
            return
        
        # Skip if same password (use cache)
        if password == self._last_password and self._cached_analysis:
            return
        
        self._last_password = password
        
        # Password Analysis (fast - run on main thread)
        analysis = self.analyzer.analyze(password)
        self._cached_analysis = analysis
        
        # Update strength meter
        self.score_label.config(text=str(analysis.strength_score))
        self.strength_label.config(text=analysis.strength_label)
        self.strength_bar['value'] = analysis.strength_score
        self.crack_time_label.config(text=f"Time to crack: {analysis.time_to_crack}")
        
        # Update progress bar color
        if analysis.strength_score < 20:
            self.strength_bar.config(style="red.Horizontal.TProgressbar")
        elif analysis.strength_score < 40:
            self.strength_bar.config(style="orange.Horizontal.TProgressbar")
        elif analysis.strength_score < 60:
            self.strength_bar.config(style="yellow.Horizontal.TProgressbar")
        else:
            self.strength_bar.config(style="green.Horizontal.TProgressbar")
        
        # Update character type indicators
        self.char_labels['lowercase'].config(
            text="✓" if analysis.has_lowercase else "✗",
            foreground="green" if analysis.has_lowercase else "red"
        )
        self.char_labels['uppercase'].config(
            text="✓" if analysis.has_uppercase else "✗",
            foreground="green" if analysis.has_uppercase else "red"
        )
        self.char_labels['digits'].config(
            text="✓" if analysis.has_digits else "✗",
            foreground="green" if analysis.has_digits else "red"
        )
        self.char_labels['special'].config(
            text="✓" if analysis.has_special else "✗",
            foreground="green" if analysis.has_special else "red"
        )
        
        # Update analysis text (fast)
        self.update_text_widget(self.analysis_text, self.format_analysis(analysis))
        
        # Update policy check (fast)
        policy_result = self.policy.validate(password)
        self.update_text_widget(self.policy_text, self.format_policy(policy_result))
        
        # Run heavy operations in background threads
        threading.Thread(target=self._update_dictionary_check, args=(password,), daemon=True).start()
        threading.Thread(target=self._update_hash_demo, args=(password,), daemon=True).start()
    
    def _update_dictionary_check(self, password: str):
        """Update dictionary check in background thread."""
        try:
            dict_result = self.dict_checker.full_check(password)
            formatted = self.format_dict_check(dict_result)
            # Update UI on main thread
            self.root.after(0, lambda: self.update_text_widget(self.dict_text, formatted))
        except Exception:
            pass
    
    def _update_hash_demo(self, password: str):
        """Update hash demo in background thread."""
        try:
            hash_results = self.hasher.hash_all(password)
            formatted = self.format_hashes(hash_results)
            # Update UI on main thread
            self.root.after(0, lambda: self.update_text_widget(self.hash_text, formatted))
        except Exception:
            pass
    
    def update_text_widget(self, widget, text: str):
        """Update a text widget with new content."""
        widget.config(state='normal')
        widget.delete(1.0, tk.END)
        widget.insert(1.0, text)
        widget.config(state='disabled')
    
    def format_analysis(self, analysis) -> str:
        """Format analysis results for display."""
        lines = []
        lines.append(f"Length: {analysis.password_length} characters")
        lines.append(f"Character Set Size: {analysis.charset_size}")
        lines.append(f"Entropy: {analysis.entropy:.2f} bits")
        lines.append(f"Strength Score: {analysis.strength_score}/100")
        lines.append(f"Strength Label: {analysis.strength_label}")
        lines.append("")
        
        if analysis.weaknesses:
            lines.append("⚠ Weaknesses:")
            for weakness in analysis.weaknesses:
                lines.append(f"  • {weakness}")
            lines.append("")
        
        if analysis.recommendations:
            lines.append("💡 Recommendations:")
            for rec in analysis.recommendations:
                lines.append(f"  • {rec}")
        
        return "\n".join(lines)
    
    def format_dict_check(self, result: dict) -> str:
        """Format dictionary check results."""
        lines = []
        lines.append(f"Risk Level: {result['risk_level'].upper()}")
        lines.append("")
        
        if result['is_common_password']:
            lines.append("⚠ CRITICAL: This password is in the common passwords list!")
            lines.append("")
        
        if result['contains_dictionary_words']:
            lines.append("⚠ Contains dictionary words:")
            for word in result['dictionary_words_found']:
                lines.append(f"  • {word}")
            lines.append("")
        
        if result['is_variation']:
            lines.append("⚠ Appears to be a variation of common passwords:")
            for var in result['variations_found']:
                lines.append(f"  • {var}")
            lines.append("")
        
        if result['warnings']:
            lines.append("Warnings:")
            for warning in result['warnings']:
                lines.append(f"  • {warning}")
        
        if not result['is_common_password'] and not result['contains_dictionary_words']:
            lines.append("✓ No dictionary-based issues detected")
        
        return "\n".join(lines)
    
    def format_hashes(self, results: dict) -> str:
        """Format hash demonstration results."""
        lines = []
        lines.append("Hash Demonstration")
        lines.append("=" * 50)
        lines.append("")
        
        for algo, result in results.items():
            lines.append(f"{result.algorithm}:")
            lines.append(f"  Hash: {result.hash_value}")
            if result.salt:
                lines.append(f"  Salt: {result.salt}")
            lines.append(f"  Time: {result.time_taken * 1000:.4f} ms")
            lines.append(f"  Secure: {'Yes ✓' if result.is_secure else 'No ✗'}")
            lines.append(f"  Note: {result.notes}")
            lines.append("")
        
        lines.append("=" * 50)
        lines.append("💡 Tip: Always use bcrypt for password storage!")
        
        return "\n".join(lines)
    
    def format_policy(self, result) -> str:
        """Format policy validation results."""
        lines = []
        
        status = "PASSED ✓" if result.passed else "FAILED ✗"
        lines.append(f"Policy Compliance: {status}")
        lines.append(f"Policy Score: {result.score}/100")
        lines.append("")
        lines.append("ℹ️  Note: Policy Score measures compliance with the selected")
        lines.append("    policy rules (e.g., length, character requirements).")
        lines.append("    This is different from the overall Strength Score above.")
        lines.append("")
        
        if result.passed_rules:
            lines.append("✓ Passed Rules:")
            for rule in result.passed_rules:
                lines.append(f"  • {rule}")
            lines.append("")
        
        if result.failed_rules:
            lines.append("✗ Failed Rules:")
            for rule in result.failed_rules:
                lines.append(f"  • {rule}")
            lines.append("")
        
        if result.recommendations:
            lines.append("💡 Recommendations:")
            for rec in result.recommendations:
                lines.append(f"  • {rec}")
        
        return "\n".join(lines)
    
    def reset_displays(self):
        """Reset all displays to default state."""
        self.score_label.config(text="0")
        self.strength_label.config(text="Enter a password")
        self.strength_bar['value'] = 0
        self.crack_time_label.config(text="Time to crack: -")
        
        for label in self.char_labels.values():
            label.config(text="✗", foreground="gray")
        
        for widget in [self.analysis_text, self.dict_text, self.hash_text, 
                       self.policy_text, self.crack_text]:
            self.update_text_widget(widget, "")
    
    def run_crack_demo(self):
        """Run the cracking demonstration in a separate thread."""
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("No Password", "Please enter a password first.")
            return
        
        hash_type = self.crack_hash_var.get()
        
        self.update_text_widget(self.crack_text, "Running crack demonstration...\nThis may take a moment...")
        
        def crack_thread():
            cracker = PasswordCracker()
            result = cracker.demonstrate_crack(password, hash_type)
            self.root.after(0, lambda: self.update_text_widget(self.crack_text, result))
        
        threading.Thread(target=crack_thread, daemon=True).start()
    
    def generate_report(self):
        """Generate and save a security report."""
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("No Password", "Please enter a password first.")
            return
        
        # Ask for file format
        format_choice = tk.StringVar(value="html")
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Generate Report")
        dialog.geometry("300x150")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Select report format:", font=('Helvetica', 11)).pack(pady=10)
        
        for fmt in [('HTML', 'html'), ('Text', 'text'), ('JSON', 'json')]:
            ttk.Radiobutton(dialog, text=fmt[0], variable=format_choice, value=fmt[1]).pack()
        
        def save_report():
            dialog.destroy()
            
            extensions = {'html': '.html', 'text': '.txt', 'json': '.json'}
            ext = extensions[format_choice.get()]
            
            filepath = filedialog.asksaveasfilename(
                defaultextension=ext,
                filetypes=[(f"{format_choice.get().upper()} files", f"*{ext}"), ("All files", "*.*")],
                initialfile=f"securepass_report{ext}"
            )
            
            if filepath:
                try:
                    from securepass.report import generate_security_report
                    generate_security_report(
                        password,
                        output_path=filepath,
                        format=format_choice.get(),
                        policy_level=self.policy_level_var.get(),
                        include_hashes=True
                    )
                    messagebox.showinfo("Success", f"Report saved to:\n{filepath}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save report:\n{str(e)}")
        
        ttk.Button(dialog, text="Save", command=save_report).pack(pady=15)
    
    def clear_all(self):
        """Clear all inputs and results."""
        self.password_var.set("")
        self.reset_displays()
    
    def show_about(self):
        """Show about dialog."""
        about_text = """SecurePass - Intelligent Password Security Analyzer

Version: 1.0.0

Features:
• Password strength analysis
• Entropy calculation
• Dictionary & common password checks
• Hash demonstrations (MD5, SHA-256, bcrypt)
• Policy validation
• Cracking demonstrations (educational)
• Security report generation

⚠️ This tool is for educational purposes.
Always use strong, unique passwords and
enable two-factor authentication."""
        
        messagebox.showinfo("About SecurePass", about_text)
    
    def run(self):
        """Start the GUI application."""
        # Initialize requirements label
        self.requirements_label.config(text=self.policy.get_requirements_text())
        
        # Center window
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
        self.root.mainloop()


def main():
    """Main entry point for GUI."""
    app = SecurePassGUI()
    app.run()


if __name__ == '__main__':
    main()
