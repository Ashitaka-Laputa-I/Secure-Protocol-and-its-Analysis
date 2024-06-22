import tkinter as tk
from tkinter import ttk, messagebox
from ttkbootstrap import Style
from threading import Thread
import time
from protocol_analysis import protocol_analysis

def analyze_protocol(progress_var, result_text, analyze_button):
    """Function to run protocol analysis in a separate thread."""
    try:
        analyze_button.config(state=tk.DISABLED)
        protocol_analysis(progress_var, result_text)
    finally:
        analyze_button.config(state=tk.NORMAL)

def simulate_progress(progress_var):
    """Simulate progress and update progress bar."""
    for i in range(101):
        progress_var.set(i)
        time.sleep(0.03)  # Adjust sleep time for smoother progress bar update

def update_progress(progress_var, root):
    """Update progress bar until the task is complete."""
    if progress_var.get() < 100:
        progress_var.set(progress_var.get() + 1)
        root.after(30, update_progress, progress_var, root)

def create_gui():
    root = tk.Tk()
    root.title("安全协议分析")  # Security Protocol Analysis
    root.geometry("950x500")  # Adjusted size for a more spacious layout

    # Apply a themed style from ttkbootstrap
    style = Style(theme="superhero")  # Keeping your chosen theme

    main_frame = ttk.Frame(root, padding=(20, 20, 20, 20))
    main_frame.pack(fill=tk.BOTH, expand=True)

    # Progress bar
    progress_var = tk.DoubleVar()
    progress_bar = ttk.Progressbar(main_frame, variable=progress_var, length=700, mode='determinate', style='blue.Horizontal.TProgressbar')
    progress_bar.grid(row=0, column=0, columnspan=2, padx=10, pady=20)

    # Result text area with scrollbar
    result_text = tk.Text(main_frame, wrap=tk.WORD, height=15, width=80, bg='#f0f0f0', font=("Arial", 14), fg="black")
    result_text.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
    scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=result_text.yview)
    scrollbar.grid(row=1, column=2, sticky='ns')
    result_text.config(yscrollcommand=scrollbar.set)

    # Add tags for different stages
    result_text.tag_config('info', foreground='blue')
    result_text.tag_config('success', foreground='green')
    result_text.tag_config('error', foreground='red')
    result_text.tag_config('highlight', background='yellow', foreground='black')

    def start_analysis():
        """Start protocol analysis in a separate thread."""
        analyze_button.config(state=tk.DISABLED)  # Disable button during analysis
        thread = Thread(target=analyze_protocol, args=(progress_var, result_text, analyze_button))
        thread.start()
        # Simulate progress
        simulate_thread = Thread(target=simulate_progress, args=(progress_var,))
        simulate_thread.start()
        # Update progress bar dynamically
        update_progress(progress_var, root)

    # Start analysis button
    analyze_button = ttk.Button(main_frame, text="开始协议分析", command=start_analysis)
    analyze_button.grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)

    # Exit button
    exit_button = ttk.Button(main_frame, text="退出", command=root.destroy)
    exit_button.grid(row=2, column=1, padx=10, pady=10, sticky=tk.E)

    root.mainloop()
