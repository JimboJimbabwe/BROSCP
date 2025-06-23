import os
import argparse
import tkinter as tk
from tkinter import ttk
from pathlib import Path

class TextFileViewer:
    def __init__(self, root, folder_path):
        self.root = root
        self.root.title("Text File Viewer")
        self.folder_path = folder_path
        
        # Get all text files in the folder
        self.text_files = [f for f in os.listdir(folder_path) if f.endswith('.txt')]
        self.current_index = 0 if self.text_files else -1
        
        # Configure main window
        self.root.geometry("1000x600")
        self.root.columnconfigure(0, weight=1)
        self.root.columnconfigure(1, weight=3)
        self.root.rowconfigure(0, weight=1)
        
        # Create file list frame
        list_frame = ttk.Frame(root, padding="10")
        list_frame.grid(row=0, column=0, sticky="nsew")
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=0)
        list_frame.rowconfigure(1, weight=1)
        
        # Create file list
        ttk.Label(list_frame, text="Text Files:").grid(row=0, column=0, sticky="w")
        self.file_listbox = tk.Listbox(list_frame)
        self.file_listbox.grid(row=1, column=0, sticky="nsew")
        self.file_listbox.bind('<<ListboxSelect>>', self.on_file_select)
        
        # Add scrollbar to list
        list_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.file_listbox.yview)
        list_scrollbar.grid(row=1, column=1, sticky="ns")
        self.file_listbox.configure(yscrollcommand=list_scrollbar.set)
        
        # Populate file list
        for file in self.text_files:
            self.file_listbox.insert(tk.END, file)
        
        # Create content frame
        content_frame = ttk.Frame(root, padding="10")
        content_frame.grid(row=0, column=1, sticky="nsew")
        content_frame.columnconfigure(0, weight=1)
        content_frame.rowconfigure(0, weight=0)
        content_frame.rowconfigure(1, weight=1)
        content_frame.rowconfigure(2, weight=0)
        
        # Create file title label
        self.title_label = ttk.Label(content_frame, text="", font=("TkDefaultFont", 12, "bold"))
        self.title_label.grid(row=0, column=0, sticky="w")
        
        # Create content text area
        self.content_text = tk.Text(content_frame, wrap=tk.WORD)
        self.content_text.grid(row=1, column=0, sticky="nsew")
        
        # Add scrollbar to content
        content_scrollbar = ttk.Scrollbar(content_frame, orient="vertical", command=self.content_text.yview)
        content_scrollbar.grid(row=1, column=1, sticky="ns")
        self.content_text.configure(yscrollcommand=content_scrollbar.set)
        
        # Create navigation buttons
        nav_frame = ttk.Frame(content_frame)
        nav_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        nav_frame.columnconfigure(0, weight=1)
        nav_frame.columnconfigure(1, weight=1)
        
        self.prev_button = ttk.Button(nav_frame, text="Previous", command=self.show_previous)
        self.prev_button.grid(row=0, column=0, sticky="w")
        
        self.next_button = ttk.Button(nav_frame, text="Next", command=self.show_next)
        self.next_button.grid(row=0, column=1, sticky="e")
        
        # Load first file if available
        if self.current_index >= 0:
            self.file_listbox.selection_set(self.current_index)
            self.load_file(self.text_files[self.current_index])
        
    def load_file(self, filename):
        """Load the content of a file into the text area"""
        file_path = os.path.join(self.folder_path, filename)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.title_label.config(text=filename)
            self.content_text.delete(1.0, tk.END)
            self.content_text.insert(tk.END, content)
        except Exception as e:
            self.content_text.delete(1.0, tk.END)
            self.content_text.insert(tk.END, f"Error loading file: {str(e)}")
    
    def on_file_select(self, event):
        """Handle file selection from the listbox"""
        selection = self.file_listbox.curselection()
        if selection:
            self.current_index = selection[0]
            self.load_file(self.text_files[self.current_index])
    
    def show_next(self):
        """Show the next file in the list"""
        if not self.text_files:
            return
            
        self.current_index = (self.current_index + 1) % len(self.text_files)
        self.file_listbox.selection_clear(0, tk.END)
        self.file_listbox.selection_set(self.current_index)
        self.file_listbox.see(self.current_index)
        self.load_file(self.text_files[self.current_index])
    
    def show_previous(self):
        """Show the previous file in the list"""
        if not self.text_files:
            return
            
        self.current_index = (self.current_index - 1) % len(self.text_files)
        self.file_listbox.selection_clear(0, tk.END)
        self.file_listbox.selection_set(self.current_index)
        self.file_listbox.see(self.current_index)
        self.load_file(self.text_files[self.current_index])

def main():
    parser = argparse.ArgumentParser(description='View text files in a folder')
    parser.add_argument('--folder', '-f', required=True, help='Path to folder containing text files')
    args = parser.parse_args()
    
    folder_path = Path(args.folder)
    
    if not folder_path.exists() or not folder_path.is_dir():
        print(f"Error: {folder_path} is not a valid directory")
        return
    
    root = tk.Tk()
    app = TextFileViewer(root, str(folder_path))
    root.mainloop()

if __name__ == "__main__":
    main()
