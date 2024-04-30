import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import font
import psutil
import time

class TaskManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Task Manager")
        self.root.configure(background='#333333')

        self.setup_style()

        # Main frame
        main_frame = ttk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Search bar at the top
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(main_frame, textvariable=self.search_var, font=("Helvetica", 12))
        self.search_entry.pack(side=tk.TOP, fill=tk.X)
        self.search_entry.bind("<Return>", lambda event: self.filter_processes())
        ttk.Button(main_frame, text="Search", command=self.filter_processes).pack(side=tk.TOP, fill=tk.X, pady=5)

        # Listbox for displaying selected processes
        self.selected_list = tk.Listbox(main_frame, width=50, height=8, bg='#505050', fg='white', font=("Helvetica", 12))
        self.selected_list.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

        # Process treeview
        self.tree = ttk.Treeview(main_frame, columns=('PID', 'Name', 'Memory', 'User'), show='headings')
        self.setup_treeview()

        # Scrollbar for the treeview
        scrollbar = ttk.Scrollbar(main_frame, orient='vertical', command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill='y')
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=5)

        # Button frame at the bottom
        button_frame = ttk.Frame(root)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X)
        self.setup_buttons(button_frame)

        self.update_processes()

    def filter_processes(self):
        filter_text = self.search_var.get().lower()
        matches = []
        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            if filter_text in values[1].lower():
                matches.append(item)

        if matches:
            self.tree.selection_set(matches[0])
            self.tree.see(matches[0])

    def setup_style(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Treeview', background='#222222', foreground='white', fieldbackground='#333333')
        style.configure('Treeview.Heading', background='#333333', foreground='white')
        style.configure('TButton', background='#404040', foreground='white', font=("Helvetica", 12))
        style.map('TButton', background=[('active', '#555555')])

    def setup_treeview(self):
        self.tree.heading('PID', text='PID', anchor='center')
        self.tree.heading('Name', text='Name', anchor='center')
        self.tree.heading('Memory', text='Memory (MB)', anchor='center')
        self.tree.heading('User', text='User', anchor='center')
        self.tree.column('PID', width=50, anchor='center')
        self.tree.column('Name', width=200, anchor='center')
        self.tree.column('Memory', width=100, anchor='center')
        self.tree.column('User', width=150, anchor='center')

    def setup_buttons(self, frame):
        ttk.Button(frame, text="End Task", command=self.end_task).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(frame, text="Refresh Processes", command=self.update_processes).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(frame, text="Select Process", command=self.select_process).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(frame, text="Process FIFO", command=lambda: self.process_selected('FIFO')).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(frame, text="Process LIFO", command=lambda: self.process_selected('LIFO')).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(frame, text="FIFO vs LIFO Comparison", command=self.compare_fifo_lifo).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(frame, text="Remove Selected Process", command=self.remove_selected_process).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(frame, text="Clear", command=self.clear_selections).pack(side=tk.LEFT, fill=tk.X, expand=True)

    def update_processes(self):
        self.tree.delete(*self.tree.get_children())
        for process in self.get_processes():
            memory_text = f"{round(process['memory'], 2)} MB"
            self.tree.insert('', tk.END, values=(process['pid'], process['name'], memory_text, process['user']))

    def get_processes(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'username']):
            try:
                memory = proc.memory_info().rss / 1024 ** 2  # Convert to MB
                processes.append({
                    'pid': proc.pid,
                    'name': proc.name(),
                    'memory': memory,
                    'user': proc.username()
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return processes

    def end_task(self):
        selected = self.tree.selection()
        if selected:
            process_info = self.tree.item(selected, 'values')
            pid = int(process_info[0])
            try:
                psutil.Process(pid).terminate()
                messagebox.showinfo("End Task", f"Process {pid} has been terminated.")
                self.update_processes()
            except psutil.NoSuchProcess:
                messagebox.showerror("Error", "The process does not exist.")
            except psutil.AccessDenied:
                messagebox.showerror("Error", "Access denied to terminate the process.")

    def select_process(self):
        for item in self.tree.selection():
            process = self.tree.item(item)['values']
            process_str = f"{process[1]} - PID: {process[0]} - Memory: {process[2]} MB"
            if process_str not in self.selected_list.get(0, tk.END):
                self.selected_list.insert(tk.END, process_str)

    def remove_selected_process(self):
        selected = self.selected_list.curselection()
        if selected:
            self.selected_list.delete(selected)

    def process_selected(self, method):
        if method == 'FIFO':
            if self.selected_list.size() > 0:
                self.selected_list.delete(0)
        elif method == 'LIFO':
            if self.selected_list.size() > 0:
                self.selected_list.delete(self.selected_list.size() - 1)
                
    def process_lists(self,comparison_window,fifo_list, lifo_list):
    # Procesa la lista FIFO
        while fifo_list.size() > 0:
            fifo_list.delete(0)
            time.sleep(2)
            comparison_window.update()  # Actualiza la ventana para reflejar los cambios

        # Procesa la lista LIFO
        while lifo_list.size() > 0:
            lifo_list.delete(lifo_list.size() - 1)
            time.sleep(2)
            comparison_window.update()

    def compare_fifo_lifo(self):
        comparison_window = tk.Toplevel(self.root)
        comparison_window.title("FIFO vs LIFO Comparison")
        fifo_frame = ttk.Frame(comparison_window)
        fifo_frame.pack(side=tk.LEFT, padx=10, pady=10)
        fifo_label = ttk.Label(fifo_frame, text="FIFO")
        fifo_label.pack()
        fifo_list = tk.Listbox(fifo_frame, width=50, height=20, bg='#505050', fg='white')
        fifo_list.pack()

        lifo_frame = ttk.Frame(comparison_window)
        lifo_frame.pack(side=tk.RIGHT, padx=10, pady=10)
        lifo_label = ttk.Label(lifo_frame, text="LIFO")
        
        lifo_label.pack()
        lifo_list = tk.Listbox(lifo_frame, width=50, height=20, bg='#505050', fg='white')
        lifo_list.pack()

        for process in self.selected_list.get(0, tk.END):
            fifo_list.insert(tk.END, process)
            lifo_list.insert(tk.END, process)
            
        while fifo_list.size() > 0:
            fifo_list.delete(0)
            time.sleep(1)
            comparison_window.update()  # Actualiza la ventana para reflejar los cambios

        # Procesa la lista LIFO
        while lifo_list.size() > 0:
            lifo_list.delete(lifo_list.size() - 1)
            time.sleep(1)
            comparison_window.update()

    def clear_selections(self):
        self.selected_list.delete(0, tk.END)

if __name__ == '__main__':
    root = tk.Tk()
    app = TaskManagerGUI(root)
    root.mainloop()
