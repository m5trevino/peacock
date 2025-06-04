#!/usr/bin/env python3
import tkinter as tk
from tkinter import messagebox
import threading
import time
import subprocess
import sys
import os
from typing import Optional, Dict, Any

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.clipboard_manager import ClipboardManager
from shared.config_manager import ConfigManager
from shared.snippets_manager import SnippetsManager
from gui.main_window import MainWindow
from ordely import OrderlyManager

class MultiClipSystem:
    def __init__(self):
        self.config = ConfigManager()
        self.clipboard_manager = ClipboardManager()
        self.snippets_manager = SnippetsManager()
        self.orderly_manager = OrderlyManager(self.clipboard_manager)
        self.main_window: Optional[MainWindow] = None
        
        # System state
        self.current_mode = "Multiclip"
        self.running = True
        
        # Load persistent data
        self._load_persistent_data()
        
        # Setup callbacks
        self.orderly_manager.set_status_callback(self._on_orderly_status)
        self.orderly_manager.set_completion_callback(self._on_orderly_complete)
    
    def _load_persistent_data(self):
        # Load clipboard state
        state_data = self.config.load_state()
        if 'clipboard_slots' in state_data:
            self.clipboard_manager.load_state(
                os.path.join(self.config.config_dir, 'clipboard_state.json')
            )
        
        # Load snippets
        snippets_data = self.config.load_snippets()
        if snippets_data and 'categories' in snippets_data:
            self.snippets_manager.load_from_dict(snippets_data)
    
    def _save_persistent_data(self):
        # Save clipboard state
        clipboard_state_file = os.path.join(self.config.config_dir, 'clipboard_state.json')
        self.clipboard_manager.save_state(clipboard_state_file)
        
        # Save snippets
        self.config.save_snippets(self.snippets_manager.to_dict())
        
        # Save general state
        state_data = {
            'current_mode': self.current_mode,
            'orderly_state': self.orderly_manager.get_state_dict(),
            'last_saved': time.time()
        }
        self.config.save_state(state_data)
    
    def initialize_gui(self):
        """Initialize the main GUI window"""
        self.main_window = MainWindow()
        
        # Set up callbacks
        self.main_window.set_slot_select_callback(self._on_slot_select)
        self.main_window.set_mode_change_callback(self._on_mode_change)
        self.main_window.set_orderly_callback(self._on_orderly_action)
        
        # Load initial slot states
        self._update_all_slot_displays()
        
        # Set initial mode
        self._update_mode_display()
        
        return self.main_window
    
    def _update_all_slot_displays(self):
        """Update all slot displays in the GUI"""
        if self.main_window:
            for slot_id in range(10):
                content = self.clipboard_manager.get_slot_content(slot_id) or ""
                preview = self.clipboard_manager.get_slot_preview(slot_id) or "Empty"
                self.main_window.update_slot(slot_id, content, preview)
    
    def _update_mode_display(self):
        """Update GUI to reflect current mode"""
        if self.main_window:
            mode_status = {
                "Multiclip": "Ready for slot operations",
                "Orderly": self.orderly_manager.get_current_status(),
                "Snippers": "Ready to browse commands"
            }
            
            self.main_window.update_status(mode_status[self.current_mode])
            
            if self.current_mode == "Orderly":
                self.main_window.update_orderly_status(
                    self.orderly_manager.get_current_status(),
                    self.orderly_manager.is_active()
                )
    
    def _on_slot_select(self, slot_id: int):
        """Handle slot selection from GUI"""
        if self.current_mode == "Multiclip":
            # Copy slot content to system clipboard
            success = self.clipboard_manager.paste_from_slot(slot_id)
            if success:
                content = self.clipboard_manager.get_slot_preview(slot_id)
                self.main_window.update_bottom_status(f"Copied slot {slot_id} to clipboard: {content}")
            else:
                self.main_window.update_bottom_status(f"Slot {slot_id} is empty")
        
        elif self.current_mode == "Orderly":
            # In Orderly mode, slots are managed automatically
            self.main_window.update_bottom_status("Slot selection disabled in Orderly mode")
    
    def _on_mode_change(self, new_mode: str):
        """Handle mode change from GUI"""
        if new_mode != self.current_mode:
            # Deactivate current mode
            if self.current_mode == "Orderly" and self.orderly_manager.is_active():
                self.orderly_manager.deactivate_orderly_mode()
            
            self.current_mode = new_mode
            self._update_mode_display()
            
            self.main_window.update_bottom_status(f"Switched to {new_mode} mode")
    
    def _on_orderly_action(self, action: str):
        """Handle Orderly mode actions from GUI"""
        if action == "toggle":
            if self.orderly_manager.is_active():
                self.orderly_manager.deactivate_orderly_mode()
            else:
                self.orderly_manager.activate_orderly_mode()
            
            self._update_mode_display()
            
        elif action == "reset":
            self.orderly_manager.reset_paste_sequence()
            self._update_mode_display()
    
    def _on_orderly_status(self, status: str):
        """Handle status updates from Orderly manager"""
        if self.main_window:
            self.main_window.update_bottom_status(f"[Orderly] {status}")
            self._update_all_slot_displays()
            self._update_mode_display()
    
    def _on_orderly_complete(self):
        """Handle Orderly workflow completion"""
        if self.main_window:
            self.main_window.update_bottom_status("Orderly workflow completed!")
            self._update_mode_display()
    
    def handle_copy_operation(self):
        """Handle copy operations based on current mode"""
        if self.current_mode == "Multiclip":
            # In Multiclip mode, copies are handled by hotkeys
            pass
        
        elif self.current_mode == "Orderly":
            # Let Orderly manager handle the copy
            success = self.orderly_manager.handle_copy_operation()
            if success:
                self._update_all_slot_displays()
                self._update_mode_display()
    
    def handle_paste_operation(self):
        """Handle paste operations based on current mode"""
        if self.current_mode == "Multiclip":
            # In Multiclip mode, pastes are handled by hotkeys
            pass
        
        elif self.current_mode == "Orderly":
            # Let Orderly manager handle the paste
            success = self.orderly_manager.handle_paste_operation()
            if success:
                self._update_mode_display()
    
    def copy_to_slot(self, slot_id: int) -> bool:
        """Copy current clipboard to specific slot"""
        if 0 <= slot_id < 10:
            success = self.clipboard_manager.copy_to_slot(slot_id)
            if success and self.main_window:
                content = self.clipboard_manager.get_slot_content(slot_id)
                preview = self.clipboard_manager.get_slot_preview(slot_id)
                self.main_window.update_slot(slot_id, content, preview)
                self.main_window.update_bottom_status(f"Copied to slot {slot_id}: {preview}")
            return success
        return False
    
    def paste_from_slot(self, slot_id: int) -> bool:
        """Paste from specific slot to clipboard"""
        if 0 <= slot_id < 10:
            success = self.clipboard_manager.paste_from_slot(slot_id)
            if success and self.main_window:
                preview = self.clipboard_manager.get_slot_preview(slot_id)
                self.main_window.update_bottom_status(f"Pasted from slot {slot_id}: {preview}")
            return success
        return False
    
    def clear_slot(self, slot_id: int) -> bool:
        """Clear specific slot"""
        if 0 <= slot_id < 10:
            success = self.clipboard_manager.clear_slot(slot_id)
            if success and self.main_window:
                self.main_window.update_slot(slot_id, "", "Empty")
                self.main_window.update_bottom_status(f"Cleared slot {slot_id}")
            return success
        return False
    
    def clear_all_slots(self):
        """Clear all slots"""
        self.clipboard_manager.clear_all_slots()
        if self.main_window:
            self._update_all_slot_displays()
            self.main_window.update_bottom_status("Cleared all slots")
    
    def launch_snippers_view(self):
        """Launch the Snippers view window"""
        try:
            subprocess.Popen([sys.executable, 'snippers-view.py'])
        except Exception as e:
            if self.main_window:
                messagebox.showerror("Error", f"Failed to launch Snippers view: {e}")
    
    def launch_snippers_save(self):
        """Launch the Snippers save window"""
        try:
            subprocess.Popen([sys.executable, 'snippers-save.py'])
        except Exception as e:
            if self.main_window:
                messagebox.showerror("Error", f"Failed to launch Snippers save: {e}")
    
    def send_slot_to_snippers(self, slot_id: int):
        """Send slot content to Snippers for saving"""
        content = self.clipboard_manager.get_slot_content(slot_id)
        if content and content.strip():
            # This would ideally pass the content to snippers-save
            # For now, we'll copy it to clipboard and launch snippers-save
            self.clipboard_manager.paste_from_slot(slot_id)
            self.launch_snippers_save()
            
            if self.main_window:
                self.main_window.update_bottom_status(f"Sent slot {slot_id} content to Snippers")
        else:
            if self.main_window:
                self.main_window.update_bottom_status(f"Slot {slot_id} is empty")
    
    def start_clipboard_monitoring(self):
        """Start monitoring clipboard changes"""
        self.clipboard_manager.start_monitoring()
    
    def stop_clipboard_monitoring(self):
        """Stop monitoring clipboard changes"""
        self.clipboard_manager.stop_monitoring()
    
    def shutdown(self):
        """Clean shutdown of the system"""
        self.running = False
        
        # Save persistent data
        self._save_persistent_data()
        
        # Stop clipboard monitoring
        self.stop_clipboard_monitoring()
        
        # Close windows
        if self.main_window:
            self.main_window.destroy()
        
        print("MultiClip System shutdown complete")

def main():
    """Main entry point"""
    try:
        # Create the system
        system = MultiClipSystem()
        
        # Initialize GUI
        main_window = system.initialize_gui()
        
        # Start clipboard monitoring
        system.start_clipboard_monitoring()
        
        # Setup shutdown handler
        def on_closing():
            system.shutdown()
        
        main_window.root.protocol("WM_DELETE_WINDOW", on_closing)
        
        print("MultiClip System starting...")
        print("Available modes: Multiclip, Orderly, Snippers")
        print("Use the GUI or hotkeys to interact with the system")
        
        # Start the GUI main loop
        main_window.run()
        
    except KeyboardInterrupt:
        print("\nShutdown requested...")
        if 'system' in locals():
            system.shutdown()
    except Exception as e:
        print(f"Error starting MultiClip System: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
