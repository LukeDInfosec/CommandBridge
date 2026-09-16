"""
Output handling — console display, file management, process control.
"""
import os
import re
import sys
import json
import subprocess
from pathlib import Path

from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import QProcess, Qt, QTimer
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QTabWidget, QGridLayout,
    QGroupBox, QSplitter, QScrollArea, QFileDialog, QMessageBox,
    QComboBox, QFrame, QPlainTextEdit, QProgressBar, QToolButton,
)
from command_bridge.constants import APP_TITLE, APP_VERSION, THEMES, BASE_DIR



class OutputMixin:
    """Mixin providing output handling — console display, file management, process control."""

    def browse_output_dir(self):
        """Browse for output directory with themed dialog"""
        file_dialog = QFileDialog(self)
        file_dialog.setWindowTitle("Select Output Directory")
        file_dialog.setFileMode(QFileDialog.FileMode.Directory)
        file_dialog.setOption(QFileDialog.Option.ShowDirsOnly, True)
        file_dialog.setDirectory(str(self.output_dir))
        
        # Apply theme to the file dialog
        self.apply_theme_to_dialog(file_dialog)
        
        # Ensure the dialog palette uses readable text/selection colors for
        # any inline editors (e.g. the "New Folder" rename field). On some
        # Linux themes Qt keeps the text selected while typing and uses the
        # palette's Highlight / HighlightedText roles, which can clash with
        # our stylesheet. We explicitly align these with our theme here.
        try:
            from PyQt6.QtGui import QPalette, QColor
            if self.current_theme in THEMES:
                theme = THEMES[self.current_theme]
                pal = file_dialog.palette()
                pal.setColor(QPalette.ColorRole.Base, QColor(theme["panel_bg"]))
                pal.setColor(QPalette.ColorRole.Text, QColor(theme["text"]))
                pal.setColor(QPalette.ColorRole.Window, QColor(theme["bg"]))
                pal.setColor(QPalette.ColorRole.WindowText, QColor(theme["text"]))
                pal.setColor(QPalette.ColorRole.Highlight, QColor(theme["accent"]))
                pal.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
                file_dialog.setPalette(pal)
        except Exception:
            # Palette tweaking is best-effort; fall back to stylesheet-only.
            pass
        
        # Use Qt's file dialog (not native)
        file_dialog.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        
        if file_dialog.exec() == QFileDialog.DialogCode.Accepted:
            selected_dirs = file_dialog.selectedFiles()
            if selected_dirs:
                self.output_dir = Path(selected_dirs[0])
                self.output_input.setText(str(self.output_dir))
                # Save the new output directory
                self.save_output_dir_preference(str(self.output_dir))
                # Keep the status bar's OUTPUT segment in step.
                if hasattr(self, "update_output_display"):
                    self.update_output_display()

    @staticmethod
    def _entry_name(item) -> str:
        """Real filename behind a list row.

        The row's visible text is for humans (directories get a trailing '/');
        the untouched name lives in the item's user-data role so display
        styling can change without breaking file resolution. The legacy emoji
        prefixes are still stripped for any row created by older code.
        """
        if item is None:
            return ""
        stored = item.data(Qt.ItemDataRole.UserRole)
        if stored:
            return str(stored)
        return item.text().replace("📄 ", "").replace("📁 ", "").rstrip("/")

    def refresh_file_list(self):
        """Refresh the artefacts list for the current output directory."""
        from PyQt6.QtWidgets import QListWidgetItem

        try:
            self.file_list.clear()
            entries = sorted(
                self.output_dir.glob("*"),
                key=lambda p: (p.is_file(), p.name.lower()),  # folders first
            )
            for entry in entries:
                is_dir = not entry.is_file()
                item = QListWidgetItem(f"{entry.name}/" if is_dir else entry.name)
                item.setData(Qt.ItemDataRole.UserRole, entry.name)
                if is_dir:
                    item.setToolTip(f"Directory: {entry.name}")
                else:
                    try:
                        size = entry.stat().st_size
                        for unit in ("B", "KB", "MB", "GB"):
                            if size < 1024 or unit == "GB":
                                item.setToolTip(f"{entry.name} — {size:.0f} {unit}")
                                break
                            size /= 1024
                    except Exception:
                        item.setToolTip(entry.name)
                self.file_list.addItem(item)

            if not entries:
                placeholder = QListWidgetItem("No artefacts yet — run a scan.")
                placeholder.setFlags(Qt.ItemFlag.NoItemFlags)
                self.file_list.addItem(placeholder)
        except Exception as e:
            self.file_list.clear()
            self.file_list.addItem(f"Error listing files: {e}")

    def on_file_selected(self, item):
        """Preview selected file"""
        try:
            filename = self._entry_name(item)
            file_path = self.output_dir / filename
            
            if file_path.is_file():
                # Read and preview file
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read(50000)  # Read first 50KB
                        if len(content) >= 50000:
                            content += "\n\n... (file truncated, showing first 50KB)"
                        self.file_preview.setText(content)
                except Exception as e:
                    self.file_preview.setText(f"Error reading file: {e}")
            else:
                self.file_preview.setText(f"Directory: {filename}\n\nSelect a file to preview.")
        except Exception as e:
            self.file_preview.setText(f"Error: {e}")

    def open_selected_file_external(self, item):
        """Open the selected file or directory using the system default handler.

        Triggered on double-click in the Directory Browser so you can jump
        directly into the file in an external viewer/editor if needed.
        """
        try:
            filename = self._entry_name(item)
            file_path = self.output_dir / filename
            if file_path.exists():
                try:
                    subprocess.Popen(["xdg-open", str(file_path)])
                except Exception as e:
                    self.show_themed_message("Error", f"Could not open: {e}", QMessageBox.Icon.Warning)
        except Exception as e:
            self.show_themed_message("Error", f"Could not open selection: {e}", QMessageBox.Icon.Warning)

    def delete_selected_file(self):
        """Delete selected file"""
        try:
            current_item = self.file_list.currentItem()
            if not current_item:
                self.show_themed_message("No Selection", "Please select a file to delete.", QMessageBox.Icon.Warning)
                return
            
            filename = self._entry_name(current_item)
            file_path = self.output_dir / filename
            
            # Confirm deletion with themed dialog
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Confirm Delete")
            msg_box.setText(f"Are you sure you want to delete:\n{filename}?")
            msg_box.setIcon(QMessageBox.Icon.Question)
            msg_box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            self.apply_theme_to_dialog(msg_box)
            reply = msg_box.exec()
            
            if reply == QMessageBox.StandardButton.Yes:
                if file_path.is_file():
                    file_path.unlink()
                    self.show_themed_message("Success", f"Deleted: {filename}")
                    self.file_preview.clear()
                    self.refresh_file_list()
                elif file_path.is_dir():
                    import shutil
                    shutil.rmtree(file_path)
                    self.show_themed_message("Success", f"Deleted directory: {filename}")
                    self.file_preview.clear()
                    self.refresh_file_list()
        except Exception as e:
            self.show_themed_message("Error", f"Could not delete file: {e}", QMessageBox.Icon.Critical)

    def open_output_folder(self):
        """Open output folder in file manager"""
        try:
            subprocess.Popen(["xdg-open", str(self.output_dir)])
        except Exception as e:
            self.show_themed_message("Error", f"Could not open folder: {e}", QMessageBox.Icon.Warning)

    def clear_console(self):
        """Clear console output"""
        self.console.clear()

    def pause_current_process(self):
        """Pause/Resume the currently running process.

        We maintain our own paused flag because QProcess does not know about
        SIGSTOP, so its state remains Running even when the OS-level process is
        paused.
        """
        if not hasattr(self, "_process_paused"):
            self._process_paused = False

        try:
            import signal
            pid = self.runner.process.processId()
            if not pid:
                self.console.append_ansi("\n[!] No process running to pause/resume\n")
                return

            if not self._process_paused:
                # Send SIGSTOP to pause
                os.kill(pid, signal.SIGSTOP)
                self._process_paused = True
                self.console.append_ansi("\n[*] Process paused\n")
                self.set_status_state("paused")
                # Flip the transport button to Resume (text + icon together).
                self.set_transport_button(self.sender(), "Resume", "play")
            else:
                # Send SIGCONT to resume
                os.kill(pid, signal.SIGCONT)
                self._process_paused = False
                self.console.append_ansi("\n[*] Process resumed\n")
                self.set_status_state("running")
                self.set_transport_button(self.sender(), "Pause", "pause")
        except Exception as e:
            self.console.append_ansi(f"\n[!] Could not pause/resume process: {e}\n")

    def skip_current_task(self):
        """Skip the current task in a multi-command sequence.

        Behaviour:
        - Send SIGINT to the running process so tools can clean up gracefully.
        - Mark an internal "skip" flag so on_command_finished can treat this as
          an intentional skip rather than a generic error. For Auto Scan, this
          means:
            * If there are more steps, move on to the next step.
            * If this was the final step, mark the sequence as successfully
              completed and set the progress bar to 100%.
        """
        if self.runner.process.state() == QProcess.ProcessState.Running:
            try:
                import signal
                pid = self.runner.process.processId()
                if pid:
                    # Let on_command_finished know this exit was user-requested
                    self._skip_current = True
                    # Send SIGINT to interrupt current command
                    os.kill(pid, signal.SIGINT)
                    self.console.append_ansi("\n[*] Skipping current task...\n")
            except Exception as e:
                self.console.append_ansi(f"\n[!] Could not skip task: {e}\n")
        else:
            self.console.append_ansi("\n[!] No process running to skip\n")

    def stop_current_process(self):
        """Stop the currently running process"""
        self.runner.stop()
        # Reset paused flag if set
        if hasattr(self, "_process_paused"):
            self._process_paused = False
        self.console.append_ansi("\n[!] Process stopped by user\n")
        self.set_status_state("idle")
        
        # Update status bar
        self.stop_progress_animation()
        self.update_status_bar("stopped", self.current_command)
        QTimer.singleShot(2000, lambda: self.update_status_bar("idle", ""))
        
        # A stopped process is no longer paused, so reset the transport button.
        for child in self.findChildren(QPushButton):
            if "Resume" in child.text():
                self.set_transport_button(child, "Pause", "pause")

    def on_command_output(self, text):
        """Handle command output"""
        try:
            cmd = self.current_command or ""
            if "sqlmap" in cmd:
                self._process_sqlmap_output(text)
                return
            if "nmap" in cmd:
                text = self._highlight_nmap_discovered_ports(text)
            if "gobuster" in cmd:
                text = self._process_gobuster_output(text)
                if not text:
                    return
            if "smartfuzz" in cmd or "ffuf" in cmd:
                # SmartFuzz / ffuf: strip ':: Progress:' chatter and reformat
                # raw ffuf -json records into clean '[status] full_url' lines
                # (200s highlighted green). Already-formatted lines pass through.
                self._process_ffuf_output(text)
                return
            if "testssl" in cmd:
                import re as _re
                text = _re.sub(r'\n{3,}', '\n\n', text)
        except Exception:
            pass
        self.console.append_ansi(text)

    def _process_gobuster_output(self, text: str) -> str:
        """Intercept Gobuster progress lines → progress bar; pass findings through."""
        import re as _re
        lines = text.split('\n')
        result = []
        for line in lines:
            m = _re.search(r'Progress:\s*(\d+)\s*/\s*(\d+)', line, _re.IGNORECASE)
            if m:
                done, total = int(m.group(1)), int(m.group(2))
                if total > 0:
                    try:
                        self.progress_bar.setValue(min(int(done * 100 / total), 99))
                    except Exception:
                        pass
                continue
            result.append(line)
        return '\n'.join(result)

    def _process_ffuf_output(self, text: str) -> None:
        """Buffer ffuf/SmartFuzz output and emit it one complete line at a time.

        ffuf writes results as newline-delimited JSON, interleaved with
        ':: Progress:' status lines. Output arrives in arbitrary chunks, so we
        buffer until we have whole lines before parsing each as JSON.
        """
        if not hasattr(self, "_ffuf_buf"):
            self._ffuf_buf = ""
        self._ffuf_buf += text
        while "\n" in self._ffuf_buf:
            line, _, rest = self._ffuf_buf.partition("\n")
            self._ffuf_buf = rest
            self._emit_ffuf_line(line)

    def _flush_ffuf_buffer(self) -> None:
        """Emit any trailing partial line left in the ffuf buffer (called on finish)."""
        leftover = getattr(self, "_ffuf_buf", "")
        if leftover:
            self._emit_ffuf_line(leftover)
        self._ffuf_buf = ""

    def _emit_ffuf_line(self, line: str) -> None:
        """Render a single ffuf/SmartFuzz output line.

        - ':: Progress:' / ':: ...' status lines are dropped.
        - Raw ffuf -json records become '[status] full_url' (200s green,
          3xx amber, 4xx red).
        - Everything else (banners, phase headers, already-formatted lines)
          passes through unchanged.
        """
        import json as _json
        stripped = line.strip().lstrip('\r')
        if not stripped:
            return
        if stripped.startswith("::"):
            return

        if stripped.startswith("{") and '"url"' in stripped and '"status"' in stripped:
            try:
                data = _json.loads(stripped)
                url = data.get("url", "")
                status = str(data.get("status", ""))
                if url:
                    self._append_ffuf_hit(status, url)
                    return
            except (ValueError, TypeError):
                pass

        self.console.append_ansi(line + "\n")

    def _append_ffuf_hit(self, status: str, url: str) -> None:
        """Print a discovered endpoint as '[status] full_url', colored by status."""
        from html import escape as _esc
        if status.startswith("2"):
            color = "#22c55e"   # green — 200 OK and friends
        elif status.startswith("3"):
            color = "#fbbf24"   # amber — redirects
        elif status.startswith("4"):
            color = "#ef4444"   # red — 401/403/etc.
        else:
            color = None

        label = _esc(f"[{status}] {url}")
        if color:
            self.console.append_html(
                f'<span style="color: {color}; font-weight: bold;">{label}</span><br>'
            )
        else:
            self.console.append_ansi(f"[{status}] {url}\n")

    def _process_sqlmap_output(self, text: str) -> None:
        """Stream sqlmap output, tracking and highlighting confirmed SQLi findings.

        This method keeps a small per-command buffer so we always inspect
        complete lines before deciding whether they represent confirmed
        injection or critical impact. All lines are still emitted; only the
        first confirmed finding is highlighted.
        """
        # Lazily initialise state if needed (e.g. for non-HTTP sqlmap buttons)
        if not hasattr(self, "_sqlmap_buffer"):
            self._reset_sqlmap_state()

        self._sqlmap_buffer += text
        while "\n" in self._sqlmap_buffer:
            line, _, rest = self._sqlmap_buffer.partition("\n")
            self._sqlmap_buffer = rest
            self._handle_sqlmap_line(line, newline=True)

    def _handle_sqlmap_line(self, line: str, newline: bool = True) -> None:
        """Analyse one sqlmap output line and emit it with optional highlighting.

        The original text of the line is preserved. On the first line that
        clearly indicates a successful or confirmed SQL injection, we render
        that whole line in green (or red for critical impact). Subsequent
        lines are passed through unchanged to avoid excessive highlighting.
        """
        import re as _re
        from html import escape as _esc

        text = line.rstrip("\r")
        lower = text.lower()

        vuln = False
        critical = False
        dbms = None
        param = None

        # Extract back-end DBMS if sqlmap reports it (e.g. "the back-end DBMS is 'MySQL'")
        m = _re.search(r"back-end dbms is\s*(?:'|\")?([^'\"]+)", text, _re.IGNORECASE)
        if m:
            dbms = m.group(1).strip()

        # Extract parameter name from common sqlmap messages
        m = _re.search(r"(?:parameter|param)\s*'([^']+)'(?:\s*\(.*\))?\s+appears to be", text, _re.IGNORECASE)
        if not m:
            m = _re.search(r"(get|post|put|cookie)\s+parameter\s+'([^']+)'", text, _re.IGNORECASE)
        if not m:
            m = _re.search(r"parameter\s*:?\s*'([^']+)'", text, _re.IGNORECASE)
        if m:
            # Use the last capturing group which holds the actual name in all patterns
            groups = m.groups()
            param = groups[-1].strip()

        # Indicators of successful / confirmed SQL injection
        success_patterns = [
            r"is vulnerable\\b",
            r"sql injection vulnerability has been detected",
            r"appears to be .*injectable",
            r"appears to be injectable",
            r"payload .*? worked",
        ]
        if any(_re.search(p, lower) for p in success_patterns):
            vuln = True
        # "available databases" is only meaningful once injection was already found
        if "available databases" in lower and getattr(self, "_sqlmap_vuln_found", False):
            vuln = True
        # If sqlmap reports the back-end DBMS, it has already confirmed injection
        if dbms:
            vuln = True

        # Critical impact indicators (e.g. stacked queries, file write / outfile)
        if "stacked queries" in lower or "stacked query" in lower:
            critical = True
            vuln = True
        if "file write" in lower or "into outfile" in lower or "into dumpfile" in lower:
            critical = True
            vuln = True
        if "[critical]" in lower:
            # Generic CRITICAL messages are treated as high importance
            critical = True

        # Update accumulated state for later summary
        if dbms and not getattr(self, "_sqlmap_dbms", None):
            self._sqlmap_dbms = dbms
        if param and not getattr(self, "_sqlmap_param", None):
            self._sqlmap_param = param
        if critical:
            self._sqlmap_critical = True
        if vuln:
            self._sqlmap_vuln_found = True

        # Decide how to render this line
        if vuln and not getattr(self, "_sqlmap_first_vuln_highlighted", False):
            # First confirmed finding: highlight entire line (green or red)
            self._sqlmap_first_vuln_highlighted = True
            color = "#ef4444" if critical else "#22c55e"  # red for critical, green otherwise
            safe = _esc(text)
            suffix = "<br>" if newline else ""
            self.console.append_html(f'<span style="color: {color}; font-weight: bold;">{safe}</span>{suffix}')
        else:
            # Pass through unchanged; preserve exact text content
            out = text + ("\n" if newline else "")
            self.console.append_ansi(out)

    def on_command_finished(self, exit_code):
        """Handle command completion"""
        # Capture and clear any pending "skip current task" request so we can
        # distinguish intentional skips from genuine errors (non-zero exit
        # codes).
        skip_requested = getattr(self, "_skip_current", False)
        if hasattr(self, "_skip_current"):
            self._skip_current = False

        # Flush any buffered ffuf/SmartFuzz output (last line may lack a newline)
        try:
            self._flush_ffuf_buffer()
        except Exception:
            pass

        # Special-case: summarize SSL/TLS findings after successful testssl runs.
        # Skip this for Externals TLS phase, which has its own aggregated summary
        # to avoid per-host spam.
        is_externals_tls = getattr(self, "_externals_active", False) and getattr(self, "_externals_phase", None) == "tls"
        if not is_externals_tls:
            try:
                self._summarize_testssl_if_applicable(exit_code)
            except Exception as e:
                self.console.append_ansi(f"[i] SSL summary (testssl) failed: {e}\\n")

        # Summarize FFUF results (HTTP hits) if applicable
        try:
            self._summarize_ffuf_if_applicable(exit_code)
        except Exception as e:
            self.console.append_ansi(f"[i] FFUF summary failed: {e}\\n")

        # Append a one-line SQL injection summary banner if the last command was
        # sqlmap and a vulnerability was confirmed.
        try:
            self._summarize_sqlmap_if_applicable(exit_code)
        except Exception as e:
            try:
                self.console.append_ansi(f"[i] SQLMap summary failed: {e}\\n")
            except Exception:
                pass
 
        scan_name = self.get_action_display_name(self.current_command)
        # For ffuf we already print a dedicated summary (hits or "no matching
        # results"), so avoid adding the generic "[ffuf] has been completed."
        # line to keep the console output clean and focused.
        is_ffuf = "ffuf" in (self.current_command or "")
        if not is_ffuf:
            if exit_code == 0:
                self.append_scan_completion_message(scan_name, success=True)
            else:
                self.append_scan_completion_message(scan_name, success=False, exit_code=exit_code)
        self.set_status_state("idle")
        
        # Update status bar
        self.stop_progress_animation()
        if exit_code == 0:
            self.update_status_bar("success", self.current_command)
            self.progress_bar.setValue(100)
        else:
            self.update_status_bar("error", self.current_command)
        
        # Reset to idle after 3 seconds
        QTimer.singleShot(3000, lambda: self.update_status_bar("idle", ""))
        
        self.refresh_file_list()

        # One-shot follow-up. A button that chains two stages — "Retrieve &
        # Analyse JS Files" runs wget and then the static analysis over what
        # landed — leaves a callable here. It is cleared *before* being called
        # so an exception inside it can never leave the hook armed for the
        # next, unrelated command, and it is skipped on a non-zero exit:
        # analysing a download that failed only prints noise.
        follow_up = getattr(self, "_command_follow_up", None)
        if follow_up is not None:
            self._command_follow_up = None
            if exit_code == 0:
                try:
                    follow_up()
                except Exception as exc:
                    self.console.append_ansi(f"\n[!] Follow-up step failed: {exc}\n")

        # Ensure pause state/label are reset when a command finishes
        if hasattr(self, "_process_paused"):
            self._process_paused = False
        for child in self.findChildren(QPushButton):
            if child.text().strip() in ("▶️ Resume", "Resume"):
                self.set_transport_button(child, "Pause", "pause")
        # If Auto Scan is active, advance to the next step on success **or**
        # when the user explicitly requested to skip the current task.
        #
        # This ensures that:
        # - Skipping an intermediate step moves on to the next command instead
        #   of aborting the entire sequence.
        # - Skipping the final step still marks Auto Scan as completed and the
        #   progress bar is set to 100%.
        if getattr(self, "_auto_scan_active", False):
            if exit_code == 0 or skip_requested:
                # Continue with next step if any remain
                if self._auto_scan_index < len(self._auto_scan_commands):
                    self._start_next_auto_scan_command()
                else:
                    # Completed all steps (including any user-skipped ones)
                    self._auto_scan_active = False
                    self._auto_scan_commands = []
                    self._auto_scan_output_dir = None
                    self._auto_scan_index = 0

                    # Ensure the status bar reflects a clean completion, even if
                    # the last step was skipped.
                    self.stop_progress_animation()
                    self.update_status_bar("success", "Auto Scan")
                    self.progress_bar.setValue(100)
            else:
                # Abort sequence on genuine error
                self._auto_scan_active = False
                self._auto_scan_commands = []
                self._auto_scan_output_dir = None
                self._auto_scan_index = 0

        # If Externals workflow is active, advance its state machine
        try:
            if getattr(self, "_externals_active", False):
                self._on_externals_command_finished(exit_code)
        except Exception as e:
            self.console.append_ansi(f"[i] Externals workflow error: {e}\\n")

        # Best-effort: strip ANSI color codes from any obvious output files
        # produced by this command (e.g. -o file, --logfile file, tee file).
        try:
            self._cleanup_ansi_in_command_outputs()
        except Exception:
            # Never let post-processing break the main workflow
            pass
