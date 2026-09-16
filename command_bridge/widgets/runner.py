"""Command runner — manages subprocess execution via QProcess with signal output."""

from pathlib import Path
from PyQt6 import QtCore
from PyQt6.QtCore import QProcess, QTimer

from command_bridge.constants import DEFAULT_OUTPUT_DIR


class CommandRunner(QtCore.QObject):
    """Manages command execution with signal-based output handling."""

    output_ready = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal(int)

    def __init__(self):
        super().__init__()
        self.process = QProcess()
        self.process.readyReadStandardOutput.connect(self._handle_output)
        self.process.readyReadStandardError.connect(self._handle_error)
        self.process.finished.connect(self._handle_finished)
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.output_file = None
        self.output_file_handle = None
        self.check_timer = QTimer()
        self.check_timer.timeout.connect(self._check_process_state)
        self.check_timer.setInterval(2000)

    def _handle_output(self):
        data = self.process.readAllStandardOutput().data().decode('utf-8', errors='replace')
        if data:
            self.output_ready.emit(data)
            if self.output_file_handle:
                try:
                    self.output_file_handle.write(data)
                    self.output_file_handle.flush()
                except Exception:
                    pass

    def _handle_error(self):
        data = self.process.readAllStandardError().data().decode('utf-8', errors='replace')
        self.output_ready.emit(data)
        if self.output_file_handle:
            try:
                self.output_file_handle.write(data)
                self.output_file_handle.flush()
            except Exception:
                pass

    def _check_process_state(self):
        if self.process.state() == QProcess.ProcessState.NotRunning:
            self.check_timer.stop()
            exit_code = self.process.exitCode()
            self._handle_finished(exit_code, self.process.exitStatus())

    def _handle_finished(self, exit_code, exit_status):
        self.check_timer.stop()
        if self.output_file_handle:
            try:
                self.output_file_handle.close()
            except Exception:
                pass
            self.output_file_handle = None
            self.output_file = None
        self.finished.emit(exit_code)

    def run_command(self, command, cwd=None, output_file=None):
        """Execute a shell command in the given working directory."""
        if cwd is None:
            cwd = str(DEFAULT_OUTPUT_DIR)
        self.process.setWorkingDirectory(cwd)

        if self.output_file_handle:
            try:
                self.output_file_handle.close()
            except Exception:
                pass
            self.output_file_handle = None
            self.output_file = None

        if output_file:
            try:
                self.output_file = output_file
                self.output_file_handle = open(output_file, 'w', encoding='utf-8', buffering=1)
            except Exception as e:
                print(f"Failed to open output file {output_file}: {e}")
                self.output_file = None
                self.output_file_handle = None

        env = QtCore.QProcessEnvironment.systemEnvironment()
        is_sqlmap = "sqlmap" in command
        env.insert("PYTHONUNBUFFERED", "1")
        env.insert("PYTHONIOENCODING", "utf-8")
        if not is_sqlmap:
            current_path = env.value("PATH", "")
            go_paths = [
                str(Path.home() / "go" / "bin"),
                "/usr/local/go/bin",
                str(Path.home() / ".local" / "bin"),
            ]
            additional_paths = ":".join([p for p in go_paths if Path(p).exists()])
            if additional_paths:
                env.insert("PATH", f"{current_path}:{additional_paths}")
        self.process.setProcessEnvironment(env)

        if "testssl" in command and "yes |" not in command:
            command = f"yes | {command}"

        use_stdbuf = True
        has_pipe = '|' in command
        has_redirect = (' >' in command) or ('>>' in command) or ('2>' in command)
        if (has_pipe or has_redirect or is_sqlmap or
                'httpx' in command or 'subfinder' in command or
                'nuclei' in command or 'katana' in command or
                'dirsearch' in command):
            use_stdbuf = False

        if use_stdbuf:
            final_command = f"stdbuf -oL -eL {command}"
        else:
            final_command = command

        if is_sqlmap:
            self.process.start("script", ["-q", "-c", final_command, "/dev/null"])
        else:
            self.process.start("/bin/bash", ["-c", final_command])
            try:
                self.process.closeWriteChannel()
            except Exception:
                pass

        self.check_timer.start()

    def stop(self):
        """Kill the running process."""
        if self.process.state() == QProcess.ProcessState.Running:
            self.process.kill()
        if self.output_file_handle:
            try:
                self.output_file_handle.close()
            except Exception:
                pass
            self.output_file_handle = None
            self.output_file = None
