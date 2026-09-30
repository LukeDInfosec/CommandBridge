"""
Window controls — resize, drag, title bar, and close event.
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



class WindowControlsMixin:
    """Mixin providing window controls — resize, drag, title bar, and close event."""

    def toggle_maximize(self):
        """Toggle between maximized and normal window state"""
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def title_bar_mouse_press(self, event):
        """Handle mouse press on title bar for dragging"""
        if event.button() == Qt.MouseButton.LeftButton:
            self.dragging = True
            self.drag_position = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def title_bar_mouse_move(self, event):
        """Handle mouse move on title bar for dragging"""
        if self.dragging and event.buttons() == Qt.MouseButton.LeftButton:
            self.move(event.globalPosition().toPoint() - self.drag_position)
            event.accept()

    def title_bar_mouse_release(self, event):
        """Handle mouse release on title bar"""
        self.dragging = False
        event.accept()

    def _update_cursor_for_edge(self, edge):
        """Set the resize cursor (or arrow) for the given edge name/None."""
        if edge:
            if edge in ('top-left', 'bottom-right'):
                self.setCursor(Qt.CursorShape.SizeFDiagCursor)
            elif edge in ('top-right', 'bottom-left'):
                self.setCursor(Qt.CursorShape.SizeBDiagCursor)
            elif edge in ('left', 'right'):
                self.setCursor(Qt.CursorShape.SizeHorCursor)
            elif edge in ('top', 'bottom'):
                self.setCursor(Qt.CursorShape.SizeVerCursor)
        else:
            self.setCursor(Qt.CursorShape.ArrowCursor)

    def _apply_resize(self, global_pos):
        """Recompute and apply window geometry for an in-progress edge resize."""
        delta = global_pos - self.resize_start_pos
        new_geometry = QtCore.QRect(self.resize_start_geometry)

        if 'left' in self.resize_edge:
            new_geometry.setLeft(self.resize_start_geometry.left() + delta.x())
        if 'right' in self.resize_edge:
            new_geometry.setRight(self.resize_start_geometry.right() + delta.x())
        if 'top' in self.resize_edge:
            new_geometry.setTop(self.resize_start_geometry.top() + delta.y())
        if 'bottom' in self.resize_edge:
            new_geometry.setBottom(self.resize_start_geometry.bottom() + delta.y())

        # Clamp each axis independently so resizing one edge is never
        # blocked by the opposite edge hitting its minimum.
        min_w = self.minimumWidth()
        min_h = self.minimumHeight()
        if new_geometry.width() < min_w:
            if 'left' in self.resize_edge:
                new_geometry.setLeft(new_geometry.right() - min_w)
            else:
                new_geometry.setRight(new_geometry.left() + min_w)
        if new_geometry.height() < min_h:
            if 'top' in self.resize_edge:
                new_geometry.setTop(new_geometry.bottom() - min_h)
            else:
                new_geometry.setBottom(new_geometry.top() + min_h)
        self.setGeometry(new_geometry)

    def mousePressEvent(self, event):
        """Handle mouse press for window resizing"""
        if event.button() == Qt.MouseButton.LeftButton:
            self.resize_edge = self.get_resize_edge(event.pos())
            if self.resize_edge:
                self.is_resizing = True
                self.resize_start_pos = event.globalPosition().toPoint()
                self.resize_start_geometry = self.geometry()
                event.accept()
                return
        from PyQt6.QtWidgets import QMainWindow
        QMainWindow.mousePressEvent(self, event)

    def mouseMoveEvent(self, event):
        """Handle mouse move for window resizing and cursor updates"""
        if self.is_resizing and hasattr(self, 'resize_edge') and self.resize_edge:
            self._apply_resize(event.globalPosition().toPoint())
            event.accept()
        else:
            # Update cursor based on position (only when not resizing)
            self._update_cursor_for_edge(self.get_resize_edge(event.pos()))
            from PyQt6.QtWidgets import QMainWindow
            QMainWindow.mouseMoveEvent(self, event)

    def mouseReleaseEvent(self, event):
        """Handle mouse release for window resizing"""
        if hasattr(self, 'resize_edge'):
            self.resize_edge = None
            self.is_resizing = False
            self._update_cursor_for_edge(self.get_resize_edge(event.pos()))
        from PyQt6.QtWidgets import QMainWindow
        QMainWindow.mouseReleaseEvent(self, event)

    def leaveEvent(self, event):
        """Reset cursor when mouse leaves the window"""
        self.setCursor(Qt.CursorShape.ArrowCursor)
        from PyQt6.QtWidgets import QMainWindow
        QMainWindow.leaveEvent(self, event)

    # Interactive control types that must NEVER be hijacked for edge-resize,
    # even when a pixel of them happens to fall within the edge margin (e.g.
    # the header bar's minimize/maximize/close buttons, nav rail buttons, a
    # scrollbar hugging the right edge). Only clicks on "background" chrome
    # (QWidget/QFrame/QLabel/scroll-area viewports, etc.) trigger a resize.
    _RESIZE_EXCLUDED_TYPES = None  # populated lazily (needs QtWidgets at call time)

    def _is_resize_excluded(self, obj):
        if WindowControlsMixin._RESIZE_EXCLUDED_TYPES is None:
            WindowControlsMixin._RESIZE_EXCLUDED_TYPES = (
                QtWidgets.QAbstractButton,
                QtWidgets.QAbstractSlider,   # covers QScrollBar too
                QtWidgets.QComboBox,
                QtWidgets.QLineEdit,
                QtWidgets.QAbstractSpinBox,
            )
        return isinstance(obj, WindowControlsMixin._RESIZE_EXCLUDED_TYPES)

    def eventFilter(self, obj, event):
        """Global event filter (installed on the QApplication instance).

        Frameless windows with full-bleed child content (header bar, nav
        rail, tab content, status bar) mean mouse events at the window's
        physical edges almost always land on a CHILD widget first, not on
        the QMainWindow itself — so mousePressEvent/mouseMoveEvent above
        rarely fire for a real click. This filter intercepts mouse press/
        move/release for every widget belonging to this window, translates
        the position into window coordinates, and starts/continues an edge
        resize whenever the cursor is within the edge margin — unless the
        event target is an interactive control (button, scrollbar, combo,
        etc.) that should keep receiving normal clicks.
        """
        et = event.type()

        if et in (
            QtCore.QEvent.Type.MouseButtonPress,
            QtCore.QEvent.Type.MouseMove,
            QtCore.QEvent.Type.MouseButtonRelease,
        ):
            try:
                if (
                    isinstance(obj, QtWidgets.QWidget)
                    and obj.window() is self
                    and not self._is_resize_excluded(obj)
                ):
                    window_pos = obj.mapTo(self, event.position().toPoint())

                    if et == QtCore.QEvent.Type.MouseButtonPress:
                        if event.button() == Qt.MouseButton.LeftButton and not self.dragging:
                            edge = self.get_resize_edge(window_pos)
                            if edge:
                                self.resize_edge = edge
                                self.is_resizing = True
                                self.resize_start_pos = event.globalPosition().toPoint()
                                self.resize_start_geometry = self.geometry()
                                return True

                    elif et == QtCore.QEvent.Type.MouseMove:
                        if self.is_resizing and getattr(self, "resize_edge", None):
                            self._apply_resize(event.globalPosition().toPoint())
                            return True
                        if not self.dragging:
                            self._update_cursor_for_edge(self.get_resize_edge(window_pos))

                    elif et == QtCore.QEvent.Type.MouseButtonRelease:
                        if self.is_resizing:
                            self.is_resizing = False
                            self.resize_edge = None
                            self._update_cursor_for_edge(self.get_resize_edge(window_pos))
                            return True
            except Exception:
                pass

        if obj == self and et == QtCore.QEvent.Type.HoverMove:
            # Only update cursor if not currently resizing
            if not self.is_resizing:
                self._update_cursor_for_edge(self.get_resize_edge(event.position().toPoint()))

        from PyQt6.QtWidgets import QMainWindow
        return QMainWindow.eventFilter(self, obj, event)

    def get_resize_edge(self, pos):
        """Determine which edge (if any) the mouse is near"""
        edge_margin = 10
        rect = self.rect()
        
        left = pos.x() < edge_margin
        right = pos.x() > rect.width() - edge_margin
        top = pos.y() < edge_margin
        bottom = pos.y() > rect.height() - edge_margin
        
        if top and left:
            return 'top-left'
        elif top and right:
            return 'top-right'
        elif bottom and left:
            return 'bottom-left'
        elif bottom and right:
            return 'bottom-right'
        elif left:
            return 'left'
        elif right:
            return 'right'
        elif top:
            return 'top'
        elif bottom:
            return 'bottom'
        return None

    def closeEvent(self, event):
        """Save window geometry and kill everything still running.

        Closing the window has to mean the tool stops touching the target.
        Anything still in flight at this point is a scan against someone
        else's network with nobody watching it and no interface left to stop
        it — so this tears down in a deliberate order and does not return
        until it is done.

        The order matters. The gates come down first, because they are what
        releases threads that are blocked mid-request or held on a pause; a
        thread waiting on a pause that will never be resumed would otherwise
        hang the wait below. Only then are the child processes killed and the
        threads joined.
        """
        # 1 ── tell every engine to stop, and release anything paused.
        self._stop_everything()

        # 2 ── the external tool. A SIGSTOP'd child cannot act on SIGTERM, so
        # anything paused is continued first; otherwise terminate() is
        # swallowed and the close stalls for the full timeout before the
        # SIGKILL that was always going to be needed.
        try:
            runner = getattr(self, "runner", None)
            if runner is not None and runner.process.state() != QProcess.ProcessState.NotRunning:
                self._resume_stopped_child(runner)
                runner.process.terminate()
                if not runner.process.waitForFinished(1500):
                    runner.process.kill()
                    runner.process.waitForFinished(500)
        except Exception:
            pass

        # 3 ── the Python worker threads. Joined, not abandoned: a QThread
        # destroyed while running takes the process down with it, and the
        # requests it has in flight would otherwise land after the window has
        # gone.
        self._join_worker_threads()

        # Stop local CORS PoC server if running
        try:
            proc = getattr(self, "_cors_poc_server", None)
            if proc is not None:
                self._cors_poc_server = None
                try:
                    if proc.state() == QProcess.ProcessState.Running:
                        proc.terminate()
                        proc.waitForFinished(1500)
                        if proc.state() == QProcess.ProcessState.Running:
                            proc.kill()
                except Exception:
                    pass
        except Exception:
            pass

        self.save_window_geometry()
        event.accept()

    # ── shutdown ─────────────────────────────────────────────────────────
    def _stop_everything(self):
        """Stop every engine that could still be talking to the target.

        Each step is wrapped on its own: a tab that failed to build, or an
        engine that is halfway through its own teardown, must not stop the
        others from being shut down.
        """
        # Coffee Break: ends the chain, releases the probe gate, and SIGCONTs
        # a suspended child so the terminate below can be delivered.
        try:
            if getattr(self, "_cb_active", False):
                self.stop_coffee_break()
        except Exception:                               # noqa: BLE001
            pass
        try:
            gate = getattr(self, "_cb_gate", None)
            if gate is not None:
                gate.stop()
        except Exception:                               # noqa: BLE001
            pass

        # The Active Scan engine. stop() sets its flag and releases its gate,
        # which is what wakes workers blocked on a pause.
        try:
            engine = getattr(self, "_as_engine", None)
            if engine is not None:
                engine.stop()
        except Exception:                               # noqa: BLE001
            pass

    @staticmethod
    def _resume_stopped_child(runner):
        """SIGCONT a child that Pause left suspended, so it can be killed."""
        try:
            import os
            import signal
            pid = runner.process.processId()
            if pid and hasattr(signal, "SIGCONT"):
                os.kill(pid, signal.SIGCONT)
        except Exception:                               # noqa: BLE001
            pass

    def _join_worker_threads(self):
        """Wait for the background threads to unwind, then let them go.

        The gates are already down by the time this runs, so a thread is at
        most one in-flight HTTP request away from noticing. The timeout is
        generous enough for that request to time out on its own and short
        enough that closing the window never feels stuck; anything still
        alive after it is left to the process exiting.
        """
        for name in ("_cb_thread", "_as_thread"):
            thread = getattr(self, name, None)
            if thread is None:
                continue
            try:
                if thread.isRunning():
                    thread.quit()
                    thread.wait(4000)
            except Exception:                           # noqa: BLE001
                pass
            try:
                setattr(self, name, None)
            except Exception:                           # noqa: BLE001
                pass

    def save_window_geometry(self):
        """Save window position and size to config file"""
        try:
            config_dir = Path.home() / ".config" / "CommandBridge"
            config_dir.mkdir(parents=True, exist_ok=True)
            config_file = config_dir / "geometry.txt"
            
            # Save geometry
            geom = self.geometry()
            with open(config_file, 'w') as f:
                f.write(f"x={geom.x()}\n")
                f.write(f"y={geom.y()}\n")
                f.write(f"width={geom.width()}\n")
                f.write(f"height={geom.height()}\n")
                f.write(f"maximized={self.isMaximized()}\n")
        except Exception as e:
            print(f"Error saving window geometry: {e}")

    def load_window_geometry(self):
        """Load saved window position and size from config file"""
        try:
            config_dir = Path.home() / ".config" / "CommandBridge"
            config_file = config_dir / "geometry.txt"
            
            if config_file.exists():
                with open(config_file, 'r') as f:
                    geometry = {}
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            geometry[key] = value
                    
                    # Restore geometry
                    if all(k in geometry for k in ['x', 'y', 'width', 'height']):
                        x = int(geometry['x'])
                        y = int(geometry['y'])
                        width = int(geometry['width'])
                        height = int(geometry['height'])
                        self.setGeometry(x, y, width, height)
                        
                        # Restore maximized state
                        if geometry.get('maximized') == 'True':
                            self.showMaximized()
        except Exception as e:
            print(f"Error loading window geometry: {e}")

