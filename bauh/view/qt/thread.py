import time
from datetime import datetime, timedelta
from typing import List

import requests
from PyQt5.QtCore import QThread, pyqtSignal
from bauh_api.abstract.controller import ApplicationManager
from bauh_api.abstract.handler import ProcessHandler
from bauh_api.abstract.model import ApplicationStatus
from bauh_api.exception import NoInternetException
from bauh_api.util.cache import Cache
from bauh_api.util.system import SystemProcess

from bauh.view.qt.view_model import ApplicationView


class AsyncAction(QThread, ProcessHandler):

    signal_confirmation = pyqtSignal(dict)

    def __init__(self):
        super(AsyncAction, self).__init__()
        self.wait_confirmation = False
        self.confirmation_res = None

    def notify_subproc_outputs(self, proc: SystemProcess, signal) -> bool:
        """
        :param signal:
        :param proc:
        :return: if the subprocess succeeded
        """
        signal.emit(' '.join(proc.subproc.args) + '\n')

        success, already_succeeded = True, False

        for output in proc.subproc.stdout:
            line = output.decode().strip()
            if line:
                signal.emit(line)

                if proc.success_phrase and proc.success_phrase in line:
                    already_succeeded = True

        if already_succeeded:
            return True

        for output in proc.subproc.stderr:
            line = output.decode().strip()
            if line:
                signal.emit(line)

                if proc.check_error_output:
                    if proc.wrong_error_phrase and proc.wrong_error_phrase in line:
                        continue
                    else:
                        success = False

        return proc.subproc.returncode is None or proc.subproc.returncode == 0

    def request_confirmation(self, title: str, body: str, options: dict) -> dict:
        self.wait_confirmation = True
        self.signal_confirmation.emit({'title': title, 'body': body, 'options': options})
        self.wait_user()
        return self.confirmation_res

    def confirm(self, msg: dict):
        self.confirmation_res = msg
        self.wait_confirmation = False

    def wait_user(self):
        while self.wait_confirmation:
            time.sleep(0.01)


class UpdateSelectedApps(AsyncAction):

    signal_finished = pyqtSignal(bool, int)
    signal_status = pyqtSignal(str)
    signal_output = pyqtSignal(str)

    def __init__(self, manager: ApplicationManager, apps_to_update: List[ApplicationView] = None):
        super(UpdateSelectedApps, self).__init__()
        self.apps_to_update = apps_to_update
        self.manager = manager
        self.root_password = None

    def run(self):

        success = False

        if self.apps_to_update:
            updated = 0
            for app in self.apps_to_update:
                self.signal_status.emit(app.model.base_data.name)
                success = bool(self.manager.update(app.model, self.root_password, self))

                if not success:
                    break
                else:
                    updated += 1
                    self.signal_output.emit('\n')

            self.signal_finished.emit(success, updated)

        self.apps_to_update = None

    def handle(self, proc: SystemProcess) -> bool:
        return self.notify_subproc_outputs(proc, self.signal_output)

    def notify(self, msg: str):
        if msg:
            self.signal_output.emit(msg)


class RefreshApps(QThread):

    signal = pyqtSignal(list)

    def __init__(self, manager: ApplicationManager):
        super(RefreshApps, self).__init__()
        self.manager = manager

    def run(self):
        self.signal.emit(self.manager.read_installed())


class UninstallApp(AsyncAction):
    signal_finished = pyqtSignal(object)
    signal_output = pyqtSignal(str)

    def __init__(self, manager: ApplicationManager, icon_cache: Cache, app: ApplicationView = None):
        super(UninstallApp, self).__init__()
        self.app = app
        self.manager = manager
        self.icon_cache = icon_cache
        self.root_password = None

    def run(self):
        if self.app:
            success = self.manager.uninstall(self.app.model, self.root_password, self)

            if success:
                self.icon_cache.delete(self.app.model.base_data.icon_url)
                self.manager.clean_cache_for(self.app.model)

            self.signal_finished.emit(self.app if success else None)
            self.app = None
            self.root_password = None

    def handle(self, proc: SystemProcess) -> bool:
        return self.notify_subproc_outputs(proc, self.signal_output)

    def notify(self, msg: str):
        if msg:
            self.signal_output.emit(msg)


class DowngradeApp(AsyncAction):
    signal_finished = pyqtSignal(bool)
    signal_error = pyqtSignal(dict)
    signal_output = pyqtSignal(str)

    def __init__(self, manager: ApplicationManager, locale_keys: dict, app: ApplicationView = None):
        super(DowngradeApp, self).__init__()
        self.manager = manager
        self.app = app
        self.locale_keys = locale_keys
        self.root_password = None

    def run(self):
        if self.app:
            success = False
            try:
                success = self.manager.downgrade_app(self.app.model, self.root_password, self)
            except (requests.exceptions.ConnectionError, NoInternetException):
                success = False
                self.signal_output.emit(self.locale_keys['internet.required'])
            finally:
                self.app = None
                self.root_password = None
                self.signal_finished.emit(success)

    def handle(self, proc: SystemProcess) -> bool:
        return self.notify_subproc_outputs(proc, self.signal_output)

    def notify(self, msg: str):
        if msg:
            self.signal_output.emit(msg)

    def show_error(self, title: str, body: str):
        self.signal_error.emit({'title': title, 'body': body})


class GetAppInfo(QThread):
    signal_finished = pyqtSignal(dict)

    def __init__(self, manager: ApplicationManager, app: ApplicationView = None):
        super(GetAppInfo, self).__init__()
        self.app = app
        self.manager = manager

    def run(self):
        if self.app:
            info = {'__app__': self.app}
            info.update(self.manager.get_info(self.app.model))
            self.signal_finished.emit(info)
            self.app = None


class GetAppHistory(QThread):
    signal_finished = pyqtSignal(dict)

    def __init__(self, manager: ApplicationManager, locale_keys: dict, app: ApplicationView = None):
        super(GetAppHistory, self).__init__()
        self.app = app
        self.manager = manager
        self.locale_keys = locale_keys

    def run(self):
        if self.app:
            try:
                self.signal_finished.emit({'history': self.manager.get_history(self.app.model)})
            except (requests.exceptions.ConnectionError, NoInternetException):
                self.signal_finished.emit({'error': self.locale_keys['internet.required']})
            finally:
                self.app = None


class SearchApps(QThread):
    signal_finished = pyqtSignal(list)

    def __init__(self, manager: ApplicationManager):
        super(SearchApps, self).__init__()
        self.word = None
        self.manager = manager

    def run(self):
        apps_found = []

        if self.word:
            res = self.manager.search(self.word)
            apps_found.extend(res['installed'])
            apps_found.extend(res['new'])

        self.signal_finished.emit(apps_found)
        self.word = None


class InstallApp(AsyncAction):

    signal_finished = pyqtSignal(object)
    signal_error = pyqtSignal(dict)
    signal_output = pyqtSignal(str)

    def __init__(self, manager: ApplicationManager, disk_cache: bool, icon_cache: Cache, locale_keys: dict, app: ApplicationView = None):
        super(InstallApp, self).__init__()
        self.app = app
        self.manager = manager
        self.icon_cache = icon_cache
        self.disk_cache = disk_cache
        self.locale_keys = locale_keys
        self.root_password = None

        self.wait_confirmation = False
        self.msg_confirmation = None

    def run(self):

        if self.app:
            success = False

            try:
                success = self.manager.install(self.app.model, self.root_password, self)

                if success and self.disk_cache:
                    self.app.model.installed = True

                    if self.app.model.supports_disk_cache():
                        icon_data = self.icon_cache.get(self.app.model.base_data.icon_url)
                        self.manager.cache_to_disk(app=self.app.model,
                                                   icon_bytes=icon_data.get('bytes') if icon_data else None,
                                                   only_icon=False)
            except (requests.exceptions.ConnectionError, NoInternetException):
                success = False
                self.signal_output.emit(self.locale_keys['internet.required'])
            finally:
                self.signal_finished.emit(self.app if success else None)
                self.app = None

    def handle(self, proc: SystemProcess) -> bool:
        return self.notify_subproc_outputs(proc, self.signal_output)

    def notify(self, msg: str):
        if msg:
            self.signal_output.emit(msg)

    def show_error(self, title: str, body: str):
        self.signal_error.emit({'title': title, 'body': body})


class AnimateProgress(QThread):

    signal_change = pyqtSignal(int)

    def __init__(self):
        super(AnimateProgress, self).__init__()
        self.progress_value = 0
        self.increment = 5
        self.stop = False

    def run(self):

        current_increment = self.increment

        while not self.stop:
            self.signal_change.emit(self.progress_value)

            if self.progress_value == 100:
                current_increment = -current_increment
            if self.progress_value == 0:
                current_increment = self.increment

            self.progress_value += current_increment

            time.sleep(0.05)

        self.progress_value = 0


class VerifyModels(QThread):

    signal_updates = pyqtSignal()

    def __init__(self, apps: List[ApplicationView] = None):
        super(VerifyModels, self).__init__()
        self.apps = apps

    def run(self):

        if self.apps:

            stop_at = datetime.utcnow() + timedelta(seconds=30)
            last_ready = 0

            while True:
                current_ready = 0

                for app in self.apps:
                    current_ready += 1 if app.model.status == ApplicationStatus.READY else 0

                if current_ready > last_ready:
                    last_ready = current_ready
                    self.signal_updates.emit()

                if current_ready == len(self.apps):
                    self.signal_updates.emit()
                    break

                if stop_at <= datetime.utcnow():
                    break

                time.sleep(0.1)

        self.apps = None


class RefreshApp(AsyncAction):

    signal_finished = pyqtSignal(bool)
    signal_output = pyqtSignal(str)

    def __init__(self, manager: ApplicationManager, app: ApplicationView = None):
        super(RefreshApp, self).__init__()
        self.app = app
        self.manager = manager
        self.root_password = None

    def run(self):

        if self.app:
            success = False

            try:
                process = self.manager.refresh(self.app.model, self.root_password)
                success = self.notify_subproc_outputs(process, self.signal_output)
            except (requests.exceptions.ConnectionError, NoInternetException):
                success = False
                self.signal_output.emit(self.locale_keys['internet.required'])
            finally:
                self.app = None
                self.signal_finished.emit(success)


class FindSuggestions(AsyncAction):

    signal_finished = pyqtSignal(list)

    def __init__(self, man: ApplicationManager):
        super(FindSuggestions, self).__init__()
        self.man = man

    def run(self):
        sugs = self.man.list_suggestions(limit=-1)
        self.signal_finished.emit(sugs if sugs is not None else [])


class ListWarnings(QThread):

    signal_warnings = pyqtSignal(list)

    def __init__(self, man: ApplicationManager, locale_keys: dict):
        super(QThread, self).__init__()
        self.locale_keys = locale_keys
        self.man = man

    def run(self):
        warnings = self.man.list_warnings()
        if warnings:
            self.signal_warnings.emit(warnings)
