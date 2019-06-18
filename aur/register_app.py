# used for AUR installation
import os
import sys
from pathlib import Path

desktop_file = """
[Desktop Entry]
Type = Application
Name = fpakman
Categories = System;
Comment = Manage your Flatpak applications
Exec = /usr/bin/fpakman
Icon = /usr/lib/python{version}/site-packages/fpakman/resources/img/flathub_45.svg
""".format(version="{}.{}".format(sys.version_info.major, sys.version_info.minor))

apps_path = '{}/.local/share/applications'.format(str(Path.home()))

if not os.path.exists(apps_path):
    os.mkdir(apps_path)

file_path = '{}/fpakman.desktop'.format(apps_path)

with open(file_path, 'w+') as f:
    f.write(desktop_file)
