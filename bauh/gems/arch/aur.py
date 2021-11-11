import logging
import os
import re
import urllib.parse
from typing import Set, List, Iterable, Dict, Optional, Tuple

import requests

from bauh import __app_name__
from bauh.api.http import HttpClient
from bauh.commons import system
from bauh.commons.system import SystemProcess, new_subprocess, SimpleProcess, ProcessHandler
from bauh.commons.user import is_root
from bauh.gems.arch import AUR_INDEX_FILE, git, CUSTOM_MAKEPKG_FILE
from bauh.gems.arch.exceptions import PackageNotFoundException

URL_INFO = 'https://aur.archlinux.org/rpc/?v=5&type=info&'
URL_SRC_INFO = 'https://aur.archlinux.org/cgit/aur.git/plain/.SRCINFO?h='
URL_SEARCH = 'https://aur.archlinux.org/rpc/?v=5&type=search&arg='
URL_INDEX = 'https://aur.archlinux.org/packages.gz'

RE_SRCINFO_KEYS = re.compile(r'(\w+)\s+=\s+(.+)\n')
RE_SPLIT_DEP = re.compile(r'[<>]?=')

KNOWN_LIST_FIELDS = ('validpgpkeys',
                     'checkdepends',
                     'checkdepends_x86_64',
                     'checkdepends_i686',
                     'depends',
                     'depends_x86_64',
                     'depends_i686',
                     'optdepends',
                     'optdepends_x86_64',
                     'optdepends_i686',
                     'sha256sums',
                     'sha256sums_x86_64',
                     'sha512sums',
                     'sha512sums_x86_64',
                     'source',
                     'source_x86_64',
                     'source_i686',
                     'makedepends',
                     'makedepends_x86_64',
                     'makedepends_i686',
                     'provides',
                     'conflicts')


def map_pkgbuild(pkgbuild: str) -> dict:
    return {attr: val.replace('"', '').replace("'", '').replace('(', '').replace(')', '') for attr, val in re.findall(r'\n(\w+)=(.+)', pkgbuild)}


def map_srcinfo(string: str, pkgname: Optional[str], fields: Set[str] = None) -> dict:
    subinfos, subinfo = [], {}

    key_fields = {'pkgname', 'pkgbase'}

    for field in RE_SRCINFO_KEYS.findall(string):
        key = field[0].strip()
        val = field[1].strip()

        if subinfo and key in key_fields:
            subinfos.append(subinfo)
            subinfo = {key: val}
        elif not fields or key in fields:
            if key not in subinfo:
                subinfo[key] = {val} if key in KNOWN_LIST_FIELDS else val
            else:
                if not isinstance(subinfo[key], set):
                    subinfo[key] = {subinfo[key]}

                subinfo[key].add(val)

    if subinfo:
        subinfos.append(subinfo)

    pkgnames = {s['pkgname'] for s in subinfos if 'pkgname' in s}
    return merge_subinfos(subinfos=subinfos,
                          pkgname=None if (not pkgname or len(pkgnames) == 1 or pkgname not in pkgnames) else pkgname,
                          fields=fields)


def merge_subinfos(subinfos: List[dict], pkgname: Optional[str] = None, fields: Optional[Set[str]] = None) -> dict:
    info = {}
    for subinfo in subinfos:
        if not pkgname or subinfo.get('pkgname') in {None, pkgname}:
            for key, val in subinfo.items():
                if not fields or key in fields:
                    current_val = info.get(key)

                    if current_val is None:
                        info[key] = val
                    else:
                        if not isinstance(current_val, set):
                            current_val = {current_val}
                            info[key] = current_val

                        if isinstance(val, set):
                            current_val.update(val)
                        else:
                            current_val.add(val)

    for field in info.keys():
        val = info.get(field)

        if isinstance(val, set):
            info[field] = [*val]

    return info


class AURClient:

    def __init__(self, http_client: HttpClient, logger: logging.Logger, x86_64: bool):
        self.http_client = http_client
        self.logger = logger
        self.x86_64 = x86_64
        self.srcinfo_cache = {}

    def search(self, words: str) -> dict:
        return self.http_client.get_json(URL_SEARCH + words)

    def get_info(self, names: Iterable[str]) -> List[dict]:
        try:
            res = self.http_client.get_json(URL_INFO + self._map_names_as_queries(names))
            return res['results'] if res and res.get('results') else []
        except:
            return []

    def get_src_info(self, name: str, real_name: Optional[str] = None) -> dict:
        srcinfo = self.srcinfo_cache.get(name)

        if srcinfo:
            return srcinfo

        res = self.http_client.get(URL_SRC_INFO + urllib.parse.quote(name))

        if res and res.text:
            srcinfo = map_srcinfo(string=res.text, pkgname=real_name if real_name else name)

            if srcinfo:
                self.srcinfo_cache[name] = srcinfo

            return srcinfo

        self.logger.warning('No .SRCINFO found for {}'.format(name))
        self.logger.info('Checking if {} is based on another package'.format(name))
        # if was not found, it may be based on another package.
        infos = self.get_info({name})

        if infos:
            info = infos[0]

            info_name = info.get('Name')
            info_base = info.get('PackageBase')
            if info_name and info_base and info_name != info_base:
                self.logger.info('{p} is based on {b}. Retrieving {b} .SRCINFO'.format(p=info_name, b=info_base))
                srcinfo = self.get_src_info(name=info_base, real_name=info_name)

                if srcinfo:
                    self.srcinfo_cache[name] = srcinfo

                return srcinfo

    def extract_required_dependencies(self, srcinfo: dict) -> Set[str]:
        deps = set()

        for attr in ('makedepends',
                     'makedepends_{}'.format('x86_64' if self.x86_64 else 'i686'),
                     'depends',
                     'depends_{}'.format('x86_64' if self.x86_64 else 'i686'),
                     'checkdepends',
                     'checkdepends_{}'.format('x86_64' if self.x86_64 else 'i686')):

            if srcinfo.get(attr):
                deps.update(srcinfo[attr])

        return deps

    def get_required_dependencies(self, name: str) -> Set[str]:
        info = self.get_src_info(name)

        if not info:
            raise PackageNotFoundException(name)

        return self.extract_required_dependencies(info)

    def _map_names_as_queries(self, names) -> str:
        return '&'.join(['arg[{}]={}'.format(i, urllib.parse.quote(n)) for i, n in enumerate(names)])

    def read_local_index(self) -> dict:
        self.logger.info('Checking if the cached AUR index file exists')
        if os.path.exists(AUR_INDEX_FILE):
            self.logger.info('Reading AUR index file from {}'.format(AUR_INDEX_FILE))
            index = {}
            with open(AUR_INDEX_FILE) as f:
                for l in f.readlines():
                    if l:
                        lsplit = l.split('=')
                        index[lsplit[0]] = lsplit[1].strip()
            self.logger.info("AUR index file read")
            return index
        self.logger.warning('The AUR index file was not found')

    def download_names(self) -> Set[str]:
        self.logger.info('Downloading AUR index')
        try:
            res = self.http_client.get(URL_INDEX)

            if res and res.text:
                return {n.strip() for n in res.text.split('\n') if n and not n.startswith('#')}
            else:
                self.logger.warning('No data returned from: {}'.format(URL_INDEX))
        except requests.exceptions.ConnectionError:
            self.logger.warning('No internet connection: could not pre-index packages')

        self.logger.info("Finished")

    def read_index(self) -> Iterable[str]:
        try:
            index = self.read_local_index()

            if not index:
                self.logger.warning("Cached AUR index file not found")
                pkgnames = self.download_names()

                if pkgnames:
                    return pkgnames
                else:
                    self.logger.warning("Could not load AUR index on the context")
                    return set()
            else:
                return index.values()
        except:
            return set()

    def clean_caches(self):
        self.srcinfo_cache.clear()

    def map_update_data(self, pkgname: str, latest_version: Optional[str], srcinfo: Optional[dict] = None) -> dict:
        info = self.get_src_info(pkgname) if not srcinfo else srcinfo

        provided = set()
        provided.add(pkgname)

        if info:
            provided.add('{}={}'.format(pkgname, info['pkgver']))
            if info.get('provides'):
                provided.update(info.get('provides'))

            return {'c': info.get('conflicts'), 's': None, 'p': provided, 'r': 'aur',
                    'v': info['pkgver'], 'd': self.extract_required_dependencies(info),
                    'b': info.get('pkgbase', pkgname)}
        else:
            if latest_version:
                provided.add('{}={}'.format(pkgname, latest_version))

            return {'c': None, 's': None, 'p': provided, 'r': 'aur', 'v': latest_version, 'd': set(), 'b': pkgname}

    def fill_update_data(self, output: Dict[str, dict], pkgname: str, latest_version: str, srcinfo: dict = None):
        data = self.map_update_data(pkgname=pkgname, latest_version=latest_version, srcinfo=srcinfo)
        output[pkgname] = data


class AURBuilder:

    ROOT_BUILDER_USER = __app_name__
    RE_UNKNOWN_GPG_KEY = re.compile(r'\(unknown public key (\w+)\)')
    RE_DEPS_PATTERN = re.compile(r'\n?\s+->\s(.+)\n')

    def __init__(self):
        self._root = is_root()

    # TODO always check if builder user exist

    def _gen_root_builder_cmd(self, cmd: list) -> list:
        return ['su', self.ROOT_BUILDER_USER, '-c', '"{}"'.format(' '.join(cmd))]

    def new_system_process(self, cmd: list) -> SystemProcess:
        if self._root:
            final_cmd = self._gen_root_builder_cmd(cmd)
        else:
            final_cmd = cmd

        return SystemProcess(new_subprocess(final_cmd))

    def _run_cmd(self, cmd: str, **kwargs) -> str:
        if self._root:
            final_cmd = ' '.join(self._gen_root_builder_cmd(cmd.split(" ")))
        else:
            final_cmd = cmd

        return system.run_cmd(final_cmd, **kwargs)

    def clone_repository(self, url: str, cwd: Optional[str], depth: int = -1) -> SimpleProcess:
        cmd = ['git', 'clone', url]

        if depth > 0:
            cmd.append(f'--depth={depth}')

        return SimpleProcess(cmd=self._gen_root_builder_cmd(cmd) if self._root else cmd, cwd=cwd)

    def gen_srcinfo(self, build_dir: str, custom_pkgbuild_path: Optional[str] = None) -> str:
        return self._run_cmd('makepkg --printsrcinfo{}'.format(' -p {}'.format(custom_pkgbuild_path) if custom_pkgbuild_path else ''),
                             cwd=build_dir)

    def check_issues(self, pkgdir: str, optimize: bool, missing_deps: bool, handler: ProcessHandler, custom_pkgbuild: Optional[str] = None) -> dict:
        res = {}

        cmd = ['makepkg', '-ALcfm', '--check', '--noarchive', '--nobuild', '--noprepare']

        if not missing_deps:
            cmd.append('--nodeps')

        if custom_pkgbuild:
            cmd.append('-p')
            cmd.append(custom_pkgbuild)

        if optimize:
            if os.path.exists(CUSTOM_MAKEPKG_FILE):
                handler.watcher.print('Using custom makepkg.conf -> {}'.format(CUSTOM_MAKEPKG_FILE))
                cmd.append('--config={}'.format(CUSTOM_MAKEPKG_FILE))
            else:
                handler.watcher.print('Custom optimized makepkg.conf ( {} ) not found'.format(CUSTOM_MAKEPKG_FILE))

        final_cmd = self._gen_root_builder_cmd(cmd) if self._root else cmd
        success, output = handler.handle_simple(SimpleProcess(final_cmd, cwd=pkgdir, shell=True))

        if missing_deps and 'Missing dependencies' in output:
            res['missing_deps'] = self.RE_DEPS_PATTERN.findall(output)

        gpg_keys = self.RE_UNKNOWN_GPG_KEY.findall(output)

        if gpg_keys:
            res['gpg_key'] = gpg_keys[0]

        if 'One or more files did not pass the validity check' in output:
            res['validity_check'] = True

        return res

    def makepkg(self, pkgdir: str, optimize: bool, handler: ProcessHandler, custom_pkgbuild: Optional[str] = None) -> Tuple[bool, str]:
        cmd = ['makepkg', '-ALcsmf', '--skipchecksums', '--nodeps']

        if custom_pkgbuild:
            cmd.append('-p')
            cmd.append(custom_pkgbuild)

        if optimize:
            if os.path.exists(CUSTOM_MAKEPKG_FILE):
                handler.watcher.print('Using custom makepkg.conf -> {}'.format(CUSTOM_MAKEPKG_FILE))
                cmd.append('--config={}'.format(CUSTOM_MAKEPKG_FILE))
            else:
                handler.watcher.print('Custom optimized makepkg.conf ( {} ) not found'.format(CUSTOM_MAKEPKG_FILE))

        final_cmd = self._gen_root_builder_cmd(cmd) if self._root else cmd
        return handler.handle_simple(SimpleProcess(final_cmd, cwd=pkgdir, shell=True))

    def update_srcinfo(self, project_dir: str) -> bool:
        updated_src = self._run_cmd('makepkg --printsrcinfo', cwd=project_dir)

        if updated_src:

            # with open('{}/.SRCINFO'.format(project_dir), 'w+') as f:  # FIXME
            #     f.write(updated_src)

            return True

        return False

    def list_output_files(self, project_dir: str, custom_pkgbuild_path: Optional[str] = None) -> Set[str]:
        output = self._run_cmd(cmd='makepkg --packagelist{}'.format(' -p {}'.format(custom_pkgbuild_path) if custom_pkgbuild_path else ''),
                               print_error=False,
                               cwd=project_dir)

        if output:
            return {p.strip() for p in output.split('\n') if p}

        return set()


def is_supported(arch_config: dict) -> bool:
    return arch_config['aur'] and git.is_installed()

