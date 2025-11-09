from django.contrib import admin
from django.urls import path
from django.urls import re_path as url
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    url(r'^$', views.index, name='index'),
    url(r'^login/*', views.admins_login, name='admins_login'),
    url(r'^logout/$', views.admins_logout, name='admins_logout'),
    url(r'^admins/main*', views.main, name='main'),
    url(r'^sqlinjection/$', views._423_sql_injection, name='sqlinjection'),
    url(r'^secondordersqlinjection/$', views._442_second_order_sql_injection, name='secondordersqlinjection'),
    url(r'^xss/$', views._532_xss, name='xss'),
    url(r'^oscommandinjection/$', views._612_os_command_injection, name='oscommandinjection'),
    url(r'^codeinjection/$', views._642_code_injection, name='codeinjection'),
    url(r'^admins/csrf/$', views._712_csrf, name='csrf'),
    url(r'^ping/$', views.ping, name='ping'),
    url(r'^pathtraversal/$', views._812_path_traversal, name='pathtraversal'),
    url(r'^xxe/$', views._822_xxe, name='xxe'),
    url(r'^dbuserlist/$', views.db_user_list, name='dbuserlist'),
]
