import os

from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.conf import settings

class Command(BaseCommand):
    help = 'DBの初期化から初期データの投入までを実施します。DBファイルが削除されるので、ご注意ください。'

    def handle(self, *args, **options):
        try:
            db_path = settings.DATABASES['default']['NAME']
            if os.path.exists(db_path):
                os.remove(db_path)
                self.stdout.write(self.style.SUCCESS(f'データベースファイル {db_path} を削除しました。'))

            #call_command('makemigrations')
            call_command('migrate')
            self.stdout.write(self.style.SUCCESS('マイグレーションを実行しました。'))

            call_command('loaddata', 'user.json')
            self.stdout.write(self.style.SUCCESS('初期データを投入しました。'))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'エラーが発生しました: {e}'))

