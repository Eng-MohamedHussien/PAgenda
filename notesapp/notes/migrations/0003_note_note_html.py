# Generated by Django 3.1.3 on 2020-12-11 13:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('notes', '0002_usersession'),
    ]

    operations = [
        migrations.AddField(
            model_name='note',
            name='note_html',
            field=models.TextField(null=True),
        ),
    ]
