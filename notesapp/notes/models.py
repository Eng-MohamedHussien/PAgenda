from django.db import models
from django.contrib.auth.models import User
from django.conf import settings
from django.contrib.sessions.models import Session
import markdown2


class UserSession(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             on_delete=models.CASCADE)
    session = models.OneToOneField(Session, on_delete=models.CASCADE)


class Note(models.Model):
    note_title = models.CharField(max_length=200)
    note_content = models.TextField()
    note_html = models.TextField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)
    author = models.ForeignKey(User, on_delete=models.CASCADE)

    def save(self, *args, **kwargs):
        self.note_html = markdown2.markdown(self.note_content)
        super(Note, self).save(*args, **kwargs)

    def __str__(self):
        return "{0} created at {1} by {2}: {3}".format(self.note_title, self.created_at, self.author.username, self.note_html)
