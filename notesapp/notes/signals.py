from .models import UserSession
from django.contrib.auth import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.contrib.sessions.models import Session


@receiver(user_logged_in)
def on_user_logged_in(sender, request, **kwargs):
    sessions = Session.objects.filter(usersession__user=kwargs.get('user'))
    if request.session.session_key:
        sessions = Session.objects.exclude(session_key=request.session.session_key)
    sessions.delete()
    request.session.save()
    UserSession.objects.get_or_create(user=kwargs.get('user'), session=Session.objects.get(pk=request.session.session_key))


@receiver(user_logged_out)
def on_user_logged_out(sender, **kwargs):
    Session.objects.filter(usersession__user=kwargs.get('user')).delete()