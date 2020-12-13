from django.urls import path
from . import views
from django.contrib.auth.views import PasswordResetConfirmView, PasswordResetDoneView, PasswordResetView, PasswordResetCompleteView

urlpatterns = [
    path('signup/', views.signup, name='signup'),
    path('login/', views.auth_login, name='login'),
    path('logout/', views.auth_logout, name='logout'),
    path('profile/<int:id>', views.profile, name='profile'),
    path('home/', views.home, name='home'),
    path('', views.home, name='home'),
    path('add_note/<int:id>', views.add_note, name='add_note'),
    path('delete_note/<int:user_id>/<int:note_id>',
         views.delete_note, name='delete_note'),
    path('update_note/<int:user_id>/<int:note_id>',
         views.update_note, name='update_note'),
    path('filter/<int:id>', views.filter_date, name='filter_date'),
    path('password_reset/', PasswordResetView.as_view(
        template_name='notes/password_reset.html'), name='password_reset'),
    path('password_reset/done/', PasswordResetDoneView.as_view(template_name='notes/password_reset_done.html'),
         name='password_reset_done'),
    path('password_reset_confirm/<uidb64>/<token>',
         PasswordResetConfirmView.as_view(template_name='notes/password_reset_confirm.html'), name='password_reset_confirm'),
    path('password_reset_complete/', PasswordResetCompleteView.as_view(template_name='notes/password_reset_complete.html'),
         name='password_reset_complete'),
]
