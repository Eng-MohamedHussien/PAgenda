from django.shortcuts import render, get_object_or_404, reverse, redirect
from .forms import signupForm, noteForm, filterForm
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.forms import AuthenticationForm
# , PasswordResetForm, SetPasswordForm
from django.contrib.auth.models import User
from .models import Note
from django.contrib.auth.decorators import login_required
'''
from django.core.mail import send_mail, BadHeaderError
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, force_text
from django.contrib.auth.hashers import check_password
'''


def auth_logout(request):
    logout(request)
    return redirect('home')


def auth_login(request):
    if request.method == 'POST':
        login_form = AuthenticationForm(request, data=request.POST)
        if login_form.is_valid():
            username = request.POST['username']
            password = request.POST['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                redirect_url = reverse('profile', args=[user.id])
                return redirect(redirect_url)
    else:
        login_form = AuthenticationForm()
    return render(request, 'notes/login.html', {'form': login_form, 'subTitle': 'Login Page'})


def signup(request):
    if request.method == 'POST':
        signup_form = signupForm(request.POST)
        if signup_form.is_valid():
            user = signup_form.save()
            login(request, user)
            return redirect(reverse('profile', args=[user.id]))
    else:
        signup_form = signupForm()
    return render(request, 'notes/signup.html', {'form': signup_form, 'subTitle': 'Signup Page'})


@login_required(login_url='login')
def profile(request, id):
    form = filterForm()
    user = get_object_or_404(User, pk=id)
    notes = user.note_set.all()
    return render(request, 'notes/profile.html', {'user': user, 'form': form, 'notes': notes, 'subTitle': 'Notes'})


def home(request):
    return render(request, 'notes/home.html', {'subTitle': 'Write your notes'})


@login_required(login_url='login')
def add_note(request, id):
    if request.method == 'POST':
        form = noteForm(request.POST)
        if form.is_valid():
            note = form.save(commit=False)
            note.author = get_object_or_404(User, pk=id)
            form.save()
            return redirect(reverse('profile', args=[id]))
    else:
        form = noteForm()
    return render(request, 'notes/crud_note.html', {'form': form, 'subTitle': 'Create Note'})


@login_required(login_url='login')
def delete_note(request, user_id, note_id):
    note = get_object_or_404(Note, pk=note_id)
    note.delete()
    return redirect(reverse('profile', args=[user_id]))


@login_required(login_url='login')
def update_note(request, user_id, note_id):
    note = get_object_or_404(Note, pk=note_id)
    form = noteForm(request.POST or None, instance=note)
    if form.is_valid():
        form.save()
        return redirect(reverse('profile', args=[user_id]))
    return render(request, 'notes/crud_note.html', {'form': form, 'subTitle': 'Update Note'})


@login_required(login_url='login')
def filter_date(request, id):
    user = get_object_or_404(User, pk=id)
    choice = "1"
    if request.method == 'GET':
        form = filterForm(request.GET)
        if form.is_valid():
            choice = request.GET['selected_choice']
    else:
        form = filterForm()
    if choice == "2":
        notes = user.note_set.all().order_by('-created_at')
    elif choice == "3":
        notes = user.note_set.all().order_by('-modified_at')
    else:
        notes = user.note_set.all()

    return render(request, 'notes/profile.html', {'user': user, 'form': form, 'notes': notes, 'subTitle': 'Notes'})


'''
def password_reset(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = request.POST['email']
            users = User.objects.filter(email=email)
            if users.exists():
                for user in users:
                    subject = "Password Reset Requested"
                    email_template_name = "notes/password_reset_email.txt"
                    c = {
                        "email": user.email,
                        'domain': '127.0.0.1:8000',
                        'site_name': 'Website',
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "user": user,
                        'token': default_token_generator.make_token(user),
                        'protocol': 'http',
                    }
                    email = render_to_string(email_template_name, c)
                    try:
                        send_mail(subject, email, 'admin@example.com',
                                  [user.email], fail_silently=False)
                    except BadHeaderError:
                        return HttpResponse('Invalid header found.')
                    return redirect("/password_reset/done/")
    else:
        form = PasswordResetForm()

    return render(request, 'notes/password_reset.html', {'form': form, 'subTitle': 'Reset Password Page'})


def password_reset_done(request):
    return render(request, 'notes/password_reset_done.html', {'subTitle': 'Sent Reset Password Email'})


def password_reset_confirm(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    # checking if the user exists, if the token is valid.
    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                user = form.save()
                return redirect("/password_reset_complete/")
        else:
            form = SetPasswordForm(user)
    return render(request, 'notes/password_reset_confirm.html', {'subTitle': 'Enter New Password', 'form': form})


def password_reset_complete(request):
    return render(request, 'notes/password_reset_complete.html', {'subTitle': 'Reset Passwdeord Completed'})
'''
