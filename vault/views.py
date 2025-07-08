# vault/views.py
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from .forms import RegisterForm
from django.contrib import messages

def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, "Registration successful.")
            return redirect('login')
    else:
        form = RegisterForm()
    return render(request, 'vault/register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        remember = request.POST.get('remember_me')  # May be None

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)

            # Session will expire on browser close unless 'remember_me' is checked
            if remember:
                request.session.set_expiry(1209600)  # 2 weeks in seconds
            else:
                request.session.set_expiry(0)  # Expire on browser close

            return redirect('dashboard')
        else:
            messages.error(request, "Invalid credentials")
    return render(request, 'vault/login.html')


def logout_view(request):
    logout(request)
    return redirect('login')



from django.http import JsonResponse
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def validate_field(request):
    field = request.POST.get("field")
    value = request.POST.get("value")
    response = {}

    if field == "username":
        response["exists"] = User.objects.filter(username=value).exists()
    elif field == "email":
        response["exists"] = User.objects.filter(email=value).exists()
    return JsonResponse(response)

