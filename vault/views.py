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

from .models import Credential

def create_credential(request):
    if request.method == 'POST':
        # example only — form handling omitted
        cred = Credential(
            user=request.user,
            platform_type='website',
            name='Gmail',
            username='you@gmail.com',
            url_or_developer='https://gmail.com',
        )
        cred.set_password('your-secret-password')
        cred.save()





from django.shortcuts import render, redirect, get_object_or_404
from .forms import CredentialForm
from .models import Credential
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import JsonResponse
from django.template.loader import render_to_string

@login_required
def dashboard(request):
    search_query = request.GET.get('q', '')
    credentials = Credential.objects.filter(user=request.user)

    if search_query:
        credentials = credentials.filter(
            Q(name__icontains=search_query) |
            Q(username__icontains=search_query) |
            Q(url_or_developer__icontains=search_query)
        )

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        html = render_to_string('vault/partials/credential_list.html', {'credentials': credentials})
        return JsonResponse({'html': html})

    return render(request, 'dashboard/dashboard.html', {'credentials': credentials, 'search_query': search_query})



@login_required
def add_credential(request):
    if request.method == 'POST':
        form = CredentialForm(request.POST)
        if form.is_valid():
            form.save(user=request.user)
            return redirect('dashboard')
    else:
        form = CredentialForm()
    return render(request, 'vault/credential_form.html', {'form': form, 'title': 'Add Credential'})

@login_required
def edit_credential(request, pk):
    cred = get_object_or_404(Credential, pk=pk, user=request.user)
    if request.method == 'POST':
        form = CredentialForm(request.POST, instance=cred)
        if form.is_valid():
            form.save(user=request.user)
            return redirect('dashboard')
    else:
        form = CredentialForm(instance=cred)
    return render(request, 'vault/credential_form.html', {'form': form, 'title': 'Edit Credential'})

@login_required
def delete_credential(request, pk):
    cred = get_object_or_404(Credential, pk=pk, user=request.user)
    if request.method == 'POST':
        cred.delete()
        return redirect('dashboard')
    return render(request, 'vault/delete_confirm.html', {'credential': cred})
