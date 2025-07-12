# vault/views.py
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from .forms import RegisterForm
from django.contrib import messages
from .models import Credential, SecurityLog

from django.contrib.auth import login

def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)

            # Redirect to 2FA setup page immediately
            # return redirect('two_factor:setup')  # correct name from two_factor.urls
            return redirect('setup_2fa')  # redirect to TOTP setup
    else:
        form = RegisterForm()

    return render(request, 'vault/register.html', {'form': form})


# def register_view(request):
#     if request.user.is_authenticated:
#         return redirect('login')

#     if request.method == 'POST':
#         form = RegisterForm(request.POST)
#         if form.is_valid():
#             form.save()
#             messages.success(request, "Registration successful. Please log in.")
#             return redirect('login')

#     else:
#         form = RegisterForm()

#     return render(request, 'vault/register.html', {'form': form})

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        remember = request.POST.get('remember_me')  # checkbox in login form

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)

            if remember:
                request.session.set_expiry(1209600)  # 2 weeks
            else:
                request.session.set_expiry(900)  # 15 minutes for example

            return redirect('dashboard')
        else:
            messages.error(request, "Invalid credentials")

    return render(request, 'vault/login.html')


def logout_view(request):
    logout(request)
    return redirect('login')



from django.http import JsonResponse
from django.contrib.auth import get_user_model
User = get_user_model()

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

    credential = get_object_or_404(Credential, pk=pk, user=request.user)  # Define it first
    
    SecurityLog.objects.create(
    user=request.user,
    action="edit_credential",
    description=f"Edited credential: {credential.name}"
)


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

    credential = get_object_or_404(Credential, pk=pk, user=request.user)  # Define it first

    SecurityLog.objects.create(
    user=request.user,
    action="edit_credential",
    description=f"Edited credential: {credential.name}"
)

    cred = get_object_or_404(Credential, pk=pk, user=request.user)
    if request.method == 'POST':
        cred.delete()
        return redirect('dashboard')
    return render(request, 'vault/delete_confirm.html', {'credential': cred})


from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages

@login_required
def profile_settings(request):
    if request.method == 'POST':
        request.user.email = request.POST.get('email')
        request.user.save()
        messages.success(request, "Profile updated.")
    return render(request, 'account/profile_settings.html')




from django.contrib.auth.decorators import login_required
from .models import LoginRecord, SecurityLog
from django.contrib.auth.decorators import login_required
from .models import LoginRecord, SecurityLog

@login_required
def user_profile(request):
    user = request.user
    
    login_logs = LoginRecord.objects.filter(user=user).order_by('-timestamp')[:5]
    security_logs = SecurityLog.objects.filter(user=user).order_by('-timestamp')[:5]

    return render(request, 'account/profile.html', {
        'user': user,
        'login_logs': login_logs,
        'security_logs': security_logs,
    })



@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password was successfully updated!')
            return redirect('profile_settings')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'account/change_password.html', {'form': form})


from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from .forms import ProfileUpdateForm
from .models import SecurityLog
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django_otp.decorators import otp_required

@login_required
def profile_view(request):
    user = request.user
    security_logs = SecurityLog.objects.filter(user=user).order_by('-timestamp')[:10]

    if request.method == 'POST':
        form = ProfileUpdateForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request, user)  # Important: Keep user logged in after password change
            messages.success(request, 'Profile updated successfully.')
            return redirect('profile')
    else:
        form = ProfileUpdateForm(instance=user)

    return render(request, 'account/profile.html', {
        'form': form,
        'security_logs': security_logs
    })



from django.contrib.auth import logout
from django.contrib import messages
from django.shortcuts import redirect

def logout_due_to_inactivity(request):
    logout(request)
    messages.warning(request, "You've been logged out due to inactivity.")
    return redirect('login')


from django_otp.plugins.otp_totp.models import TOTPDevice

@login_required
def toggle_2fa(request):
    if request.method == 'POST':
        if request.user.has_2fa_device():
            # Turn off 2FA: Delete the device
            TOTPDevice.objects.filter(user=request.user).delete()
            request.user.is_2fa_enabled = False
        else:
            # Turn on 2FA: Redirect to setup
            return redirect('two_factor:setup')

        request.user.save()
        messages.success(request, "2FA settings updated.")
    return redirect('profile')


# vault/views.py
from django_otp.plugins.otp_totp.models import TOTPDevice
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django_otp.util import random_hex
import qrcode.image.svg
from io import BytesIO
import pyotp

@login_required
def setup_2fa(request):
    user = request.user

    # Create a TOTP device if not exists
    device, created = TOTPDevice.objects.get_or_create(user=user, confirmed=False)

    # Generate key if new
    if created or not device.key:
        device.key = random_hex()
        device.save()

    # Generate the URI and QR code
    key = device.key
    otp_uri = pyotp.totp.TOTP(key).provisioning_uri(
        name=user.email or user.username,
        issuer_name="Password Manager"
    )

    # Generate QR code as inline SVG
    img = qrcode.make(otp_uri, image_factory=qrcode.image.svg.SvgImage)
    buffer = BytesIO()
    img.save(buffer)
    qr_svg = buffer.getvalue().decode()

    # On POST, verify OTP
    if request.method == 'POST':
        token = request.POST.get('token')
        totp = pyotp.TOTP(key)
        if totp.verify(token):
            device.confirmed = True
            device.save()
            return redirect('profile')  # or dashboard
        else:
            return render(request, 'account/setup_2fa.html', {
                'qr_svg': qr_svg,
                'error': 'Invalid OTP. Try again.'
            })

    return render(request, 'account/setup_2fa.html', {'qr_svg': qr_svg})


@login_required
def disable_2fa(request):
    user = request.user
    TOTPDevice.objects.filter(user=user).delete()
    user.is_2fa_enabled = False
    user.save()
    messages.success(request, "Two-factor authentication has been disabled.")
    return redirect('profile')
