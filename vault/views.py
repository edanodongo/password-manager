# vault/views.py
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from .forms import RegisterForm
from django.contrib import messages
from .models import Credential, SecurityLog
from .decorators import two_factor_required

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

from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.shortcuts import render, redirect
from django_otp.plugins.otp_totp.models import TOTPDevice
from django.contrib.auth import get_user_model
from .models import BackupCode  # make sure this is correct

User = get_user_model()

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        otp_token = request.POST.get('otp_token')  # optional
        remember = request.POST.get('remember_me')

        # Step 1: Authenticate user credentials
        user = authenticate(request, username=username, password=password)

        if user is not None:
            device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
            has_2fa = device is not None

            if has_2fa:
                if not otp_token:
                    messages.error(request, "OTP or backup code is required.")
                    return render(request, 'vault/login.html', {'username': username, 'otp_required': True})

                # Try verifying TOTP
                if device.verify_token(otp_token):
                    login(request, user)
                else:
                    # Check for valid backup code
                    backup = BackupCode.objects.filter(user=user, code=otp_token, used=False).first()
                    if backup:
                        backup.used = True
                        backup.save()
                        login(request, user)
                        messages.warning(request, "Backup code used. Please reconfigure 2FA.")
                        return redirect('setup_2fa')  # force new 2FA setup
                    else:
                        messages.error(request, "Invalid OTP or backup code.")
                        return render(request, 'vault/login.html', {'username': username, 'otp_required': True})
            else:
                # No 2FA required
                login(request, user)

            # Sync 2FA flag
            user.is_2fa_enabled = TOTPDevice.objects.filter(user=user, confirmed=True).exists()
            user.save()

            # Session expiry
            request.session.set_expiry(1209600 if remember else 900)

            return redirect('dashboard')
        else:
            messages.error(request, "Invalid username or password.")

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
@two_factor_required
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
@two_factor_required
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

import pyotp
import qrcode
import base64
from io import BytesIO
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django_otp.plugins.otp_totp.models import TOTPDevice
from django.contrib import messages
import os
import binascii

@login_required
def setup_2fa(request):
    user = request.user

    # Get or create unconfirmed device
    device, created = TOTPDevice.objects.get_or_create(user=user, confirmed=False)

    if created or not device.key:
        # Generate raw secret (10 bytes = 80 bits)
        raw_key = os.urandom(10)

        # Store HEX for django-otp
        hex_key = binascii.hexlify(raw_key).decode()
        device.key = hex_key
        device.save()

    # Convert hex key → base32 for TOTP (pyotp)
    raw_key_bytes = binascii.unhexlify(device.key)
    base32_key = base64.b32encode(raw_key_bytes).decode('utf-8').replace('=', '')

    # Generate provisioning URI
    totp = pyotp.TOTP(base32_key)
    otp_uri = totp.provisioning_uri(name=user.email or user.username, issuer_name="Password Manager")

    # Generate QR Code as base64 PNG
    qr = qrcode.make(otp_uri)
    buffer = BytesIO()
    qr.save(buffer, format='PNG')
    qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    qr_data_uri = f"data:image/png;base64,{qr_base64}"

    if request.method == 'POST':
        code = request.POST.get('token')
        if totp.verify(code):
            device.confirmed = True
            device.save()
            user.is_2fa_enabled = True
            user.save()
            messages.success(request, "2FA has been successfully enabled.")
            return redirect('dashboard')

        messages.error(request, "Invalid OTP code. Please try again.")

    return render(request, 'account/setup_2fa.html', {
        'qr_code': qr_data_uri
    })


@login_required
def disable_2fa(request):
    user = request.user
    TOTPDevice.objects.filter(user=user).delete()
    user.is_2fa_enabled = False  # ✅ Unset flag
    user.save()
    messages.success(request, "Two-factor authentication has been disabled.")
    return redirect('profile')

# view to load the 2FA status via AJAX in profile page without page reload
# from django.http import JsonResponse
# from django.contrib.auth.decorators import login_required

# @login_required
# def check_2fa_status(request):
#     is_enabled = request.user.is_2fa_enabled
#     return JsonResponse({'is_2fa_enabled': is_enabled})



from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json
from django.contrib.auth import get_user_model
from django_otp.plugins.otp_totp.models import TOTPDevice

@csrf_exempt
def check_2fa_status(request):
    data = json.loads(request.body)
    username = data.get('username')
    User = get_user_model()
    try:
        user = User.objects.get(username=username)
        is_2fa_enabled = TOTPDevice.objects.filter(user=user, confirmed=True).exists()
    except User.DoesNotExist:
        is_2fa_enabled = False

    return JsonResponse({'is_2fa_enabled': is_2fa_enabled})

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json
from .models import BackupCode
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings
import secrets

User = get_user_model()

@csrf_exempt
def send_backup_code_email(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            user = User.objects.filter(username=username).first()

            if not user:
                return JsonResponse({'success': False, 'message': 'User not found'})

            if not user.is_2fa_enabled:
                return JsonResponse({'success': False, 'message': '2FA is not enabled for this user'})

            # Get or generate backup code
            code = BackupCode.objects.filter(user=user, used=False).first()
            if not code:
                new_code = secrets.token_hex(4)
                BackupCode.objects.create(user=user, code=new_code)
                code_to_send = new_code
            else:
                code_to_send = code.code

            send_mail(
                subject="Your 2FA Backup Code",
                message=f"Here is your backup code: {code_to_send}\n\nOnly use this if you can't access your authenticator app.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )

            return JsonResponse({'success': True, 'message': 'Backup code has been sent to your email.'})

        except Exception as e:
            return JsonResponse({'success': False, 'message': f'Error: {str(e)}'})

    return JsonResponse({'success': False, 'message': 'Invalid request'})
