# vault/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from .forms import RegisterForm, CredentialForm, ProfileUpdateForm
from django.contrib import messages
from .models import Credential, SecurityLog, BackupCode, LoginRecord
from .decorators import two_factor_required
from django.contrib.auth import get_user_model

from django_otp.plugins.otp_totp.models import TOTPDevice

from django.http import JsonResponse

from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.template.loader import render_to_string

from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash

from django_otp.decorators import otp_required

import pyotp, qrcode, base64, os, binascii, json, secrets, time
from io import BytesIO

from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import timedelta


User = get_user_model()



# Register view with immediate 2FA setup redirect

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



# Login view with 2FA support

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



# Logout view

@login_required
def logout_view(request):
    logout(request)
    return redirect('login')



# AJAX view to validate unique fields like username or email

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



# view to create a new credential
@login_required
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



# view to render the dashboard with credentials

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



# view to add a new credential

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



# view to edit a credential

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



# view to delete a credential

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



# Profile settings view

@login_required
def profile_settings(request):
    if request.method == 'POST':
        request.user.email = request.POST.get('email')
        request.user.save()
        messages.success(request, "Profile updated.")
    return render(request, 'account/profile_settings.html')



# User profile view with login history and security logs

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



# Change password view

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



# Profile view with 2FA status and update form

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



# View to log out due to inactivity

def logout_due_to_inactivity(request):
    logout(request)
    messages.warning(request, "You've been logged out due to inactivity.")
    return redirect('login')



# View to toggle 2FA on/off

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


# View to set up 2FA

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



# View to disable 2FA

@login_required
def disable_2fa(request):
    user = request.user
    TOTPDevice.objects.filter(user=user).delete()
    user.is_2fa_enabled = False  # Unset flag
    user.save()
    messages.success(request, "Two-factor authentication has been disabled.")
    return redirect('profile')



# view to load the 2FA status via AJAX in profile page without page reload
# This view checks if the user has a confirmed TOTP device

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



# view to send backup code via email
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

            cooldown_period = timedelta(minutes=5)
            now = timezone.now()

            # Get or create a backup code
            code = BackupCode.objects.filter(user=user, used=False).order_by('-last_sent_at').first()
            if code and now - code.last_sent_at < cooldown_period:
                remaining = int((cooldown_period - (now - code.last_sent_at)).total_seconds())
                return JsonResponse({
                    'success': False,
                    'message': f"Please wait {remaining} seconds before requesting a new backup code.",
                    'cooldown': remaining
                })

            if not code:
                code = BackupCode.objects.create(user=user, code=secrets.token_hex(4))
            code.last_sent_at = now
            code.save()

            # Send the email
            send_mail(
                subject="Your 2FA Backup Code",
                message=f"Your backup code is: {code.code}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )

            return JsonResponse({'success': True, 'message': 'Backup code sent.', 'cooldown': 300})

        except Exception as e:
            return JsonResponse({'success': False, 'message': f'Error: {str(e)}'})

    return JsonResponse({'success': False, 'message': 'Invalid request'})
