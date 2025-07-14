from django.db import models
from .utils.crypto import encrypt, decrypt
from django.contrib.auth.models import AbstractUser
from django.conf import settings

from django_otp.plugins.otp_totp.models import TOTPDevice

class CustomUser(AbstractUser):
    # Add a flag to check if 2FA is enabled
    is_2fa_enabled = models.BooleanField(default=False)

    def has_2fa_device(self):
        return TOTPDevice.objects.filter(user=self, confirmed=True).exists()


class Credential(models.Model):
    PLATFORM_CHOICES = [
        ('website', 'Website'),
        ('game', 'Game'),
        ('app', 'Desktop App'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    platform_type = models.CharField(max_length=10, choices=PLATFORM_CHOICES)
    name = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    password_encrypted = models.TextField()
    url_or_developer = models.CharField(max_length=200, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def set_password(self, raw_password):
        self.password_encrypted = encrypt(raw_password)

    def get_password(self):
        return decrypt(self.password_encrypted)

    def __str__(self):
        return f"{self.name} ({self.platform_type})"


from django.db import models

class CyberTip(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    
# a model for session history
class LoginRecord(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.timestamp} ({self.ip_address})"


class SecurityLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    action = models.CharField(max_length=100)
    description = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)


from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()

class BackupCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=20)
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    last_sent_at = models.DateTimeField(default=timezone.now)
