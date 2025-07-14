from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from .models import LoginRecord


# Signal receiver to log user login events
# This function is triggered whenever a user logs in, logging their IP address and user agent.
@receiver(user_logged_in)
def log_login(sender, request, user, **kwargs):
    LoginRecord.objects.create(
        user=user,
        ip_address=request.META.get('REMOTE_ADDR', 'unknown'),
        user_agent=request.META.get('HTTP_USER_AGENT', 'unknown'),
    )
