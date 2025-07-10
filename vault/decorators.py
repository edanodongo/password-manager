from functools import wraps
from django_otp import user_has_device
from django_otp.decorators import otp_required

def otp_optional(view_func):
    """
    Enforce OTP only for users who have a device registered.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if user_has_device(request.user):
            return otp_required(view_func)(request, *args, **kwargs)
        return view_func(request, *args, **kwargs)
    return _wrapped_view
