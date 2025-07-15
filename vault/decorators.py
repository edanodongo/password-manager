from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps

# Two-Factor Authentication (2FA) decorator
# This decorator checks if the user has 2FA enabled before allowing access to the view.
def two_factor_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        if not getattr(request.user, 'is_2fa_enabled', False):
            messages.warning(request, "You must enable 2FA to access this page.")
            return redirect('setup_2fa')
        return view_func(request, *args, **kwargs)
    return _wrapped_view
